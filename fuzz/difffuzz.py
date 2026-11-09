# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""Continuous differential fuzzing, end to end: Alcyon vs HAProxy through real binaries (T293).

usage: difffuzz.py gate|soak|record [options]       (fuzz/README.md has the long form)

Every case goes over a raw socket to a real HAProxy and a real Alcyon (same config, each in
front of its own recording backend). The outcome of a case is its *shape*: the status lines
each proxy answered and a hash of the bytes each backend received. A case is SAME when the two
shapes are equal, DIFF otherwise. fuzz/known_diffs.json lists the DIFFs we know about, keyed by
sha256 of the input bytes, each with the shape it shows and the T-number that tracks it.

  gate    short, time-boxed (--budget, default 30 s): the baseline's inputs, fuzz/corpus, and
          fresh cases from the generator (fixed seed). FAILS on a DIFF not in the baseline, on a
          known input whose DIFF shape changed, and on a known input that became SAME (the
          hash to remove is printed).
  soak    generator rounds (seed, seed+1, ...) for --minutes; new DIFFs go to --out (markdown).
  record  run the inputs of --dir (or the baseline's) and print baseline entries to merge
          (--write merges them into the baseline file with --task).

A case that would change the verdict is run a second time first (a 408 racing a timeout must
not fail the gate). Processes are killed by PID on every exit path. Ports: --base-port
(default 18400) .. +4*workers (4 workers: 18400-18423 with --workers 6), nothing else in the repo uses that range.
"""
import argparse, atexit, base64, concurrent.futures as cf, glob, hashlib, json, os, re
import signal, socket, subprocess, sys, tempfile, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'harness'))
import reference  # noqa: E402  -- $ALCYON_REFERENCE (T630)
PIDS = set()


def killall(*_):
    for p in list(PIDS):
        try:
            os.kill(p, signal.SIGKILL)
        except OSError:
            pass
        PIDS.discard(p)


atexit.register(killall)
for _s in (signal.SIGTERM, signal.SIGINT):
    signal.signal(_s, lambda *a: (killall(), os._exit(130)))


def norm(data):
    """The bytes a backend got, with chunked framing decoded: HAProxy and Alcyon re-emit chunk
    sizes differently (`A` vs `a`, merged chunks), which is not a difference that matters."""
    i = data.find(b'\r\n\r\n')
    if i < 0 or b'transfer-encoding: chunked' not in data[:i].lower():
        return data
    head, rest, body = data[:i + 4], data[i + 4:], b''
    while True:
        j = rest.find(b'\r\n')
        if j < 0:
            return data
        try:
            n = int(rest[:j].split(b';')[0].strip(), 16)
        except ValueError:
            return data
        if n == 0:
            return head + b'[chunked body] ' + body + b' [end]' + rest[j:]
        if len(rest) < j + 2 + n + 2:
            return data
        body += rest[j + 2:j + 2 + n]
        rest = rest[j + 2 + n + 2:]


class Backend:
    """Records the bytes of each connection; answers 200 once a head has arrived."""

    def __init__(s, port):
        s.port = port
        s.log = []
        s.lock = threading.Lock()
        s.l = socket.socket()
        s.l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.l.bind(('127.0.0.1', port))
        s.l.listen(50)
        threading.Thread(target=s.run, daemon=True).start()

    def run(s):
        while True:
            c, _ = s.l.accept()
            threading.Thread(target=s.h, args=(c,), daemon=True).start()

    def h(s, c):
        data = b''
        sent = False
        c.settimeout(0.3)
        try:
            while True:
                d = c.recv(65536)
                if not d:
                    break
                data += d
                if not sent and (b'\r\n\r\n' in data or b'\n\n' in data):
                    c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok')
                    sent = True
                    c.settimeout(0.1)
        except Exception:
            pass
        with s.lock:
            s.log.append(data)
        c.close()

    def take(s):
        with s.lock:
            r = s.log
            s.log = []
        return r


CFG = """global
  tune.bufsize 32768
defaults
  mode http
  timeout connect 500ms
  timeout client 1000ms
  timeout server 1000ms
  timeout http-request 1000ms
frontend fe
  bind 127.0.0.1:{fe}
  default_backend be
backend be
  server s1 127.0.0.1:{be}
"""


def wait_port(port, tries=100):
    for _ in range(tries):
        try:
            socket.create_connection(('127.0.0.1', port), 0.2).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


class Pair:
    """One worker: a haproxy and an alcyon, each with its own backend, on 4 consecutive ports."""

    def __init__(s, ha, ib, base, tmp):
        s.px = {}
        for i, (name, binp) in enumerate((('haproxy', ha), ('alcyon', ib))):
            fe, be = base + 2 * i, base + 2 * i + 1
            f = f'{tmp}/{name}-{base}.cfg'
            cfg = CFG.format(fe=fe, be=be)
            if name == 'alcyon':
                # Header names as HAProxy writes them (X5, D-E: Alcyon's default keeps their case).
                cfg = cfg.replace('global\n', 'global\n  tune.alcyon.h1-lowercase-headers on\n', 1)
            open(f, 'w').write(cfg)
            bk = Backend(be)
            p = subprocess.Popen([binp, '-f', f], stdout=open(f'{tmp}/{name}-{base}.log', 'w'),
                                 stderr=subprocess.STDOUT, start_new_session=True)
            PIDS.add(p.pid)
            s.px[name] = (p, fe, bk)
        for name, (p, fe, bk) in s.px.items():
            if not wait_port(fe):
                raise SystemExit(f'difffuzz: {name} did not listen on {fe}')

    def one(s, name, raw):
        p, fe, bk = s.px[name]
        bk.take()
        c = socket.create_connection(('127.0.0.1', fe))
        c.settimeout(1.3)
        try:
            c.sendall(raw)
        except OSError:
            pass
        resp = b''
        try:
            while True:
                d = c.recv(65536)
                if not d:
                    break
                resp += d
        except Exception:
            pass
        c.close()
        time.sleep(0.25)
        fwd = b'|'.join(norm(x) for x in bk.take())
        st = [x.decode() for x in re.findall(rb'HTTP/1\.[01] (\d+)', resp)]
        return st, fwd

    def shape(s, raw):
        out = {}
        ths = []
        for name in s.px:
            t = threading.Thread(target=lambda n=name: out.__setitem__(n, s.one(n, raw)))
            t.start()
            ths.append(t)
        for t in ths:
            t.join()
        return {n: {'status': out[n][0], 'fwd': hashlib.sha256(out[n][1]).hexdigest()[:12],
                    'fwd_len': len(out[n][1])} for n in out}, out

    def alive(s):
        return all(p.poll() is None for p, _, _ in s.px.values())


def key(raw):
    return hashlib.sha256(raw).hexdigest()[:16]


def same(sh):
    return sh['haproxy'] == sh['alcyon']


def run_cases(pairs, cases, deadline=None):
    """cases: [(key, raw)]. Returns {key: (shape, raw)} for every case that ran (DIFF or SAME)."""
    res = {}
    q = list(cases)
    qlock = threading.Lock()

    def worker(pair):
        while True:
            with qlock:
                if not q or (deadline and time.time() > deadline):
                    return
                k, raw = q.pop(0)
            sh, _ = pair.shape(raw)
            res[k] = (sh, raw)

    with cf.ThreadPoolExecutor(len(pairs)) as ex:
        list(ex.map(worker, pairs))
    return res


def confirm(pair, k, raw, first):
    """Run again; a flaky first result must not decide. Returns the second shape."""
    sh, _ = pair.shape(raw)
    return sh


# Baseline `task` values that name an accepted class, not a tracked defect: any DIFF with the
# shape of such an entry is known, whatever its input (T315). `note:alcyon-stricter` is
# "HAProxy closes without a status, Alcyon answers 400, nothing reaches the server".
ACCEPTED_CLASSES = ('note:alcyon-stricter',)


def accepted_shapes(base):
    """The shapes of the baseline's accepted classes, as a list of shape dicts."""
    out = []
    for v in base.values():
        if v.get('task') in ACCEPTED_CLASSES and v['shape'] not in out:
            out.append(v['shape'])
    return out


def is_accepted(sh, base):
    """Whether the DIFF shape `sh` is the shape of an accepted class of the baseline."""
    return sh in accepted_shapes(base)


def load_baseline(path):
    try:
        return json.load(open(path))
    except FileNotFoundError:
        return {}


def gen_cases(gen, seed, iters, tmp):
    d = tempfile.mkdtemp(prefix='gen-', dir=tmp)
    r = subprocess.run([gen, '--emit-dir', d, '--seed', str(seed), '--iters', str(iters)],
                       capture_output=True, text=True)
    if r.returncode:
        raise SystemExit('difffuzz: generator failed: ' + r.stderr[-300:])
    return [open(f, 'rb').read() for f in sorted(glob.glob(d + '/*.bin'))]


def setup(a):
    tmp = tempfile.mkdtemp(prefix='alcyon-difffuzz-')
    pairs = [Pair(a.haproxy, a.alcyon, a.base_port + 4 * i, tmp) for i in range(a.workers)]
    return pairs


def self_test(pair):
    sh, _ = pair.shape(b'GET / HTTP/1.1\r\nHost: x\r\n\r\n')
    if not (same(sh) and sh['alcyon']['status'] == ['200']):
        raise SystemExit(f'difffuzz: self-test failed (a plain GET is not 200/200): {sh}')


def cmd_gate(a):
    base = load_baseline(a.baseline)
    t0 = time.time()
    deadline = t0 + a.budget
    pairs = setup(a)
    try:
        self_test(pairs[0])
        cases = {}
        # a rotating slice of the baseline (--replay entries, from an offset that moves with
        # the day), so every entry is replayed within len/replay days; `soak` and `--replay 0`
        # (= all) replay everything
        keys = sorted(base)
        n = len(keys) if a.replay == 0 else min(a.replay, len(keys))
        off = (a.rotate * n) % len(keys) if keys else 0
        for k in (keys[off:] + keys[:off])[:n]:
            cases[k] = base64.b64decode(base[k]['input_b64'])
        for f in sorted(glob.glob(a.corpus + '/*.bin')):
            raw = open(f, 'rb').read()
            cases.setdefault(key(raw), raw)
        # fresh cases; the baseline replays first, so a short budget never skips it
        known = list(cases.items())
        fresh = [(key(r), r) for r in gen_cases(a.gen, a.seed, a.iters, tempfile.gettempdir())]
        seen = set(cases)
        fresh = [(k, r) for k, r in fresh if k not in seen]
        # the baseline replay is exempt from the budget; the fresh cases are cut at it
        res = run_cases(pairs, known)
        res.update(run_cases(pairs, fresh, deadline))
        fails = []
        for k, (sh, raw) in res.items():
            inb = k in base
            if inb:
                want = base[k]['shape']
                if same(sh):
                    sh2 = confirm(pairs[0], k, raw, sh)
                    if same(sh2):
                        fails.append(f'BECAME SAME {k} ({base[k]["task"]}): remove it from fuzz/known_diffs.json')
                elif sh != want:
                    sh2 = confirm(pairs[0], k, raw, sh)
                    if sh2 != want and not same(sh2):
                        fails.append(f'SHAPE CHANGED {k} ({base[k]["task"]}): was {json.dumps(want)} now {json.dumps(sh2)}; '
                                     f'raw={raw[:120]!r}')
            elif not same(sh):
                sh2 = confirm(pairs[0], k, raw, sh)
                if not same(sh2) and not is_accepted(sh2, base):
                    fails.append(f'NEW DIFF {k}: ha={sh2["haproxy"]} alcyon={sh2["alcyon"]} raw={raw[:160]!r}')
        if not all(p.alive() for p in pairs):
            fails.append('a proxy died during the run')
        ran_fresh = sum(1 for k, _ in fresh if k in res)
        print(f'diff-fuzz: {len(known)} known/corpus + {ran_fresh}/{len(fresh)} fresh cases '
              f'(seed {a.seed}), {sum(1 for k in res if k in base)}/{len(base)} baseline entries replayed (slice {off}+{n}), '
              f'{len(fails)} problem(s), {time.time() - t0:.1f}s')
        for f in fails:
            print('  ' + f)
        return 1 if fails else 0
    finally:
        killall()


def cmd_record(a):
    pairs = setup(a)
    try:
        self_test(pairs[0])
        cases = {}
        for d in a.dir:
            for f in sorted(glob.glob(d + '/*.bin')):
                raw = open(f, 'rb').read()
                cases.setdefault(key(raw), raw)
        res = run_cases(pairs, list(cases.items()))
        out = {}
        for k, (sh, raw) in res.items():
            if not same(sh):
                sh2 = pairs[0].shape(raw)[0]
                if not same(sh2) and sh2 == sh:
                    out[k] = {'task': a.task, 'shape': sh, 'input_b64': base64.b64encode(raw).decode(),
                              'note': raw[:80].decode('latin-1')}
        print(f'record: {len(res)} cases, {len(out)} stable DIFFs')
        if a.write:
            b = load_baseline(a.baseline)
            for k, v in out.items():
                b.setdefault(k, v)
            json.dump(b, open(a.baseline, 'w'), indent=1, sort_keys=True)
            open(a.baseline, 'a').write('\n')
            print(f'record: baseline now {len(b)} entries')
        return 0
    finally:
        killall()


def cmd_soak(a):
    base = load_baseline(a.baseline)
    t0 = time.time()
    end = t0 + a.minutes * 60
    pairs = setup(a)
    new = {}
    total = 0
    rnd = 0
    accepted = 0  # DIFFs of an accepted class (ACCEPTED_CLASSES) on inputs not in the baseline
    try:
        self_test(pairs[0])
        while time.time() < end:
            seed = a.seed + rnd
            rnd += 1
            cases = [(key(r), r) for r in gen_cases(a.gen, seed, a.iters, tempfile.gettempdir())]
            cases = [(k, r) for k, r in cases if k not in new]
            res = run_cases(pairs, cases, end)
            total += len(res)
            for k, (sh, raw) in res.items():
                if same(sh):
                    continue
                if k in base and base[k]['shape'] == sh:
                    continue
                if k not in base and is_accepted(sh, base):
                    accepted += 1
                    continue
                sh2 = pairs[0].shape(raw)[0]
                if not same(sh2) and not (k in base and base[k]['shape'] == sh2) and not (k not in base and is_accepted(sh2, base)):
                    new[k] = (sh2, raw, seed, k in base)
            if not all(p.alive() for p in pairs):
                print('difffuzz: a proxy died')
                new['proxy-died'] = ({}, b'', seed, False)
                break
        secs = time.time() - t0
        sha = subprocess.run(['git', 'rev-parse', '--short', 'HEAD'], capture_output=True, text=True, cwd=HERE).stdout.strip()
        if a.out and new:
            os.makedirs(os.path.dirname(a.out), exist_ok=True)
            with open(a.out, 'w') as f:
                f.write(f'# difffuzz soak {time.strftime("%F")} alcyon {sha}\n\n{total} cases, {len(new)} new DIFFs '
                        f'(not in fuzz/known_diffs.json, or shape changed), seeds {a.seed}..{a.seed + rnd - 1}\n\n')
                for k, (sh, raw, seed, changed) in sorted(new.items()):
                    f.write(f'## {k} (seed {seed}{", known input, shape changed" if changed else ""})\n\n'
                            f'- haproxy: {sh.get("haproxy")}\n- alcyon: {sh.get("alcyon")}\n- raw: `{raw[:300]!r}`\n'
                            f'- input_b64: `{base64.b64encode(raw).decode()}`\n\n')
        print(f'difffuzz-soak: {total} cases in {secs:.0f}s, {rnd} rounds (seeds {a.seed}..{a.seed + rnd - 1}), '
              f'{len(new)} new DIFFs, alcyon {sha}' + (f' ({accepted} more of an accepted class)' if accepted else '') + (f', report {a.out}' if a.out and new else ''))
        return 1 if new else 0
    finally:
        killall()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('mode', choices=['gate', 'soak', 'record'])
    tgt = os.environ.get('CARGO_TARGET_DIR', 'target')
    ap.add_argument('--alcyon', default=os.path.join(tgt, 'debug', 'alcyon'))
    ap.add_argument('--gen', default=os.path.join(tgt, 'debug', 'alcyon-fuzz'))
    ap.add_argument('--haproxy', default=None, help='default $ALCYON_REFERENCE/haproxy/haproxy')
    ap.add_argument('--baseline', default=os.path.join(HERE, 'known_diffs.json'))
    ap.add_argument('--corpus', default=os.path.join(HERE, 'corpus'))
    ap.add_argument('--budget', type=float, default=30.0)
    ap.add_argument('--workers', type=int, default=6)
    ap.add_argument('--base-port', type=int, default=18400)
    day = int(time.time() // 86400)
    ap.add_argument('--seed', type=int, default=293)
    ap.add_argument('--rotate', type=int, default=day)
    ap.add_argument('--replay', type=int, default=50, help='baseline entries to replay in the gate (0 = all)')
    ap.add_argument('--iters', type=int, default=150)
    ap.add_argument('--minutes', type=float, default=60.0)
    ap.add_argument('--out', default='')
    ap.add_argument('--dir', action='append', default=[])
    ap.add_argument('--task', default='T291')
    ap.add_argument('--write', action='store_true')
    a = ap.parse_args()
    if a.haproxy is None:
        a.haproxy = reference.require(reference.HAPROXY, who='diff-fuzz')
    return {'gate': cmd_gate, 'soak': cmd_soak, 'record': cmd_record}[a.mode](a)


if __name__ == '__main__':
    sys.exit(main())
