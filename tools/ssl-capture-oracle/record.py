#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""Record HAProxy's answers to the ssl_capture clients and write ssl_capture_table.rs.

The ClientHello each client sends depends on the host's OpenSSL, Python and curl, so the
table is a recording of this host: re-record it when those change (2026-11-09: OpenSSL 4.0
dropped ec_point_formats from TLS 1.3-only hellos and the table went stale).

    tools/ssl-capture-oracle/record.py [--haproxy PATH] [--out FILE] [--ja4]

Runs the oracle with the config of crates/alcyon-rt/tests/it/ssl_capture.rs (`start_cfg`) for
capture sizes 1024, 128, 16, 0 and unset, and clients 1-8 of its `get`. `--ja4` prints the JA4
strings (FoxIO technical_details/JA4.md) of the lists HAProxy answered at 1024, for the `JA4`
table of ssl_capture.rs; `--check-ja4 FILE` recomputes them from an existing table.
"""
import argparse, hashlib, os, re, socket, subprocess, sys, tempfile, time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TEST = os.path.join(REPO, "crates/alcyon-rt/tests/it/ssl_capture.rs")
OUT = os.path.join(REPO, "crates/alcyon-rt/tests/it/ssl_capture_table.rs")
SIZES = ["1024", "128", "16", "0", "unset"]
CLIENTS = range(1, 9)


def rust_consts(src):
    """HEADERS, the ja3 expression and the client option strings, read from the test itself."""
    headers = re.findall(r'\("(x-[a-z0-9]+)", "(%\[[^"]*\])"\)', src.split("const HEADERS")[1].split("];")[0])
    # A Rust `\` at the end of a line drops the newline and the next line's indentation.
    ja3 = re.sub(r"\\\n\s*", "", "".join(re.findall(r'"([^"]*)"', src.split("let ja3 =")[1].split(";")[0])))
    opts = {}
    for name, body in re.findall(r"const (C\d): &str = (\"(?:[^\"\\]|\\.)*\");", src, re.S):
        opts[int(name[1:])] = re.sub(r"\\\n\s*", "", body[1:-1])
    return headers, ja3, opts


PY_CLIENT = (
    "import ssl,socket,sys\nc=ssl.create_default_context();c.check_hostname=False;c.verify_mode=ssl.CERT_NONE\n"
    "h,p=sys.argv[1].rsplit(':',1)\ns=c.wrap_socket(socket.create_connection((h,int(p)),5),server_hostname='localhost')\n"
    "s.sendall(b'GET / HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n')\nd=b''\n"
    "while True:\n b=s.recv(65536)\n if not b: break\n d+=b\nsys.stdout.write(d.decode())\n"
)


def get(addr, client, opts):
    if client == 5:
        out = subprocess.run([sys.executable, "-c", PY_CLIENT, addr], capture_output=True, timeout=20).stdout
    elif client == 6:
        out = subprocess.run(["curl", "-s", "-k", "--tlsv1.3", "-m", "5", "-D", "-", "-o", "/dev/null",
                              f"https://{addr}/"], capture_output=True, timeout=20).stdout
    else:
        o = opts[client] if client in (1, 2, 3, 4, 8, 9) else opts[7]
        out = subprocess.run(["openssl", "s_client", "-connect", addr, *o.split(), "-ign_eof", "-quiet"],
                             input=b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                             capture_output=True, timeout=20).stdout
    return out.decode(errors="replace").replace("\r", "")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def record(haproxy, headers, ja3, opts, tmp):
    crt = os.path.join(tmp, "crt.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                    "-keyout", crt + ".key", "-out", crt, "-days", "2"], check=True, capture_output=True)
    with open(crt, "a") as f, open(crt + ".key") as k:
        f.write(k.read())
    rows = []
    for size in SIZES:
        port = free_port()
        addr = f"127.0.0.1:{port}"
        glob = "global\n" + ("" if size == "unset" else f"  tune.ssl.capture-buffer-size {size}\n")
        hdrs = "".join(f' hdr {n} "{e}"' for n, e in headers)
        cfg = (f"{glob}defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n"
               f"frontend t\n  bind {addr} ssl crt {crt}\n  http-request set-header x-ja3 \"{ja3}\"\n  "
               f"http-request return status 200{hdrs}\n")
        path = os.path.join(tmp, f"h-{size}.cfg")
        with open(path, "w") as f:
            f.write(cfg)
        p = subprocess.Popen([haproxy, "-db", "-f", path], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(200):
                try:
                    socket.create_connection(("127.0.0.1", port), 0.1).close()
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                raise SystemExit(f"haproxy never listened: {p.stderr.read1().decode()}")
            for client in CLIENTS:
                r = get(addr, client, opts)
                if not re.match(r"HTTP/(1\.1|2) 200", r):
                    raise SystemExit(f"N {size} client {client}: no 200: {r[:200]!r}")
                got = []
                for name, _ in headers:
                    m = re.search(rf"^{name}: (.*)$", r, re.M)
                    if m:
                        got.append((name, m.group(1).strip()))
                rows.append((size, client, got))
        finally:
            p.terminate()
            p.wait()
    return rows


def write_table(rows, out, version):
    lines = [
        "// SPDX-License-Identifier: GPL-2.0-or-later",
        "// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.",
        "",
        f"//! Generated from the raw output of `HAProxy` {version} for the T344 C2",
        "//! capture fetches: (N, client, headers it answered). A header not listed was not answered (no sample).",
        "//! The clients are in `ssl_capture.rs`. Not edited by hand: `tools/ssl-capture-oracle/record.py`",
        f"//! wrote it, with this host's clients ({client_versions()}).",
        "",
        "pub type Row = (&'static str, u8, &'static [(&'static str, &'static str)]);",
        "",
        "pub const HAPROXY: &[Row] = &[",
    ]
    for size, client, got in rows:
        lines.append(f'    ("{size}", {client}, &[')
        lines += [f'        ("{n}", "{v}"),' for n, v in got]
        lines.append("    ]),")
    lines.append("];")
    with open(out, "w") as f:
        f.write("\n".join(lines) + "\n")


def client_versions():
    ossl = subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout.split()[:2]
    curl = subprocess.run(["curl", "--version"], capture_output=True, text=True).stdout.split()[:2]
    return f"{' '.join(ossl)}, Python {sys.version.split()[0]}, {' '.join(curl)}"


def ja4(hdr, alpn="h1"):
    """FoxIO JA4 (technical_details/JA4.md) of one client's answered lists and its ALPN part."""
    split = lambda h: [h[i:i + 4].lower() for i in range(0, len(h), 4)]
    ciphers, exts, sigalgs = split(hdr["x-cl1"]), split(hdr["x-ext1"]), split(hdr.get("x-sa1", ""))
    sni = "d" if "0000" in exts else "i"
    versions = split(hdr.get("x-sv1", "")) or [f"{int(hdr['x-hid']):04x}"]
    ver = {"0304": "13", "0303": "12", "0302": "11", "0301": "10"}[max(versions)]
    a = f"t{ver}{sni}{len(ciphers):02d}{len(exts):02d}{alpn}"
    b = hashlib.sha256(",".join(sorted(ciphers)).encode()).hexdigest()[:12]
    ext_part = ",".join(sorted(e for e in exts if e not in ("0000", "0010")))
    if sigalgs:
        ext_part += "_" + ",".join(sigalgs)
    c = hashlib.sha256(ext_part.encode()).hexdigest()[:12]
    return f"{a}_{b}_{c}"


def parse_table(path):
    rows = {}
    for size, client, body in re.findall(r'\("(\w+)", (\d+), &\[(.*?)\]\)', open(path).read(), re.S):
        rows[(size, int(client))] = dict(re.findall(r'\("(x-[a-z0-9]+)", "([^"]*)"\)', body))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--haproxy", default=os.path.expanduser("~/reference/haproxy/haproxy"))
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--ja4", action="store_true")
    ap.add_argument("--check-ja4", metavar="TABLE")
    a = ap.parse_args()
    if a.check_ja4:
        for (size, client), h in sorted(parse_table(a.check_ja4).items()):
            if size == "1024":
                alpn = {1: "h1", 2: "h1", 4: "h1", 6: "h2"}.get(client, "00")
                print(client, ja4(h, alpn))
        return
    headers, ja3, opts = rust_consts(open(TEST).read())
    version = subprocess.run([a.haproxy, "-v"], capture_output=True, text=True).stdout.split()[2]
    with tempfile.TemporaryDirectory() as tmp:
        rows = record(a.haproxy, headers, ja3, opts, tmp)
    write_table(rows, a.out, version)
    print(f"wrote {a.out}: {len(rows)} rows")
    if a.ja4:
        for size, client, got in rows:
            if size == "1024":
                alpn = {1: "h1", 2: "h1", 4: "h1", 6: "h2"}.get(client, "00")
                print(client, ja4(dict(got), alpn))


if __name__ == "__main__":
    main()
