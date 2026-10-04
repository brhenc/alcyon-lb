import subprocess
passes = ["", "a", "secret", "pass word", "0123456789abcdef", "0123456789abcdefg", "x" * 31, "y" * 64, "z" * 72, "w" * 73, "é€ü", "pa$$:w\\rd"]
settings = [
    "$1$", "$1$salt", "$1$salt$", "$1$abcdefghijkl$", "$1$s$x",
    "$5$salt", "$5$abcdefghijklmnopqrstu$", "$5$$", "$5$rounds=1000$s", "$5$rounds=5000$saltsalt", "$5$rounds=2345$",
    "$6$salt", "$6$abcdefghijklmnopqrstu$", "$6$$", "$6$rounds=1000$s", "$6$rounds=5000$saltsalt", "$6$rounds=2345$", "$6$round=1000$x",
    "$2a$04$fDT1s53J9hc2GdGrAK.LQO", "$2b$04$fDT1s53J9hc2GdGrAK.LQO", "$2y$05$abcdefghijklmnopqrstuu", "$2b$05$......................",
    "$2a$04$//////////////////////",
]
bad = ["$1$sa:lt$x", "$6$sa lt", "$6$rounds=999$x", "$6$rounds=1000", "$6$rounds=01000$x", "$5$rounds=+1000$x", "$5$rounds=1000000000$x",
       "$2b$03$fDT1s53J9hc2GdGrAK.LQO", "$2b$5$fDT1s53J9hc2GdGrAK.LQO", "$2c$05$fDT1s53J9hc2GdGrAK.LQO", "$2b$05$fDT1s53J9hc2GdGrAK:LQO", "$2b$05$short",
       "$9$x$y", "$", "$$", "$1", "", "*", "!", "x", "ab!", "!!"]
def run(pairs):
    inp = "".join(f"{p}\t{s}\n" for p, s in pairs)
    r = subprocess.run(["/tmp/t155/cb"], input=inp, capture_output=True, text=True)
    return r.stdout.split("\n")[:len(pairs)]
rows = []
good_pairs = [(p, s) for s in settings for p in passes]
outs = run(good_pairs)
for (p, s), o in zip(good_pairs, outs):
    assert o != "NULL", (s, p)
    # the right password, and the hash as glibc writes it
    rows.append((o, p, "ok"))
    # bcrypt reads 72 bytes of the password: nothing after them changes the hash
    if not (o.startswith("$2") and len(p.encode()) >= 72):
        rows.append((o, p + "x", "no"))
    else:
        rows.append((o, p + "x", "ok"))
    if p and not (o.startswith("$2") and len(p.encode()) > 72):
        rows.append((o, p[:-1], "no"))
# settings used directly as stored hashes: glibc's own verdict (crypt(p, s) == s)
direct = [(p, s) for s in settings + bad for p in ["secret", ""]]
for (p, s), o in zip(direct, run(direct)):
    rows.append((s, p, "load:" + ("NULL" if o == "NULL" else "ok") + ",match:" + ("yes" if o == s else "no")))
# other glibc formats
for s in ["ab", "a.", "KX9oOBGuoeCIs", "_J9..salt", "_J9..sal", "$sha1$1$abc", "$md5$abc", "$3$abc", "$y$j9T$1nZAl.AiE9fK3YIKl7dej.$fm26plQOfV3uymBaBxn65uVem0IUdbHYe6PLwrZdu30", "$2x$05$fDT1s53J9hc2GdGrAK.LQOtqRsu5pcbLSuKdbfWmKNcCLmW5Y6rgu"]:
    o = run([("secret", s)])[0]
    rows.append((s, "secret", "load:" + ("NULL" if o == "NULL" else "ok") + ",match:" + ("yes" if o == s else "no")))
with open("/home/bhenc/project-ibex/.claude/worktrees/agent-a19aa4612676c1f17/crates/ibex-crypt/tests/vectors.txt", "w") as f:
    f.write("# stored<TAB>password<TAB>verdict, from glibc crypt() on 2026-10-04 (see tests/vectors.py in the task)\n")
    for r in rows:
        f.write("\t".join(r) + "\n")
print(len(rows))
