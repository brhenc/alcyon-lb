#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

import sys
import os
import argparse
import subprocess
import json
import shutil
import tarfile
import tempfile

def main():
    args = sys.argv[1:]
    paths = []
    sections = ""
    if "--" in args:
        idx = args.index("--")
        paths = args[:idx]
        for a in args[idx+1:]:
            if a.startswith("--sections="):
                sections = a
    else:
        paths = args

    if not paths:
        print("Usage: isolate.sh <path>... [-- --sections=...]")
        sys.exit(1)

    repo_root = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True).stdout.strip()
    
    paths_rel = []
    for p in paths:
        abs_p = os.path.abspath(p)
        if abs_p.startswith(repo_root):
            paths_rel.append(os.path.relpath(abs_p, repo_root))
        else:
            paths_rel.append(p)

    # The committed version pointed at /tmp/fingerprint.py, a scratch copy that exists on
    # one machine and is cleared on reboot. The script ships next to this one.
    fingerprint_py = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fingerprint.py")
    fp_cmd = [sys.executable, fingerprint_py]
    if sections:
        fp_cmd.append(sections)

    print("=> Fingerprinting current tree...")
    fp_now_str = subprocess.run(fp_cmd, cwd=repo_root, capture_output=True, text=True, check=True).stdout
    fp_now = json.loads(fp_now_str)

    backup_tar = tempfile.mktemp(prefix="isolate_backup_", suffix=".tar.gz")
    print(f"=> Backing up paths to {backup_tar} ...")
    with tarfile.open(backup_tar, "w:gz") as tar:
        for p in paths_rel:
            full_p = os.path.join(repo_root, p)
            if os.path.exists(full_p):
                tar.add(full_p, arcname=p)

    print("=> Reverting paths...")
    for p in paths_rel:
        res = subprocess.run(["git", "ls-tree", "HEAD", "--", p], cwd=repo_root, capture_output=True, text=True)
        if res.stdout.strip():
            subprocess.run(["git", "checkout", "HEAD", "--", p], cwd=repo_root, check=True)
        else:
            full_p = os.path.join(repo_root, p)
            if os.path.exists(full_p):
                if os.path.isdir(full_p):
                    shutil.rmtree(full_p)
                else:
                    os.remove(full_p)
                
    try:
        env = os.environ.copy()
        env["CARGO_INCREMENTAL"] = "0"
        
        print("=> Rebuilding...")
        subprocess.run(["cargo", "build", "--bin", "alcyon"], cwd=repo_root, env=env, check=True)
        
        print("=> Fingerprinting reverted tree...")
        fp_rev_str = subprocess.run(fp_cmd, cwd=repo_root, capture_output=True, text=True, check=True).stdout
        fp_rev = json.loads(fp_rev_str)
        
        print("=> Restoring paths...")
        for p in paths_rel:
            full_p = os.path.join(repo_root, p)
            if os.path.exists(full_p):
                if os.path.isdir(full_p):
                    shutil.rmtree(full_p)
                else:
                    os.remove(full_p)
        with tarfile.open(backup_tar, "r:gz") as tar:
            tar.extractall(path=repo_root)
            for m in tar.getmembers():
                if m.isfile():
                    os.utime(os.path.join(repo_root, m.name), None)
            
        print("=> Rebuilding restored tree...")
        subprocess.run(["cargo", "build", "--bin", "alcyon"], cwd=repo_root, env=env, check=True)

        print("=> Verifying restore...")
        fp_restored_str = subprocess.run(fp_cmd, cwd=repo_root, capture_output=True, text=True, check=True).stdout
        
        if fp_restored_str != fp_now_str:
            print("ERROR: Restored fingerprint does not match original!")
            fd1, f1_name = tempfile.mkstemp()
            fd2, f2_name = tempfile.mkstemp()
            with os.fdopen(fd1, "w") as f1, os.fdopen(fd2, "w") as f2:
                json.dump(fp_now, f1, sort_keys=True, indent=2)
                f1.write("\n")
                json.dump(json.loads(fp_restored_str), f2, sort_keys=True, indent=2)
                f2.write("\n")
            subprocess.run(["diff", "-u", f1_name, f2_name])
            os.remove(f1_name)
            os.remove(f2_name)
            sys.exit(1)
            
        print("=> Diff (Reverted -> Current):")
        fd1, f1_name = tempfile.mkstemp()
        fd2, f2_name = tempfile.mkstemp()
        with os.fdopen(fd1, "w") as f1, os.fdopen(fd2, "w") as f2:
            json.dump(fp_rev, f1, sort_keys=True, indent=2)
            f1.write("\n")
            json.dump(fp_now, f2, sort_keys=True, indent=2)
            f2.write("\n")
        subprocess.run(["diff", "-u", f1_name, f2_name])
        os.remove(f1_name)
        os.remove(f2_name)
        
    except SystemExit:
        raise
    except BaseException as e:
        # The window between "revert" and "restore" is the whole point of this script and
        # also its only dangerous moment: the paths under test are deleted from the tree,
        # and for untracked files the tar is the only copy. Ctrl-C used to leave them
        # deleted with a hint printed, which is how harness/covercheck.py was lost twice.
        # Put them back before reporting the failure.
        print(f"\nERROR or INTERRUPT: {e}")
        print("=> Restoring from backup...")
        try:
            for p in paths_rel:
                full_p = os.path.join(repo_root, p)
                if os.path.exists(full_p):
                    if os.path.isdir(full_p):
                        shutil.rmtree(full_p)
                    else:
                        os.remove(full_p)
            with tarfile.open(backup_tar, "r:gz") as tar:
                tar.extractall(path=repo_root)
            print(f"=> Restored. Backup kept at {backup_tar}")
        except BaseException as restore_err:
            print(f"RESTORE FAILED: {restore_err}")
            print(f"Restore by hand with: tar -xzf {backup_tar} -C {repo_root}")
        sys.exit(1)
        
    print(f"Cleanly finished. Backup left at {backup_tar} just in case.")

if __name__ == "__main__":
    main()
