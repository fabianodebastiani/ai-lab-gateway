#!/usr/bin/env python3
"""Operator-executed Oracle-to-WSL V2 public management key install.

Run ONLY from the independent Oracle ubuntu root recovery session.
Transfers the NEW PUBLIC management key through the existing SSH v1 tunnel
as the existing restricted ai-lab-gateway service identity. It does NOT
expose/copy any private key. Does not change registry or tunnel services.

The target atomically appends the new public key to its authorized_keys,
backing up the prior file. No user escalation is attempted on WSL.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import shlex
import stat
import subprocess
import sys

SOURCE = Path("/var/lib/ai-lab-gateway/keys/windows-wsl-v2-candidate.pub")
AUTH_KEY = Path("/var/lib/ai-lab-gateway/keys/windows-wsl_ed25519")
PORT = 10002
USERNAME = "ai-lab-gateway"
TARGET_USER = "ai-gateway"
SERVER = "127.0.0.1"

REMOTE_SCRIPT = r"""
import base64, os, pathlib, stat, sys, tempfile
base=pathlib.Path.home()/'.ssh'
destination=base/'authorized_keys'
backup=base/'ai-lab-v2'/'authorized_keys.pre-v2'
key=sys.stdin.buffer.readline(2048).strip()
if not key.startswith(b'ssh-ed25519 ') or len(key)>1024:
    raise SystemExit('REFUSED: non-ED25519 public key')
words=key.split()
if len(words)<2:
    raise SystemExit('REFUSED: incomplete key')
try:
    body=base64.b64decode(words[1], validate=True)
except ValueError:
    raise SystemExit('REFUSED: malformed key')
if len(body)!=51 or body[4:15]!=b'ssh-ed25519':
    raise SystemExit('REFUSED: malformed ED25519 blob')
if (not base.is_dir() or base.is_symlink() or
        base.stat().st_uid!=os.getuid() or
        (base.stat().st_mode & 0o077)):
    raise SystemExit('REFUSED: unexpected SSH home')
if (not destination.is_file() or destination.is_symlink()
        or destination.stat().st_uid!=os.getuid()):
    raise SystemExit('REFUSED: unexpected authorized_keys')
if (not backup.parent.is_dir() or backup.parent.is_symlink()
        or backup.parent.stat().st_uid!=os.getuid()
        or (backup.parent.stat().st_mode & 0o077)):
    raise SystemExit('REFUSED: unexpected candidate directory')
original=destination.read_bytes()
canonical=b' '.join(words[:2])
old_keys={b' '.join(item.split()[:2]) for item in original.splitlines()
          if item.strip() and not item.lstrip().startswith(b'#')}
if canonical in old_keys:
    print('ALREADY_PRESENT: no changes')
    raise SystemExit(0)
if backup.exists() or backup.is_symlink():
    if not backup.is_file() or backup.read_bytes()!=original:
        raise SystemExit('REFUSED: previous backup differs from active file')
else:
    fd,path=tempfile.mkstemp(prefix='.v2-backup-',dir=backup.parent)
    with os.fdopen(fd,'wb') as stream:stream.write(original);stream.flush();os.fsync(stream.fileno())
    os.chmod(path,0o600)
    os.replace(path,backup)
fd,path=tempfile.mkstemp(prefix='.v2-authorized-',dir=base)
try:
    with os.fdopen(fd,'wb') as stream:
        stream.write(original.rstrip(b'\n')+b'\n'+canonical+b' ai-lab-wsl-v2-management\n')
        stream.flush();os.fsync(stream.fileno())
    os.chmod(path,0o600)
    os.replace(path,destination)
finally:
    if os.path.exists(path):os.unlink(path)
print('NEW_PUBLIC_KEY_INSTALLED; legacy key retained; target user non-root')
"""


def main():
    if os.geteuid()!=0:
        raise SystemExit("REFUSED: use sudo from separate ubuntu administrator session")
    user=pwd.getpwnam(USERNAME)
    for path in (SOURCE, AUTH_KEY):
        if not path.is_file() or path.is_symlink() or path.stat().st_uid!=user.pw_uid:
            raise SystemExit("REFUSED: unexpected gateway key owner or file")
    if stat.S_IMODE(AUTH_KEY.stat().st_mode)!=0o600:
        raise SystemExit("REFUSED: management private key permissions")
    pub=SOURCE.read_bytes().strip()
    if not pub.startswith(b"ssh-ed25519 ") or len(pub)>1024:
        raise SystemExit("REFUSED: unexpected public key format")
    words=pub.split()
    digest=hashlib.sha256(base64.b64decode(words[1],validate=True)).digest()
    fingerprint="SHA256:"+base64.b64encode(digest).decode().rstrip("=")
    print("CANDIDATE_PUBLIC_FINGERPRINT="+fingerprint,flush=True)

    def drop():
        os.initgroups(USERNAME,user.pw_gid)
        os.setgid(user.pw_gid)
        os.setuid(user.pw_uid)

    command=[
        "/usr/bin/ssh","-T",
        "-o","BatchMode=yes",
        "-o","IdentitiesOnly=yes",
        "-o","StrictHostKeyChecking=yes",
        "-o","ConnectTimeout=8",
        "-i",str(AUTH_KEY),
        "-p",str(PORT),
        f"{TARGET_USER}@{SERVER}",
        "--",
        "python3 -c "+shlex.quote(REMOTE_SCRIPT),
    ]
    result=subprocess.run(command,input=pub+b"\n",capture_output=True,
                          timeout=18,check=False,preexec_fn=drop)
    if result.returncode:
        print("TARGET_INSTALL_FAILED: SSH exit "+str(result.returncode),flush=True)
        if result.stderr:
            print(result.stderr.decode(errors="replace")[:800],file=sys.stderr)
        raise SystemExit(1)
    print(result.stdout.decode(errors="replace").strip(),flush=True)


if __name__=="__main__":
    main()
