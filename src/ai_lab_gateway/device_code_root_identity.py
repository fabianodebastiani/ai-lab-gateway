"""Supervised root-owned, one-time Gateway management key preparation.

NOT DEPLOYED. Prepares ONLY the independent WSL 10003 candidate identity.
It does not approve a device, install an authorized_keys entry, enable an
MCP/SSH service, alter the registry or grant privilege. The target Linux
never receives this private key.

Production trust boundary:
  /etc/ai-lab-gateway                         root:ai-lab-gateway 0750
  /etc/ai-lab-gateway/device-code-keys        root:ai-lab-gateway 0750
  /etc/ai-lab-gateway/device-code-keys/wsl-10003 root:ai-lab-gateway 0750
  identity, identity.pub                      root:ai-lab-gateway 0640

The root-owned parent and directory are non-writable by Gateway, while the
Gateway Unix group may read the candidate SSH private key. A protected lock
plus atomic directory rename prevent concurrent partial publication; a
crash before rename leaves an untrusted hidden staging directory, which
requires explicit root reconciliation. A crash after rename leaves a fully
prepared but *unauthorized* standalone identity, not live SSH access.
"""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

from .enrollment import _validate_public_key

BASE = Path("/etc/ai-lab-gateway/device-code-keys")
PILOT = "wsl-10003"
LOCK = ".wsl-10003.lock"
PUBLIC = "identity.pub"
PRIVATE = "identity"


def _require_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError("real root UID required for WSL SSH identity")


def _trusted_root_dir(path: Path, *, group_gid: int, mode: int = 0o750) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or info.st_gid != group_gid or stat.S_IMODE(info.st_mode) != mode):
        raise PermissionError("candidate identity directory is not root controlled")


def _file(path: Path, *, group_gid: int) -> bytes:
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
                or st.st_gid != group_gid or st.st_nlink != 1
                or stat.S_IMODE(st.st_mode) != 0o640):
            raise PermissionError("candidate identity file does not have root:gateway 0640")
        with os.fdopen(fd, "rb", closefd=False) as data:
            raw = data.read(16385)
    finally:
        os.close(fd)
    if len(raw) > 16384:
        raise PermissionError("candidate identity file too large")
    return raw


def _sync_folder(path: Path) -> None:
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _derive_as_gateway(path: Path, *, gateway_uid: int,
                       gateway_gid: int) -> str:
    """Derive with the exact unprivileged SSH-client identity.

    A root-owned 0640 private key is intentionally group-readable.
    OpenSSH refuses it when invoked as its *owner* (root); checking as the
    gateway UID both verifies usable group access and SSH's safe-key policy.
    No private bytes appear in subprocess output.
    """
    if (type(gateway_uid) is not int or gateway_uid <= 0
            or type(gateway_gid) is not int or gateway_gid < 0):
        raise PermissionError("refusing root or untrusted key reader identity")
    result = subprocess.run(
        ["/usr/bin/setpriv", "--reuid", str(gateway_uid),
         "--regid", str(gateway_gid), "--clear-groups",
         "/usr/bin/ssh-keygen", "-y", "-P", "", "-f", str(path)],
        check=True, capture_output=True, text=True, timeout=7)
    return _validate_public_key(result.stdout.strip())


def prepare_wsl_management_identity(*, group_gid: int, gateway_uid: int, base: Path = BASE) -> dict:
    """Explicit root-only operator action; does not enroll anything.

    Production callers use BASE, never a request-supplied directory. Tests
    inject a disposable root-owned folder to exercise ownership as UID 0.
    """
    _require_root()
    if (type(group_gid) is not int or group_gid < 0
            or type(gateway_uid) is not int or gateway_uid <= 0):
        raise PermissionError("invalid protected gateway identity")
    base = Path(base)
    _trusted_root_dir(base, group_gid=group_gid)
    destination = base / PILOT
    lock_path = base / LOCK
    lock = os.open(str(lock_path),
                   os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        st = os.fstat(lock)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
                or st.st_gid != os.getegid()
                or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1):
            raise PermissionError("untrusted root-only identity lock")
        fcntl.flock(lock, fcntl.LOCK_EX)
        if destination.exists() or destination.is_symlink():
            raise FileExistsError("WSL candidate identity already exists; never rotate")
        tmp = Path(tempfile.mkdtemp(prefix=".incomplete-wsl-10003-", dir=base))
        committed = False
        try:
            os.chown(tmp, 0, group_gid)
            os.chmod(tmp, 0o750)
            key = tmp / PRIVATE
            subprocess.run(
                ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519",
                 "-N", "", "-f", str(key), "-C", "ai-lab-wsl-10003"],
                check=True, capture_output=True, timeout=20)
            pub = tmp / PUBLIC
            for candidate in (key, pub):
                os.chown(candidate, 0, group_gid)
                os.chmod(candidate, 0o640)
            actual_pub = _validate_public_key(
                _file(pub, group_gid=group_gid).decode("ascii").strip())
            if _derive_as_gateway(
                    key, gateway_uid=gateway_uid, gateway_gid=group_gid) != actual_pub:
                raise PermissionError("private/public candidate identity mismatch")
            _sync_folder(tmp)
            # root-controlled base is not group-writable. No other UID
            # can race the final name while this exclusive lock is held.
            if destination.exists() or destination.is_symlink():
                raise FileExistsError("candidate identity appeared during preparation")
            os.rename(tmp, destination)
            committed = True
            _sync_folder(base)
            return {
                "status": "root_candidate_identity_prepared",
                "device_id": "windows-wsl",
                "port": 10003,
                "public_key": actual_pub,
                "ssh_activated": False,
                "registry_changed": False,
            }
        finally:
            if not committed and tmp.exists():
                shutil.rmtree(tmp)
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)


def verify_wsl_management_identity(*, group_gid: int, gateway_uid: int,
                                   base: Path = BASE) -> str:
    """Return only the checked public key; never disclose private material."""
    _require_root()
    base = Path(base)
    _trusted_root_dir(base, group_gid=group_gid)
    target = base / PILOT
    _trusted_root_dir(target, group_gid=group_gid)
    pub = _validate_public_key(
        _file(target / PUBLIC, group_gid=group_gid).decode("ascii").strip())
    _file(target / PRIVATE, group_gid=group_gid)
    if _derive_as_gateway(
            target / PRIVATE, gateway_uid=gateway_uid, gateway_gid=group_gid) != pub:
        raise PermissionError("candidate management keypair differs")
    return pub
