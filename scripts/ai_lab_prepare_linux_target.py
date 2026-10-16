#!/usr/bin/env python3
"""One-time *local* Ubuntu/Debian SSH preparation for one-code enrollment.

This privileged helper runs only on the Linux the human is enrolling. It
does not receive a remote command, URL, token, device code or SSH key.
It creates a dedicated no-sudo login and prepares existing OpenSSH.
It MUST NOT run on the Oracle Gateway as a way to change Gateway policy.
"""
from __future__ import annotations

import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys

USER = "ai-gateway"
REQUIRED_HOST = Path("/etc/ssh/ssh_host_ed25519_key.pub")
BANNED_GROUPS = {"sudo", "wheel", "root", "docker", "lxd", "adm"}
USERNAME = re.compile(r"ai-gateway\Z")


def command(argv: list[str], *, timeout: int = 60) -> None:
    subprocess.run(argv, check=True, timeout=timeout,
                   stdin=subprocess.DEVNULL)


def inspect_existing_user() -> pwd.struct_passwd:
    user = pwd.getpwnam(USER)
    if user.pw_uid == 0 or user.pw_gid == 0:
        raise PermissionError("management user must not be root")
    if user.pw_shell not in ("/bin/bash", "/bin/sh"):
        raise PermissionError("management login shell is not allowed")
    home = Path(user.pw_dir)
    if home.is_symlink():
        raise PermissionError("management home directory is symlinked")
    meta = home.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != user.pw_uid:
        raise PermissionError("management home directory owner is invalid")
    result = subprocess.run(
        ["/usr/bin/id", "-nG", USER], check=True, capture_output=True,
        text=True, timeout=5)
    if set(result.stdout.strip().split()) & BANNED_GROUPS:
        raise PermissionError("management user has privileged group membership")
    if Path("/usr/bin/sudo").is_file():
        # Ubuntu sudo -l -U USER can exit with status 0 even when the
        # result is "User ... is not allowed to run sudo on HOST".
        # Fail closed unless the exact canonical denial is confirmed.
        result = subprocess.run(
            ["/usr/bin/sudo", "-n", "-l", "-U", USER],
            capture_output=True, text=True, timeout=5,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"})
        denial = re.fullmatch(
            r"User ai-gateway is not allowed to run sudo on [A-Za-z0-9._-]+\\.",
            result.stdout.strip())
        if result.returncode not in (0, 1) or denial is None or result.stderr.strip():
            raise PermissionError("management user has sudo rules or sudo policy cannot be verified")
    return user


def prepare() -> None:
    if os.geteuid() != 0:
        raise PermissionError("local setup requires explicit sudo from the Linux owner")
    if not Path("/run/systemd/system").is_dir():
        raise RuntimeError("local systemd is required for the first release")
    if not Path("/etc/debian_version").is_file():
        raise RuntimeError("automatic OpenSSH setup currently supports Ubuntu/Debian")
    if not Path("/usr/sbin/sshd").is_file():
        command(["/usr/bin/apt-get", "update"], timeout=180)
        command(["/usr/bin/apt-get", "install", "-y", "--no-install-recommends",
                 "openssh-server"], timeout=180)
    if not REQUIRED_HOST.is_file() or REQUIRED_HOST.is_symlink():
        raise PermissionError("Linux host Ed25519 key unavailable")
    command(["/usr/bin/systemctl", "enable", "--now", "ssh"], timeout=30)
    try:
        user = inspect_existing_user()
    except KeyError:
        command(["/usr/sbin/useradd", "--create-home", "--shell",
                 "/bin/bash", USER], timeout=10)
        user = inspect_existing_user()
    command(["/usr/bin/loginctl", "enable-linger", USER], timeout=12)
    # Linger allows the nonprivileged systemd --user tunnel to stay active
    # without keeping the administrator's login session running.
    command(["/usr/bin/systemctl", "start",
             f"user@{user.pw_uid}.service"], timeout=20)
    print(f"AI_LAB_TARGET_PREPARED user={USER} uid={user.pw_uid} no_sudo=true")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 1:
            raise ValueError("no caller-supplied setup options are supported")
        prepare()
    except (OSError, subprocess.SubprocessError, ValueError, PermissionError,
            RuntimeError) as exc:
        print("AI_LAB_TARGET_NOT_PREPARED: " + type(exc).__name__ +
              ": " + str(exc), file=sys.stderr)
        raise SystemExit(1)
