#!/usr/bin/env python3
"""Stage and publish a hash-pinned, Restricted-only Linux bootstrap in Caddy.

Run --check as an ordinary user for read-only preflight. Only the original
human administrator may run --apply under local sudo; no MCP root action.
Fail closed on changed routes, unexpected files or failed Caddy validation.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import urllib.request
from urllib.parse import urlparse

VERSION = '2026-10-17-stage6-restricted-v1'
INSTALL_COMMIT = '13a06d291b3e9c2b17025c1c54cd657fc68e39f2'
INSTALL_SHA256 = '367fb8d46b0efcac3c319c92174af29e96e943ae18cdbeb7a8e62576c0857127'
INSTALL_URL = (f'https://raw.githubusercontent.com/fabianodebastiani/ai-lab-gateway/'
               f'{INSTALL_COMMIT}/scripts/install_ai_lab_device.sh')
PUBLIC_URL = 'https://gateway.debasti.com/install.sh'
CADDY_CONFIG = Path('/etc/caddy/Caddyfile')
PUBLIC_DIR = Path('/usr/local/share/ai-lab-gateway-public')
PUBLIC_FILE = PUBLIC_DIR / 'install.sh'
BACKUP_DIR = Path('/var/backups/ai-lab-bootstrap-publish-v1')
BACKUP_CONFIG = BACKUP_DIR / 'Caddyfile.before-install-sh'
CADDY = '/usr/bin/caddy'
SYSTEMCTL = '/usr/bin/systemctl'

BLOCK = '''    # BEGIN AI LAB RESTRICTED BOOTSTRAP V1
    handle /install.sh {
        root * /usr/local/share/ai-lab-gateway-public
        header Content-Type "text/plain; charset=utf-8"
        header X-Content-Type-Options nosniff
        header Cache-Control no-store
        file_server
    }
    # END AI LAB RESTRICTED BOOTSTRAP V1

'''


class PublicationError(Exception):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def download_pinned_installer() -> bytes:
    request = urllib.request.Request(INSTALL_URL, headers={'User-Agent': 'ai-lab-verified-bootstrap-publisher'})
    with urllib.request.urlopen(request, timeout=15) as response:
        effective = urlparse(response.geturl())
        if effective.scheme != 'https' or effective.netloc != 'raw.githubusercontent.com':
            raise PublicationError('unexpected GitHub bootstrap redirect or downgrade')
        if int(response.headers.get('Content-Length', '0') or 0) > 150_000:
            raise PublicationError('unexpected bootstrap content length')
        source = response.read(150_001)
    if not (0 < len(source) <= 150_000) or sha(source) != INSTALL_SHA256:
        raise PublicationError('pinned bootstrap checksum mismatch; NOTHING installed')
    if not source.startswith(b'#!/bin/sh\n'):
        raise PublicationError('bootstrap file is not POSIX sh')
    return source


def candidate_caddy_config(original: str) -> str:
    prefix = 'gateway.debasti.com {\n'
    if original.count(prefix) != 1:
        raise PublicationError('unexpected gateway Caddy host block')
    if 'handle /install.sh' in original or 'AI LAB RESTRICTED BOOTSTRAP' in original:
        if original.count(BLOCK) == 1:
            return original
        raise PublicationError('installer route already exists with unrecognized content')
    if '    handle {' not in original or '    handle /pairing/device/* {' not in original:
        raise PublicationError('unexpected original gateway routes; manual review required')
    return original.replace(prefix, prefix + BLOCK, 1)


def trusted_regular_file(path: Path, *, must_root: bool = True) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise PublicationError(f'not a trustworthy regular file: {path}')
    if must_root and (info.st_uid != 0 or info.st_gid != 0 or (info.st_mode & 0o022)):
        raise PublicationError(f'file is not root-controlled: {path}')


def trusted_dir(path: Path, *, mode: int) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != mode):
        raise PublicationError(f'directory mode/owner mismatch: {path}')


def fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_file(path: Path, content: bytes, mode: int) -> None:
    fd, temp = tempfile.mkstemp(prefix='.ai-lab-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            os.fchmod(out.fileno(), mode)
            os.fchown(out.fileno(), 0, 0)
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
        fsync_dir(path.parent)
    finally:
        if os.path.lexists(temp):
            os.unlink(temp)


def command(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=30, check=check)


def validate_candidate(content: str) -> None:
    with tempfile.TemporaryDirectory(prefix='ai-lab-validate-', dir='/tmp') as directory:
        path = Path(directory) / 'Caddyfile'
        path.write_text(content, encoding='utf-8')
        result = command([CADDY, 'validate', '--adapter', 'caddyfile', '--config', str(path)], check=False)
        if result.returncode != 0:
            raise PublicationError('Caddy syntax validation failed: ' + result.stderr[-700:])


def preflight() -> tuple[bytes, str, str]:
    source = download_pinned_installer()
    trusted_regular_file(CADDY_CONFIG)
    original = CADDY_CONFIG.read_text(encoding='utf-8')
    intended = candidate_caddy_config(original)
    if PUBLIC_DIR.exists() or PUBLIC_DIR.is_symlink():
        trusted_dir(PUBLIC_DIR, mode=0o755)
    if PUBLIC_FILE.exists() or PUBLIC_FILE.is_symlink():
        trusted_regular_file(PUBLIC_FILE)
        if sha(PUBLIC_FILE.read_bytes()) != INSTALL_SHA256:
            raise PublicationError('public install.sh already exists with different bytes')
        if intended != original:
            raise PublicationError('public install.sh exists without matching Caddy route')
    if BACKUP_DIR.exists() or BACKUP_DIR.is_symlink():
        trusted_dir(BACKUP_DIR, mode=0o700)
    if BACKUP_CONFIG.exists() or BACKUP_CONFIG.is_symlink():
        trusted_regular_file(BACKUP_CONFIG)
    validate_candidate(intended)
    return source, original, intended


def verify_public_endpoint() -> None:
    req = urllib.request.Request(PUBLIC_URL, headers={'User-Agent': 'ai-lab-publish-verify'})
    with urllib.request.urlopen(req, timeout=10) as response:
        content = response.read(150_001)
        if response.geturl() != PUBLIC_URL or response.status != 200:
            raise PublicationError('unexpected public installer URL / status')
    if sha(content) != INSTALL_SHA256:
        raise PublicationError('public installer checksum mismatch after Caddy reload')


def apply() -> None:
    if os.geteuid() != 0:
        raise PublicationError('--apply requires original local Ubuntu administrator sudo')
    source, original, intended = preflight()
    if original == intended:
        if PUBLIC_FILE.exists() and sha(PUBLIC_FILE.read_bytes()) == INSTALL_SHA256:
            verify_public_endpoint()
            print('AI_LAB_BOOTSTRAP_ALREADY_PUBLISHED: SHA-256 verified')
            return
        raise PublicationError('route exists but matching public file missing')
    if PUBLIC_FILE.exists() or PUBLIC_FILE.is_symlink():
        raise PublicationError('unexpected existing public file')
    PUBLIC_DIR.mkdir(parents=False, exist_ok=True, mode=0o755)
    trusted_dir(PUBLIC_DIR, mode=0o755)
    BACKUP_DIR.mkdir(parents=False, exist_ok=True, mode=0o700)
    trusted_dir(BACKUP_DIR, mode=0o700)
    if BACKUP_CONFIG.exists() or BACKUP_CONFIG.is_symlink():
        raise PublicationError('backup already exists; refuse overwrite')
    atomic_file(BACKUP_CONFIG, original.encode('utf-8'), 0o600)

    file_published = False
    config_changed = False
    try:
        atomic_file(PUBLIC_FILE, source, 0o644)
        file_published = True
        atomic_file(CADDY_CONFIG, intended.encode('utf-8'), 0o644)
        config_changed = True
        command([SYSTEMCTL, 'reload', 'caddy'])
        verify_public_endpoint()
    except BaseException:
        # Restore the original configuration without requiring private tokens.
        if config_changed:
            atomic_file(CADDY_CONFIG, original.encode('utf-8'), 0o644)
            try:
                command([SYSTEMCTL, 'reload', 'caddy'])
            except Exception as error:
                print(f'CRITICAL: original Caddy config restored, reload failed: {error}', file=sys.stderr)
        if file_published:
            PUBLIC_FILE.unlink(missing_ok=True)
            fsync_dir(PUBLIC_DIR)
        raise
    print(f'AI_LAB_BOOTSTRAP_PUBLISHED: {PUBLIC_URL}')
    print(f'AI_LAB_BOOTSTRAP_SHA256: {INSTALL_SHA256}')
    print(f'AI_LAB_BOOTSTRAP_BACKUP: {BACKUP_CONFIG}')


def main() -> int:
    parser = argparse.ArgumentParser(description='Independently approved, hash-pinned AI Lab installer publisher')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--check', action='store_true', help='read-only checks; never changes proxy or services')
    group.add_argument('--apply', action='store_true', help='requires original local sudo')
    args = parser.parse_args()
    try:
        if args.check:
            _, original, intended = preflight()
            print('AI_LAB_BOOTSTRAP_PUBLISH_CHECK_OK')
            print('route_state:', 'already_configured' if original == intended else 'ready_to_add')
            print('sha256:', INSTALL_SHA256)
            print('apply_requires: original local administrator sudo')
        else:
            apply()
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, PublicationError) as error:
        print('AI_LAB_BOOTSTRAP_PUBLISH_FAILED: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
