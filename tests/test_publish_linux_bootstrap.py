"""Nonprivileged tests for publishing the verified public bootstrap."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase, mock

SOURCE = Path(__file__).resolve().parents[1] / 'scripts/publish_linux_bootstrap.py'
spec = importlib.util.spec_from_file_location('ai_lab_bootstrap_publish_test', SOURCE)
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
BASE = '''gateway.debasti.com {
    handle /pairing/device/* {
        reverse_proxy 127.0.0.1:8003
    }

    handle /pairing/* {
        reverse_proxy 127.0.0.1:8002
    }

    handle /approvals* {
        reverse_proxy 127.0.0.1:8001
    }

    handle {
        reverse_proxy 127.0.0.1:8000
    }
}
'''


class PublicationTests(TestCase):
    def test_exact_commit_and_sha_pin(self):
        self.assertEqual(len(p.INSTALL_COMMIT), 40)
        self.assertEqual(len(p.INSTALL_SHA256), 64)
        self.assertIn(p.INSTALL_COMMIT, p.INSTALL_URL)
        self.assertIn('https://raw.githubusercontent.com/', p.INSTALL_URL)

    def test_new_route_precedes_pairing_and_fallback(self):
        proposed = p.candidate_caddy_config(BASE)
        self.assertEqual(proposed.count('handle /install.sh'), 1)
        self.assertLess(proposed.index('handle /install.sh'), proposed.index('handle /pairing/device/*'))
        self.assertLess(proposed.index('handle /install.sh'), proposed.index('handle {'))
        self.assertIn('reverse_proxy 127.0.0.1:8000', proposed)
        self.assertIn('reverse_proxy 127.0.0.1:8003', proposed)
        self.assertIn('X-Content-Type-Options nosniff', proposed)
        self.assertIn('Cache-Control no-store', proposed)

    def test_route_is_idempotent_when_exact_same_block(self):
        once = p.candidate_caddy_config(BASE)
        self.assertEqual(p.candidate_caddy_config(once), once)

    def test_rejects_wrong_domain_and_unrecognized_layout(self):
        for raw in ('other.example {\n    handle {}\n}\n',
                    'gateway.debasti.com {\n    handle {}\n}\n',
                    'gateway.debasti.com {\n    handle /pairing/device/* {}\n}\n'):
            with self.subTest(raw=raw):
                with self.assertRaises(p.PublicationError):
                    p.candidate_caddy_config(raw)

    def test_rejects_existing_different_install_route(self):
        raw = BASE.replace('gateway.debasti.com {\n',
                           'gateway.debasti.com {\n    handle /install.sh { respond PWNED }\n')
        with self.assertRaises(p.PublicationError):
            p.candidate_caddy_config(raw)

    def test_rejects_altered_marker(self):
        raw = p.candidate_caddy_config(BASE).replace('no-store', 'public, max-age=3600')
        with self.assertRaises(p.PublicationError):
            p.candidate_caddy_config(raw)

    def test_rejects_bad_download_hash_even_on_https(self):
        stream = mock.MagicMock()
        stream.geturl.return_value = p.INSTALL_URL
        stream.read.return_value = b'#!/bin/sh\necho unsafe\n'
        stream.headers = {'Content-Length':'22'}
        with mock.patch.object(p.urllib.request, 'urlopen') as openurl:
            openurl.return_value.__enter__.return_value = stream
            with self.assertRaisesRegex(p.PublicationError, 'checksum'):
                p.download_pinned_installer()

    def test_rejects_https_to_http_redirect(self):
        stream = mock.MagicMock()
        stream.geturl.return_value = 'http://raw.githubusercontent.com/hijacked'
        with mock.patch.object(p.urllib.request, 'urlopen') as openurl:
            openurl.return_value.__enter__.return_value = stream
            with self.assertRaisesRegex(p.PublicationError, 'downgrade'):
                p.download_pinned_installer()

    def test_rejects_large_download(self):
        stream = mock.MagicMock()
        stream.geturl.return_value = p.INSTALL_URL
        stream.headers = {'Content-Length':'150001'}
        with mock.patch.object(p.urllib.request, 'urlopen') as openurl:
            openurl.return_value.__enter__.return_value = stream
            with self.assertRaisesRegex(p.PublicationError, 'length'):
                p.download_pinned_installer()

    def test_pinned_script_checks_hash_and_shebang(self):
        sample = b'#!/bin/sh\necho reviewed\n'
        stream = mock.MagicMock()
        stream.geturl.return_value = p.INSTALL_URL
        stream.headers = {'Content-Length':str(len(sample))}
        stream.read.return_value = sample
        with mock.patch.object(p, 'INSTALL_SHA256', hashlib.sha256(sample).hexdigest()), \
             mock.patch.object(p.urllib.request, 'urlopen') as openurl:
            openurl.return_value.__enter__.return_value = stream
            self.assertEqual(p.download_pinned_installer(), sample)

    def test_rejects_missing_immutable_source_shebang(self):
        sample = b'rm -rf unsafe\n'
        stream = mock.MagicMock()
        stream.geturl.return_value = p.INSTALL_URL
        stream.headers = {'Content-Length':str(len(sample))}
        stream.read.return_value = sample
        with mock.patch.object(p, 'INSTALL_SHA256', hashlib.sha256(sample).hexdigest()), \
             mock.patch.object(p.urllib.request, 'urlopen') as openurl:
            openurl.return_value.__enter__.return_value = stream
            with self.assertRaisesRegex(p.PublicationError, 'POSIX'):
                p.download_pinned_installer()

    def test_root_not_required_to_check_but_required_to_apply(self):
        with mock.patch.object(p.os, 'geteuid', return_value=1003), \
             mock.patch.object(p, 'preflight') as preflight:
            with self.assertRaisesRegex(p.PublicationError, 'original local'):
                p.apply()
            preflight.assert_not_called()

    def test_check_never_updates_caddy_or_runs_systemctl(self):
        with mock.patch.object(p, 'preflight', return_value=(b'content', BASE, p.candidate_caddy_config(BASE))), \
             mock.patch.object(p, 'command') as command, \
             mock.patch.object(p, 'atomic_file') as write, \
             mock.patch('sys.argv', ['publisher.py', '--check']):
            self.assertEqual(p.main(), 0)
            command.assert_not_called()
            write.assert_not_called()

    def test_validate_caddy_fail_closed(self):
        with mock.patch.object(p, 'command', return_value=SimpleNamespace(returncode=1,stderr='invalid route')):
            with self.assertRaisesRegex(p.PublicationError,'Caddy syntax'):
                p.validate_candidate(p.candidate_caddy_config(BASE))

    def test_requires_root_controlled_caddyfile(self):
        with TemporaryDirectory() as directory:
            target = Path(directory) / 'Caddyfile'
            target.write_text(BASE)
            target.chmod(0o666)
            with self.assertRaises(p.PublicationError):
                p.trusted_regular_file(target)

    def test_rejects_symlink_route_file(self):
        with TemporaryDirectory() as directory:
            target = Path(directory) / 'real'
            target.write_text(BASE)
            link = Path(directory) / 'Caddyfile'
            link.symlink_to(target)
            with self.assertRaises(p.PublicationError):
                p.trusted_regular_file(link)


if __name__ == '__main__':
    import unittest
    unittest.main()
