"""Offline safety/regression tests. Keys and the test CA live only in tempdirs."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from unittest import mock

MODULE = Path(__file__).resolve().parents[1] / 'scripts' / 'ssl_manage.py'
spec = importlib.util.spec_from_file_location('ssl_manage', str(MODULE))
sm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sm)
DOMAIN = 'example.org'
NAMES = [DOMAIN, 'www.example.org']


def command(argv):
    subprocess.run([str(a) for a in argv], check=True, stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE)


def fake_exchange(left, right):
    """Test double only: production has no three-rename fallback."""
    left, right = Path(left), Path(right)
    temp = left.parent / 'exchange-test-only'
    os.rename(str(left), str(temp))
    os.rename(str(right), str(left))
    os.rename(str(temp), str(right))


class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('openssl'):
            raise unittest.SkipTest('local OpenSSL is required')
        cls.fixtures = tempfile.TemporaryDirectory()
        cls.fixture = Path(cls.fixtures.name).resolve()
        cls.ca = cls.fixture / 'ca.pem'
        cakey = cls.fixture / 'ca.key'
        command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '365',
                 '-subj', '/CN=Offline Test CA', '-keyout', cakey, '-out', cls.ca,
                 '-addext', 'basicConstraints=critical,CA:TRUE'])
        ext = cls.fixture / 'extensions.cnf'
        ext.write_text('subjectAltName=DNS:example.org,DNS:www.example.org\n'
                       'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n'
                       'extendedKeyUsage=serverAuth\n')
        cls.material = {}
        for index, (label, days) in enumerate([('old', 10), ('new', 90), ('older', 5), ('expired', -1)]):
            directory = cls.fixture / label
            directory.mkdir()
            key, leaf, csr = directory / 'privkey.pem', directory / 'leaf.pem', directory / 'request.csr'
            command(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
                     '-subj', '/CN=example.org', '-keyout', key, '-out', csr])
            if days < 0:
                (cls.fixture / 'index.txt').write_text('')
                (cls.fixture / 'serial').write_text('03\n')
                ca_config = cls.fixture / 'ca.cnf'
                ca_config.write_text('[ca]\ndefault_ca=test\n[test]\n'
                                     'database={0}/index.txt\nserial={0}/serial\n'
                                     'new_certs_dir={0}\ncertificate={0}/ca.pem\n'
                                     'private_key={0}/ca.key\ndefault_md=sha256\n'
                                     'policy=policy\n[policy]\ncommonName=supplied\n'.format(cls.fixture))
                command(['openssl', 'ca', '-batch', '-notext', '-config', ca_config,
                         '-startdate', '20200101000000Z', '-enddate', '20210101000000Z',
                         '-in', csr, '-extfile', ext, '-out', leaf])
            else:
                command(['openssl', 'x509', '-req', '-in', csr, '-CA', cls.ca, '-CAkey', cakey,
                         '-set_serial', str(index + 1), '-days', str(days), '-extfile', ext, '-out', leaf])
            (directory / 'fullchain.pem').write_bytes(leaf.read_bytes() + cls.ca.read_bytes())
            cls.material[label] = directory

    @classmethod
    def tearDownClass(cls):
        cls.fixtures.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.config_path = self.base / 'config.json'
        self.config = {
            'nginx_root': str(self.base / 'nginx'), 'acme_home': str(self.base / 'acme'),
            'log_root': str(self.base / 'logs'), 'backup_root': str(self.base / 'backups'),
            'work_root': str(self.base / 'work'), 'lock_file': str(self.base / 'operation.lock'),
            'origin_address': '127.0.0.1', 'dns_provider': 'dns_test',
            'nginx_test_command': ['nginx', '-t'],
            'nginx_reload_command': ['nginx', '-s', 'reload'],
            'timezone_offset': '+08:00', 'timezone_name': 'Asia/Shanghai',
            'certificates': {DOMAIN: self.group_spec()}}
        self.save_config()
        self.environment = mock.patch.dict(os.environ, {'SSL_CERT_FILE': str(self.ca)})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.addCleanup(self.temp.cleanup)
        self.manager = sm.Manager(self.config_path)
        self.copy_material('old', self.manager.group(DOMAIN))
        self.copy_material('new', self.manager.stage(DOMAIN))
        self.write_metadata()
        (self.manager.acme / 'acme.sh').write_text('#!/bin/sh\nexit 0\n')
        self.out = io.StringIO()
        self.redirect = contextlib.redirect_stdout(self.out)
        self.redirect.__enter__()
        self.addCleanup(self.redirect.__exit__, None, None, None)

    def group_spec(self):
        root = self.base / 'nginx' / 'cert' / DOMAIN
        return {'names': NAMES[:], 'certificate': str(root / 'fullchain.pem'),
                'private_key': str(root / 'privkey.pem'), 'ports': [443, 8443]}

    def save_config(self):
        self.config_path.write_text(json.dumps(self.config))

    def copy_material(self, label, directory):
        directory.mkdir(parents=True, exist_ok=True)
        for name in ('fullchain.pem', 'privkey.pem'):
            shutil.copyfile(str(self.material[label] / name), str(directory / name))
        os.chmod(str(directory / 'privkey.pem'), 0o600)

    def write_metadata(self, **changes):
        meta = {'Le_Domain': DOMAIN, 'Le_Alt': 'www.example.org', 'Le_Keylength': '2048',
                'Le_NextRenewTime': str(int(time.time() + 100 * 86400)),
                'Le_RealFullChainPath': str(self.manager.stage(DOMAIN) / 'fullchain.pem'),
                'Le_RealKeyPath': str(self.manager.stage(DOMAIN) / 'privkey.pem')}
        meta.update(changes)
        path = self.manager.acme_conf(DOMAIN)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(''.join("{}='{}'\n".format(k, v) for k, v in meta.items()))

    def snapshot(self):
        return {str(p.relative_to(self.base)): (p.stat().st_mode, p.read_bytes() if p.is_file() else None)
                for p in self.base.rglob('*')}

    @contextlib.contextmanager
    def publication(self, verify=None, reload=None):
        with mock.patch.object(sm, 'supported_exchange'), \
             mock.patch.object(sm, 'exchange_directories', side_effect=fake_exchange) as exchange, \
             mock.patch.object(self.manager, 'nginx_test') as check, \
             mock.patch.object(self.manager, 'reload', side_effect=reload) as reload_mock, \
             mock.patch.object(self.manager, 'verify', side_effect=verify) as verify_mock:
            yield exchange, check, reload_mock, verify_mock

    def publish(self):
        stage = self.manager.stage(DOMAIN)
        return self.manager.publish(DOMAIN, stage / 'fullchain.pem', stage / 'privkey.pem')

    def records(self):
        return [sm.read_json(p) for p in sorted((self.manager.home / 'state' / 'transactions').glob('*.json'))]

    def test_real_local_certificate_validation_and_mismatch(self):
        pair = self.material['new']
        result = sm.validate_pair(pair / 'fullchain.pem', pair / 'privkey.pem', NAMES)
        self.assertGreater(result['expires'], time.time())
        with self.assertRaisesRegex(sm.Failure, 'mismatch'):
            sm.validate_pair(pair / 'fullchain.pem', self.material['old'] / 'privkey.pem', NAMES)
        with self.assertRaisesRegex(sm.Failure, 'SAN'):
            sm.validate_pair(pair / 'fullchain.pem', pair / 'privkey.pem', [DOMAIN])

    def test_plan_and_every_dry_run_are_read_only_and_offline(self):
        before = self.snapshot()
        for argv in [['plan'], ['configure', '--dry-run'], ['reconcile', '--dry-run'],
                     ['status', '--dry-run'], ['reissue', '--cert', DOMAIN, '--dry-run'],
                     ['enroll', '--cert', 'new.example.org', '--dry-run']]:
            with mock.patch.object(sm, 'tls_fingerprint', side_effect=AssertionError('network')), \
                 mock.patch.object(sm.Manager, 'acme_run', side_effect=AssertionError('ACME')):
                self.assertEqual(sm.main(argv + ['--config', str(self.config_path)]), 0)
            self.assertEqual(before, self.snapshot())
        self.assertFalse(Path(self.config['lock_file']).exists())

    def test_status_performs_read_only_tls_for_every_name_port(self):
        fingerprint = sm.cert_info(self.manager.group(DOMAIN) / 'fullchain.pem')['fingerprint']
        before = self.snapshot()
        with mock.patch.object(sm, 'tls_fingerprint', return_value=fingerprint) as tls:
            self.assertEqual(sm.main(['status', '--config', str(self.config_path)]), 0)
        self.assertEqual(tls.call_count, 8)
        self.assertEqual(before, self.snapshot())
        self.assertIn('verified', self.out.getvalue())

    def test_empty_registry_status_and_enroll_plan(self):
        self.config['certificates'] = {}
        self.save_config()
        before = self.snapshot()
        self.assertEqual(sm.main(['status', '--config', str(self.config_path)]), 0)
        self.assertEqual(sm.main(['enroll', '--config', str(self.config_path), '--cert',
                                  'new.example.org', '--dry-run']), 0)
        self.assertEqual(before, self.snapshot())

    def test_existing_exclusive_lock_is_detected_by_readonly(self):
        with sm.operation_lock(self.manager.lock_file):
            with self.assertRaisesRegex(sm.Failure, 'lock'):
                sm.main(['plan', '--config', str(self.config_path)])
        with self.manager.lock_file.open('rb') as lock:
            sm.fcntl.flock(lock.fileno(), sm.fcntl.LOCK_EX | sm.fcntl.LOCK_NB)
            with self.assertRaisesRegex(sm.Failure, 'lock'):
                sm.main(['status', '--config', str(self.config_path)])

    def test_readonly_absent_lock_guards_concurrent_writer_without_creating(self):
        with sm.operation_lock(self.manager.lock_file, readonly=True):
            self.assertFalse(self.manager.lock_file.exists())
            with self.assertRaisesRegex(sm.Failure, 'lock'):
                with sm.operation_lock(self.manager.lock_file):
                    self.fail('writer acquired shared directory guard')

    def test_explicit_reissue_and_normal_reconcile_force_semantics(self):
        with mock.patch.object(sm, 'supported_exchange'), \
             mock.patch.object(sm.Manager, 'recover'), \
             mock.patch.object(sm.Manager, 'reconcile_one', return_value='unchanged') as reconcile:
            self.assertEqual(sm.main(['reconcile', '--config', str(self.config_path)]), 0)
            reconcile.assert_called_once_with(DOMAIN, force=False)
            reconcile.reset_mock()
            self.assertEqual(sm.main(['reissue', '--cert', DOMAIN, '--config', str(self.config_path)]), 0)
            reconcile.assert_called_once_with(DOMAIN, force=True)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            sm.main(['reconcile', '--force', '--config', str(self.config_path)])

    def test_renew_dns_argv_never_forces_unless_explicit(self):
        with mock.patch.object(self.manager, 'acme_run', return_value=0) as acme:
            self.manager.renew_acme(DOMAIN)
            argv = acme.call_args[0][0]
            self.assertNotIn('--force', argv)
            self.assertIn('--keylength', argv)
            self.manager.renew_acme(DOMAIN, force=True)
            self.assertIn('--force', acme.call_args[0][0])
            self.assertNotIn('--server', acme.call_args[0][0])

    def test_existing_candidate_published_before_due_and_no_acme(self):
        with self.publication(), mock.patch.object(self.manager, 'renew_acme') as acme:
            self.assertEqual(self.manager.reconcile_one(DOMAIN), 'deployed')
            acme.assert_not_called()
        self.assertEqual(sm.pair_digest(self.manager.group(DOMAIN)), sm.pair_digest(self.material['new']))

    def test_due_and_forced_renewal_skip_older_valid_candidate(self):
        # A five-day staging candidate must not block renewal of ten-day live.
        # Set renew_before_days=1 so these exercise due and force independently.
        self.manager.config['renew_before_days'] = 1
        for force in (False, True):
            with self.subTest(force=force):
                self.copy_material('old', self.manager.group(DOMAIN))
                self.copy_material('older', self.manager.stage(DOMAIN))
                self.write_metadata(Le_NextRenewTime=str(int(time.time() + (86400 if force else -86400))))
                old_live_pair = sm.pair_digest(self.manager.group(DOMAIN))

                def renew(ident, forced):
                    self.assertEqual(ident, DOMAIN)
                    self.assertEqual(forced, force)
                    self.assertEqual(sm.pair_digest(self.manager.group(DOMAIN)), old_live_pair)
                    self.copy_material('new', self.manager.stage(ident))

                with self.publication() as (exchange, _, _, _), \
                     mock.patch.object(self.manager, 'renew_acme', side_effect=renew) as acme:
                    self.assertEqual(self.manager.reconcile_one(DOMAIN, force=force), 'deployed')
                    acme.assert_called_once_with(DOMAIN, force)
                    exchange.assert_called_once()
                self.assertEqual(sm.pair_digest(self.manager.group(DOMAIN)), sm.pair_digest(self.material['new']))
                latest = [record for record in self.records() if record['phase'] == 'committed']
                self.assertTrue(all(record['candidate_pair'] == sm.pair_digest(self.material['new']) for record in latest))

    def test_acme_skip_with_stale_candidate_retains_live_and_verifies(self):
        self.manager.config['renew_before_days'] = 1
        self.copy_material('older', self.manager.stage(DOMAIN))
        self.write_metadata(Le_NextRenewTime=str(int(time.time() - 86400)))
        before = sm.pair_digest(self.manager.group(DOMAIN))
        with self.publication() as (exchange, _, reload, verify), \
             mock.patch.object(self.manager, 'acme_run', return_value=2) as acme:
            self.assertEqual(self.manager.reconcile_one(DOMAIN), 'unchanged')
            acme.assert_called_once()
            self.assertNotIn('--force', acme.call_args[0][0])
            exchange.assert_not_called()
            reload.assert_not_called()
            verify.assert_called_once()
        self.assertEqual(sm.pair_digest(self.manager.group(DOMAIN)), before)
        self.assertEqual(self.records(), [])

    def test_acme_skip_preserves_seven_day_live_guard(self):
        self.copy_material('older', self.manager.group(DOMAIN))
        self.copy_material('older', self.manager.stage(DOMAIN))
        self.write_metadata(Le_NextRenewTime=str(int(time.time() - 86400)))
        before = sm.pair_digest(self.manager.group(DOMAIN))
        with self.publication() as (exchange, _, reload, verify), \
             mock.patch.object(self.manager, 'acme_run', return_value=2) as acme:
            with self.assertRaisesRegex(sm.Failure, 'less than seven days'):
                self.manager.reconcile_one(DOMAIN)
            acme.assert_called_once()
            exchange.assert_not_called()
            reload.assert_not_called()
            verify.assert_called_once()
        self.assertEqual(sm.pair_digest(self.manager.group(DOMAIN)), before)

    def test_explicit_reissue_skip_reports_no_replacement_and_retains_live(self):
        self.manager.config['renew_before_days'] = 1
        for label in ('older', 'old'):
            with self.subTest(candidate=label):
                self.copy_material(label, self.manager.stage(DOMAIN))
                before = sm.pair_digest(self.manager.group(DOMAIN))
                with self.publication() as (exchange, _, reload, verify), \
                     mock.patch.object(self.manager, 'acme_run', return_value=2) as acme:
                    with self.assertRaisesRegex(sm.Failure, 'reissue produced no replacement'):
                        self.manager.reconcile_one(DOMAIN, force=True)
                    acme.assert_called_once()
                    self.assertIn('--force', acme.call_args[0][0])
                    exchange.assert_not_called()
                    reload.assert_not_called()
                    verify.assert_called_once()
                self.assertEqual(sm.pair_digest(self.manager.group(DOMAIN)), before)
                self.assertEqual(self.records(), [])

    def test_new_enrollment_uses_provider_and_staging_without_reload(self):
        shutil.rmtree(str(self.manager.group(DOMAIN)))
        shutil.rmtree(str(self.manager.acme_conf(DOMAIN).parent))
        self.config['certificates'] = {}
        self.save_config()
        self.manager = sm.Manager(self.config_path)
        calls = []

        def acme(args, ident, action, **kwargs):
            calls.append([str(x) for x in args])
            self.write_metadata()
            return 0

        with mock.patch.object(self.manager, 'acme_run', side_effect=acme), \
             mock.patch.object(self.manager, 'nginx_test'), \
             mock.patch.object(self.manager, 'reload') as reload:
            self.assertEqual(self.manager.enroll(DOMAIN, NAMES[1:]), 0)
            reload.assert_not_called()
        self.assertEqual(calls[0][:6], [str(self.manager.acme / 'acme.sh'), '--issue', '--dns', 'dns_test', '--keylength', '2048'])
        self.assertNotIn('--force', calls[0])
        self.assertNotIn('--server', calls[0])
        self.assertIn('--install-cert', calls[1])
        self.assertEqual(sm.pair_digest(self.manager.group(DOMAIN)), sm.pair_digest(self.material['new']))
        self.assertIn(DOMAIN, sm.read_json(self.config_path)['certificates'])

    def test_registered_unprovisioned_group_issues_without_repeating_sans(self):
        shutil.rmtree(str(self.manager.group(DOMAIN)))
        shutil.rmtree(str(self.manager.stage(DOMAIN)))
        shutil.rmtree(str(self.manager.acme_conf(DOMAIN).parent))
        registry_before = self.config_path.read_bytes()
        before = self.snapshot()
        with mock.patch.object(self.manager, 'acme_run') as acme:
            self.assertEqual(self.manager.enroll(DOMAIN, [], dry_run=True), 0)
            acme.assert_not_called()
        self.assertEqual(before, self.snapshot())
        calls = []

        def acme(args, ident, action, **kwargs):
            calls.append([str(x) for x in args])
            if '--issue' in args:
                self.write_metadata(Le_RealFullChainPath='', Le_RealKeyPath='')
            else:
                self.assertIn('--install-cert', args)
                self.copy_material('new', self.manager.stage(ident))
                self.write_metadata()
            return 0

        with mock.patch.object(self.manager, 'acme_run', side_effect=acme), \
             mock.patch.object(self.manager, 'nginx_test'), \
             mock.patch.object(self.manager, 'reload') as reload:
            self.assertEqual(self.manager.enroll(DOMAIN, []), 0)
            reload.assert_not_called()
        self.assertEqual(len(calls), 2)
        self.assertIn('--issue', calls[0])
        self.assertEqual(calls[0][-4:], ['-d', DOMAIN, '-d', NAMES[1]])
        self.assertNotIn('--force', calls[0])
        self.assertIn('--install-cert', calls[1])
        self.assertEqual(sm.pair_digest(self.manager.group(DOMAIN)), sm.pair_digest(self.material['new']))
        self.assertEqual(self.config_path.read_bytes(), registry_before)
        self.assertEqual(self.manager.spec(DOMAIN)['ports'], [443, 8443])

    def test_registered_partial_or_empty_live_group_rejected_before_ca(self):
        shutil.rmtree(str(self.manager.acme_conf(DOMAIN).parent))
        for retained in (None, 'fullchain.pem', 'privkey.pem'):
            with self.subTest(retained=retained):
                target = self.manager.group(DOMAIN)
                shutil.rmtree(str(target))
                target.mkdir()
                if retained:
                    shutil.copyfile(str(self.material['old'] / retained), str(target / retained))
                before = self.snapshot()
                with mock.patch.object(self.manager, 'acme_run') as acme, \
                     mock.patch.object(self.manager, 'configure') as configure:
                    with self.assertRaisesRegex(sm.Failure, 'incomplete'):
                        self.manager.enroll(DOMAIN, [])
                    acme.assert_not_called()
                    configure.assert_not_called()
                self.assertEqual(before, self.snapshot())

    def test_acme_output_withheld_and_metadata_log_private(self):
        proc = subprocess.CompletedProcess([], 0, stdout=b'secret account.conf', stderr=b'private key')
        with mock.patch.object(sm.subprocess, 'run', return_value=proc) as run:
            self.manager.acme_run([self.manager.acme / 'acme.sh', '--renew'], DOMAIN, 'renew')
        kwargs = run.call_args[1]
        self.assertEqual(kwargs['stdout'], subprocess.DEVNULL)
        self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
        self.assertEqual(run.call_args[0][0][-2:], ['--home', str(self.manager.acme)])
        logs = list(self.manager.log_root.rglob('*.log'))
        self.assertEqual(len(logs), 1)
        self.assertRegex(logs[0].name, r'^\d{4}-\d\d-\d\d_\d\d-\d\d-\d\d__renew-')
        self.assertEqual(stat.S_IMODE(logs[0].stat().st_mode), 0o600)
        self.assertNotIn('secret', logs[0].read_text())

    def test_configure_and_renew_reject_staging_links_before_acme(self):
        sentinel = self.base / 'external-sentinel'
        sentinel.write_bytes(b'leave outside material alone')
        live_before = sm.pair_digest(self.manager.group(DOMAIN))
        for operation in ('configure', 'renew'):
            for filename in ('fullchain.pem', 'privkey.pem'):
                for destination in (self.manager.group(DOMAIN) / filename, sentinel):
                    with self.subTest(operation=operation, filename=filename, destination=destination):
                        target = self.manager.stage(DOMAIN) / filename
                        target.unlink()
                        target.symlink_to(destination)
                        with mock.patch.object(self.manager, 'nginx_test'), \
                             mock.patch.object(self.manager, 'acme_run') as acme:
                            with self.assertRaisesRegex(sm.Failure, 'Symlink'):
                                if operation == 'configure':
                                    self.manager.configure([DOMAIN])
                                else:
                                    self.manager.renew_acme(DOMAIN)
                            acme.assert_not_called()
                        self.assertEqual(sm.pair_digest(self.manager.group(DOMAIN)), live_before)
                        self.assertEqual(sentinel.read_bytes(), b'leave outside material alone')
                        target.unlink()
                        shutil.copyfile(str(self.material['new'] / filename), str(target))

    def test_acme_runner_rechecks_stage_targets_before_subprocess(self):
        target = self.manager.stage(DOMAIN) / 'privkey.pem'
        target.unlink()
        target.symlink_to(self.manager.group(DOMAIN) / 'privkey.pem')
        live_before = sm.pair_digest(self.manager.group(DOMAIN))
        with mock.patch.object(sm.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run:
            with self.assertRaisesRegex(sm.Failure, 'Symlink'):
                self.manager.acme_run([self.manager.acme / 'acme.sh', '--renew'], DOMAIN, 'renew')
            run.assert_not_called()
        self.assertEqual(sm.pair_digest(self.manager.group(DOMAIN)), live_before)
        self.assertFalse(self.manager.log_root.exists())

    def test_configure_rejects_special_stage_files_but_allows_new_empty_files(self):
        target = self.manager.stage(DOMAIN) / 'privkey.pem'
        target.unlink()
        os.mkfifo(str(target), 0o600)
        with mock.patch.object(self.manager, 'nginx_test'), \
             mock.patch.object(self.manager, 'acme_run') as acme:
            with self.assertRaisesRegex(sm.Failure, 'regular file'):
                self.manager.configure([DOMAIN])
            acme.assert_not_called()
        target.unlink()
        (self.manager.stage(DOMAIN) / 'fullchain.pem').write_bytes(b'')
        with mock.patch.object(self.manager, 'nginx_test'), \
             mock.patch.object(self.manager, 'acme_run') as acme:
            self.manager.configure([DOMAIN])
            acme.assert_called_once()

    def test_success_publish_backup_hash_permissions_timezone(self):
        with self.publication() as (exchange, check, reload, verify):
            self.assertEqual(self.publish(), 'deployed')
            exchange.assert_called_once()
            reload.assert_called_once()
        record = self.records()[0]
        self.assertEqual(record['phase'], 'committed')
        backup = Path(record['previous_backup'])
        self.assertRegex(backup.name, r'^\d{4}-\d\d-\d\d_\d\d-\d\d-\d\d__cert')
        manifest = sm.read_json(backup / 'manifest.json')
        self.assertTrue(manifest['created_at'].endswith('+08:00'))
        self.assertEqual(manifest['timezone'], 'Asia/Shanghai')
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((backup / 'payload' / 'privkey.pem').stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((backup / 'manifest.json').stat().st_mode), 0o600)
        self.assertEqual(sm.pair_digest(backup / 'payload'), manifest['files'])
        self.manager.backup_material(record)
        self.assertFalse(Path(record['work_dir']).exists())

    def test_baseline_mismatch_and_missing_key_refuse_exchange(self):
        shutil.copyfile(str(self.material['new'] / 'privkey.pem'),
                        str(self.manager.group(DOMAIN) / 'privkey.pem'))
        with self.publication() as (exchange, _, _, _):
            with self.assertRaisesRegex(sm.Failure, 'mismatch'):
                self.publish()
            exchange.assert_not_called()
        (self.manager.group(DOMAIN) / 'privkey.pem').unlink()
        with self.publication() as (exchange, _, _, _):
            with self.assertRaises(sm.Failure):
                self.publish()
            exchange.assert_not_called()

    def test_candidate_mismatch_refuses_publish(self):
        shutil.copyfile(str(self.material['old'] / 'privkey.pem'),
                        str(self.manager.stage(DOMAIN) / 'privkey.pem'))
        with self.publication() as (exchange, _, _, _):
            with self.assertRaisesRegex(sm.Failure, 'mismatch'):
                self.publish()
            exchange.assert_not_called()

    def test_nginx_check_failure_does_not_exchange(self):
        before = sm.pair_digest(self.manager.group(DOMAIN))
        with self.publication() as (exchange, check, reload, _):
            check.side_effect = sm.Failure('nginx syntax failure')
            with self.assertRaisesRegex(sm.Failure, 'syntax'):
                self.publish()
            exchange.assert_not_called()
            reload.assert_not_called()
        self.assertEqual(before, sm.pair_digest(self.manager.group(DOMAIN)))

    def test_post_switch_failure_restores_old_pair(self):
        before = sm.pair_digest(self.manager.group(DOMAIN))
        with self.publication(verify=[sm.Failure('new TLS mismatch'), None, None]) as (exchange, _, _, _):
            with self.assertRaisesRegex(sm.Failure, 'rolled back'):
                self.publish()
            self.assertEqual(exchange.call_count, 2)
        self.assertEqual(before, sm.pair_digest(self.manager.group(DOMAIN)))
        self.assertEqual(self.records()[0]['phase'], 'rolled_back')

    def test_rollback_failure_blocks_following_operations(self):
        with self.publication(reload=[sm.Failure('reload'), sm.Failure('restore reload')]):
            with self.assertRaisesRegex(sm.Failure, 'ROLLBACK FAILED'):
                self.publish()
        self.assertEqual(self.records()[0]['phase'], 'rollback_failed')
        with self.publication(reload=sm.Failure('still broken')):
            with self.assertRaisesRegex(sm.Failure, 'ROLLBACK FAILED'):
                self.manager.recover()

    def test_uncommitted_prepared_and_switched_recover(self):
        with self.publication():
            self.publish()
            record = self.records()[0]
            record['phase'] = 'prepared'  # interruption after exchange, before switched journal
            self.manager.journal(record)
            self.manager.recover()
        self.assertEqual(self.records()[0]['phase'], 'rolled_back')
        self.assertEqual(sm.pair_digest(self.manager.group(DOMAIN)), sm.pair_digest(self.material['old']))
        with self.publication():
            self.publish()
            record = [r for r in self.records() if r['phase'] == 'committed'][0]
            record['phase'] = 'switched'
            self.manager.journal(record)
            self.manager.recover()
        self.assertTrue(all(r['phase'] == 'rolled_back' for r in self.records()))

    def test_interrupted_recovery_preserves_extra_live_members_and_work(self):
        with self.publication(), mock.patch.object(self.manager, 'cleanup_work'):
            self.publish()
        record = self.records()[0]
        record['phase'] = 'switched'
        self.manager.journal(record)
        job = Path(record['work_dir'])
        work_before = {str(p.relative_to(job)): p.read_bytes() for p in job.rglob('*') if p.is_file()}
        sentinel = self.manager.group(DOMAIN) / 'unrelated.conf'
        sentinel.write_bytes(b'keep this file at its live path')
        live_before = sm.pair_digest(self.manager.group(DOMAIN))
        with self.publication() as (exchange, _, reload, _), \
             mock.patch.object(self.manager, 'cleanup_work') as cleanup:
            with self.assertRaisesRegex(sm.Failure, 'ROLLBACK FAILED.*only its certificate'):
                self.manager.recover()
            exchange.assert_not_called()
            reload.assert_not_called()
            cleanup.assert_not_called()
        self.assertEqual(sentinel.read_bytes(), b'keep this file at its live path')
        self.assertEqual(sm.pair_digest(self.manager.group(DOMAIN)), live_before)
        self.assertTrue(job.is_dir())
        self.assertEqual({str(p.relative_to(job)): p.read_bytes() for p in job.rglob('*') if p.is_file()}, work_before)
        self.assertEqual(self.records()[0]['phase'], 'rollback_failed')

    def test_expired_baseline_can_be_repaired(self):
        self.copy_material('expired', self.manager.group(DOMAIN))
        with self.publication():
            self.assertEqual(self.publish(), 'deployed')
        self.assertEqual(sm.pair_digest(self.manager.group(DOMAIN)), sm.pair_digest(self.material['new']))

    def test_expired_live_status_preserves_fingerprint_and_reports_tls_invalid(self):
        self.copy_material('expired', self.manager.group(DOMAIN))
        fingerprint = sm.cert_info(self.manager.group(DOMAIN) / 'fullchain.pem')['fingerprint']

        def tls(address, name, port, strict=True):
            if strict:
                raise sm.Failure('certificate has expired')
            return fingerprint

        with mock.patch.object(sm, 'tls_fingerprint', side_effect=tls):
            self.assertEqual(self.manager.status([DOMAIN]), 1)
        row = json.loads(self.out.getvalue())[0]
        self.assertEqual(row['origin_fingerprint'], 'matches_live')
        self.assertIn('expired', row['error'])
        self.assertEqual(row['fingerprint'], fingerprint)

    def test_damaged_backup_stops_rollback(self):
        with self.publication():
            self.publish()
        record = self.records()[0]
        (Path(record['previous_backup']) / 'payload' / 'privkey.pem').write_text('corrupted')
        with self.assertRaisesRegex(sm.Failure, 'integrity|SHA256'):
            self.manager.backup_material(record)

    def test_tampered_manifest_sums_and_record_identity(self):
        with self.publication():
            self.publish()
        record = self.records()[0]
        (Path(record['previous_backup']) / 'SHA256SUMS').write_text('wrong')
        with self.assertRaisesRegex(sm.Failure, 'SHA256'):
            self.manager.backup_material(record)
        record['cert_id'] = 'other.example.org'
        with self.assertRaises(sm.Failure):
            self.manager.validate_record(record)

    def test_recovery_never_removes_external_path_or_symlink(self):
        with self.publication():
            self.publish()
        record = self.records()[0]
        external = self.base / 'must-survive'
        external.mkdir()
        (external / 'sentinel').write_text('keep')
        record['work_dir'] = str(external)
        with self.assertRaises(sm.Failure):
            self.manager.cleanup_work(record)
        record['work_dir'] = str(self.manager.work / DOMAIN / 'publish-escape')
        Path(record['work_dir']).symlink_to(external, target_is_directory=True)
        with self.assertRaises(sm.Failure):
            self.manager.cleanup_work(record)
        self.assertEqual((external / 'sentinel').read_text(), 'keep')
        record['previous_backup'] = str(external)
        with self.assertRaises(sm.Failure):
            self.manager.backup_material(record)

    def test_unsafe_roots_names_ports_symlinks_and_provider_rejected(self):
        changes = [({'work_root': str(self.base / 'nginx' / 'work')}, None),
                   ({'work_root': str(self.base / 'work' / '..' / 'escape')}, None),
                   ({'dns_provider': 'dns_test; bad'}, None),
                   ({'nginx_reload_command': 'nginx -s reload'}, None),
                   ({}, {'ports': [True]}), ({}, {'ports': [0]}),
                   ({}, {'names': [DOMAIN, '*.example.org']}),
                   ({}, {'names': ['www.example.org', DOMAIN]})]
        for changeset, spec_change in changes:
            config = json.loads(json.dumps(self.config))
            config.update(changeset)
            if spec_change:
                config['certificates'][DOMAIN].update(spec_change)
            self.config_path.write_text(json.dumps(config))
            with self.assertRaises(sm.Failure):
                sm.Manager(self.config_path)
        self.save_config()
        link = self.base / 'symlink-work'
        link.symlink_to(self.manager.work, target_is_directory=True)
        self.config['work_root'] = str(link)
        self.save_config()
        with self.assertRaisesRegex(sm.Failure, 'Symlink'):
            sm.Manager(self.config_path)

    def test_unsupported_platform_stops_without_any_changes(self):
        before = self.snapshot()
        with mock.patch.object(sm.platform, 'system', return_value='Darwin'):
            with self.assertRaisesRegex(sm.Failure, 'Linux'):
                self.manager.publish(DOMAIN, self.manager.stage(DOMAIN) / 'fullchain.pem',
                                     self.manager.stage(DOMAIN) / 'privkey.pem')
        self.assertEqual(before, self.snapshot())

    def test_native_and_docker_trusted_argv_passed_without_shell(self):
        with mock.patch.object(sm, 'run') as run:
            self.manager.reload()
            self.assertEqual(run.call_args_list, [mock.call(['nginx', '-t']),
                                                 mock.call(['nginx', '-s', 'reload'])])
            run.reset_mock()
            self.manager.config['nginx_test_command'] = ['docker', 'exec', 'nginx', 'nginx', '-t']
            self.manager.config['nginx_reload_command'] = ['docker', 'exec', 'nginx', 'nginx', '-s', 'reload']
            self.manager.reload()
            self.assertEqual(run.call_args_list[0][0][0][:3], ['docker', 'exec', 'nginx'])
        result = subprocess.CompletedProcess([], 1, stdout=b'', stderr=b'account.conf=secret')
        with mock.patch.object(sm.subprocess, 'run', return_value=result) as run:
            with self.assertRaises(sm.Failure) as caught:
                sm.run(['nginx', '-t'])
            self.assertNotIn('secret', str(caught.exception))
            self.assertNotIn('shell', run.call_args[1])

    def test_acme_identity_hooks_ecc_and_live_install_target_rejected(self):
        for changes in [{'Le_Domain': 'wrong.example.org'}, {'Le_Keylength': 'ec-256'},
                        {'Le_DeployHook': 'danger'}, {'Le_RealFullChainPath': self.group_spec()['certificate']}]:
            self.write_metadata(**changes)
            with mock.patch.object(self.manager, 'nginx_test'), \
                 mock.patch.object(self.manager, 'acme_run') as acme:
                with self.assertRaises(sm.Failure):
                    self.manager.configure([DOMAIN])
                acme.assert_not_called()

    def test_live_group_with_unrelated_files_is_never_exchanged(self):
        sentinel = self.manager.group(DOMAIN) / 'site.conf'
        sentinel.write_text('must remain')
        with self.publication() as (exchange, _, _, _):
            with self.assertRaisesRegex(sm.Failure, 'only its certificate'):
                self.publish()
            exchange.assert_not_called()
        self.assertEqual(sentinel.read_text(), 'must remain')

    def test_rollback_dry_run_is_readonly_and_expired_backup_is_refused(self):
        self.copy_material('expired', self.manager.group(DOMAIN))
        with self.publication():
            self.publish()
        record = self.records()[0]
        before = self.snapshot()
        with mock.patch.object(sm, 'tls_fingerprint', side_effect=AssertionError('network')):
            self.assertEqual(sm.main(['rollback', '--config', str(self.config_path),
                                      '--transaction', record['id'], '--dry-run']), 0)
        self.assertEqual(before, self.snapshot())
        with self.publication() as (exchange, _, _, _):
            with self.assertRaisesRegex(sm.Failure, 'validity'):
                self.manager.rollback(record['id'])
            exchange.assert_not_called()

    def test_expired_old_pair_restore_marks_failure_and_blocks(self):
        self.copy_material('expired', self.manager.group(DOMAIN))
        with self.publication(verify=[sm.Failure('new TLS failed'), None,
                                      sm.Failure('old certificate expired')]):
            with self.assertRaisesRegex(sm.Failure, 'ROLLBACK FAILED'):
                self.publish()
        record = self.records()[0]
        self.assertEqual(record['phase'], 'rollback_failed')
        self.assertFalse(record['rollback_tls_valid'])
        self.assertEqual(sm.pair_digest(self.manager.group(DOMAIN)), sm.pair_digest(self.material['expired']))

    def test_manual_rollback_checks_stale_current_and_old_expiration(self):
        with self.publication():
            self.publish()
            record = self.records()[0]
            self.manager.rollback(record['id'])
        self.assertEqual(sm.pair_digest(self.manager.group(DOMAIN)), sm.pair_digest(self.material['old']))
        with self.assertRaisesRegex(sm.Failure, 'stale'):
            self.manager.rollback(record['id'])


if __name__ == '__main__':
    unittest.main()
