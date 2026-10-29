#!/usr/bin/env python3
"""Transactional RSA certificate publication; Python 3.6+, stdlib only.

Requires administrator-owned configuration, acme.sh, OpenSSL and Linux renameat2.
ACME writes staging only. This program owns live directories, backups and reload.
No application routes, CA defaults, credentials or scheduled jobs are installed.
"""
import ctypes
import platform
import argparse
import base64
import datetime
import fcntl
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import stat
import contextlib
import uuid
from pathlib import Path


class Failure(RuntimeError):
    pass


def run(args, data=None, timeout=30):
    """Never include external output or argv values in errors (they may be secret)."""
    try:
        p = subprocess.run([str(a) for a in args], input=data, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.SubprocessError:
        raise Failure('External command timed out or could not complete')
    if p.returncode:
        raise Failure('External command failed (exit {}); output withheld'.format(p.returncode))
    return p.stdout


def safe_path(value):
    """Reject ambiguous paths and every existing symlink component."""
    if not isinstance(value, (str, Path)):
        raise Failure('Path must be a string')
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts or path == Path('/'):
        raise Failure('Expected an absolute non-root path without traversal')
    for part in [path] + list(path.parents):
        if part.is_symlink():
            raise Failure('Symlink paths are not supported')
    return path


def regular_file(path):
    path = safe_path(path)
    if not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise Failure('Expected a regular file')
    return path


def valid_name(name):
    if not isinstance(name, str) or len(name) > 253 or '.' not in name:
        return False
    return all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
               for label in name.split('.')) and not name.split('.')[-1].isdigit()


def supported_exchange():
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'aarch64'):
        raise Failure('Linux x86_64/aarch64 renameat2 is required; no non-atomic fallback')


@contextlib.contextmanager
def operation_lock(path, readonly=False):
    """The existing parent directory is a stable guard if the lock file is absent.

    All invocations take this guard before the lock file. Also honor independent
    users of the existing lock file. Read-only commands never create either.
    """
    path = safe_path(path)
    if not path.parent.is_dir():
        raise Failure('lock_file parent must already exist')
    guard = os.open(str(path.parent), os.O_RDONLY)
    fd = None
    mode = fcntl.LOCK_SH if readonly else fcntl.LOCK_EX
    try:
        try:
            fcntl.flock(guard, mode | fcntl.LOCK_NB)
            flags = os.O_RDONLY if readonly else os.O_RDWR | os.O_CREAT
            try:
                fd = os.open(str(path), flags | os.O_NOFOLLOW, 0o600)
            except FileNotFoundError:
                if not readonly:
                    raise
            if fd is not None:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise Failure('Lock must be a regular file')
                fcntl.flock(fd, mode | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Failure('Another certificate operation owns the lock')
        yield
    finally:
        if fd is not None:
            os.close(fd)
        os.close(guard)


def utc_iso(timestamp=None):
    value = (datetime.datetime.now(datetime.timezone.utc) if timestamp is None else
             datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc))
    return value.isoformat().replace('+00:00', 'Z')


def sync_dir(path):
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_bytes(path, content, mode=0o600):
    path = safe_path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name + '.', dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, str(path))
        sync_dir(path.parent)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def atomic_json(path, content):
    atomic_bytes(path, (json.dumps(content, indent=2, sort_keys=True) + '\n').encode())


def exchange_directories(left, right):
    """Atomically exchange two real directories on the same filesystem."""
    supported_exchange()
    left, right = safe_path(left), safe_path(right)
    for path in (left, right):
        if path.is_symlink() or not path.is_dir():
            raise Failure('Exchange requires real directories: ' + str(path))
    if left.stat().st_dev != right.stat().st_dev:
        raise Failure('Certificate publication requires one filesystem')
    number = {'x86_64': 316, 'aarch64': 276}.get(platform.machine())
    if number is None:
        raise Failure('Unsupported platform for atomic directory exchange')
    libc = ctypes.CDLL(None, use_errno=True)
    rc = libc.syscall(ctypes.c_long(number), ctypes.c_int(-100), os.fsencode(str(left)),
                      ctypes.c_int(-100), os.fsencode(str(right)), ctypes.c_uint(2))
    if rc:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    sync_dir(left.parent)
    sync_dir(right.parent)


def pair_digest(directory):
    directory = safe_path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise Failure('Expected a real certificate directory: ' + str(directory))
    digests = {}
    for name in ('fullchain.pem', 'privkey.pem'):
        path = regular_file(directory / name)
        digests[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digests


def copy_pair(cert, key, directory):
    directory = safe_path(directory)
    cert, key = regular_file(cert), regular_file(key)
    directory.mkdir(parents=True, mode=0o700)
    atomic_bytes(directory / 'fullchain.pem', Path(cert).read_bytes(), 0o644)
    atomic_bytes(directory / 'privkey.pem', Path(key).read_bytes(), 0o600)
    sync_dir(directory)
    return pair_digest(directory)


def read_json(path):
    with regular_file(path).open() as f:
        return json.load(f)


def read_acme(path):
    """Read an allowlisted set of simple assignments; never source shell config."""
    allowed = {'Le_Domain', 'Le_Alt', 'Le_Keylength', 'Le_NextRenewTime',
               'Le_RealFullChainPath', 'Le_RealKeyPath', 'Le_RealCertPath',
               'Le_RealCACertPath', 'Le_ReloadCmd', 'Le_PreHook', 'Le_PostHook',
               'Le_RenewHook', 'Le_DeployHook'}
    result = {}
    for line in regular_file(path).read_text().splitlines():
        key, sep, val = line.partition('=')
        if sep and key in allowed:
            val = val.strip().strip("'\"")
            if val.startswith('__ACME_BASE64__START_'):
                val = base64.b64decode(val[len('__ACME_BASE64__START_'):].split(
                    '__ACME_BASE64__END_')[0]).decode()
            result[key] = val
    return result


def cert_info(cert):
    cert = regular_file(cert)
    der = run(['openssl', 'x509', '-in', cert, '-outform', 'DER'])
    decoded = ssl._ssl._test_decode_cert(str(cert))
    return {'fingerprint': hashlib.sha256(der).hexdigest(),
            'not_before': ssl.cert_time_to_seconds(decoded['notBefore']),
            'expires': ssl.cert_time_to_seconds(decoded['notAfter']),
            'decoded': decoded}


def validate_pair(cert, key, names, min_seconds=86400, check_time=True):
    cert, key = regular_file(cert), regular_file(key)
    info = cert_info(cert)
    now = time.time()
    if check_time and (info['not_before'] > now or info['expires'] < now + min_seconds):
        raise Failure('Certificate validity window is unsuitable')
    dns_names = [value for kind, value in info['decoded'].get('subjectAltName', []) if kind == 'DNS']
    if any('*' in name for name in dns_names) or set(dns_names) != set(names):
        raise Failure('Certificate SAN set must exactly match the registered non-wildcard names')
    cert_public = run(['openssl', 'x509', '-in', cert, '-pubkey', '-noout'])
    cert_public = run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], cert_public)
    key_public = run(['openssl', 'pkey', '-in', key, '-pubout', '-outform', 'DER'])
    if cert_public != key_public:
        raise Failure('Certificate/private key mismatch')
    # acme.sh's <domain>/ layout here is deliberately RSA-2048 only.
    rsa = run(['openssl', 'rsa', '-in', key, '-noout', '-text'])
    if not re.search(rb'(?:Private-Key:|RSA Private-Key:) \(2048 bit', rsa):
        raise Failure('Only RSA 2048 certificates are supported')
    leaf = run(['openssl', 'x509', '-in', cert, '-outform', 'PEM'])
    args = ['openssl', 'verify', '-untrusted', cert]
    if not check_time:
        args.append('-no_check_time')
    # OpenSSL accepts the leaf on stdin; even read-only validation needs no
    # temporary file and never copies a key outside its existing directory.
    run(args, leaf)
    return info


def tls_fingerprint(address, name, port, strict=True):
    context = ssl.create_default_context() if strict else ssl._create_unverified_context()
    with socket.create_connection((address, port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=name) as conn:
            return hashlib.sha256(conn.getpeercert(binary_form=True)).hexdigest()


class Manager:
    def __init__(self, config_path):
        self.config_path = regular_file(config_path)
        self.config = read_json(self.config_path)
        self.root = safe_path(self.config['nginx_root'])
        self.home = self.root / 'ssl'
        self.log_root = safe_path(self.config['log_root'])
        self.acme = safe_path(self.config['acme_home'])
        self.certs = self.config['certificates']
        self.backups = safe_path(self.config['backup_root'])
        self.work = safe_path(self.config['work_root'])
        self.lock_file = safe_path(self.config['lock_file'])
        offset = self.config.get('timezone_offset', '+00:00')
        if not isinstance(offset, str) or not re.fullmatch(r'[+-](?:0\d|1[0-3]):[0-5]\d|[+-]14:00', offset):
            raise Failure('timezone_offset must be an ISO offset from -14:00 to +14:00')
        minutes = int(offset[1:3]) * 60 + int(offset[4:6])
        self.timezone = datetime.timezone(datetime.timedelta(minutes=minutes if offset[0] == '+' else -minutes))
        self.timezone_name = self.config.get('timezone_name', 'UTC' + offset)
        if not isinstance(self.timezone_name, str) or not self.timezone_name or len(self.timezone_name) > 80:
            raise Failure('Invalid timezone_name')
        self.validate_config()

    def now(self):
        return datetime.datetime.now(self.timezone)

    def validate_config(self):
        # Administrator-controlled roots must not overlap: work cleanup can never
        # reach live material, ACME account data, logs or historical backups.
        roots = [self.root, self.acme, self.log_root, self.backups, self.work]
        for path in roots:
            safe_path(path)
        for i, left in enumerate(roots):
            for right in roots[i + 1:]:
                if left == right or left in right.parents or right in left.parents:
                    raise Failure('nginx/acme/log/backup/work roots must be independent')
        if any(self.lock_file == p or p in self.lock_file.parents for p in roots):
            raise Failure('lock_file must be outside managed roots')
        safe_path(self.home)
        safe_path(self.root / 'cert')
        safe_path(self.home / 'state' / 'transactions')
        for field in ('nginx_test_command', 'nginx_reload_command'):
            argv = self.config.get(field)
            if not isinstance(argv, list) or not argv or any(
                    not isinstance(a, str) or not a or '\x00' in a for a in argv):
                raise Failure(field + ' must be a nonempty trusted argv array')
        provider = self.config.get('dns_provider')
        if not isinstance(provider, str) or not re.fullmatch(r'dns_[A-Za-z0-9_]+', provider):
            raise Failure('dns_provider must be an acme.sh dns_ provider name')
        address = self.config.get('origin_address')
        if not isinstance(address, str) or not address or any(c.isspace() for c in address) or '/' in address or '\x00' in address:
            raise Failure('Invalid origin_address (host/IP without a port)')
        if ':' in address:
            try:
                socket.inet_pton(socket.AF_INET6, address)
            except OSError:
                raise Failure('origin_address must not include a port')
        days = self.config.get('renew_before_days', 30)
        if type(days) is not int or not 1 <= days <= 365:
            raise Failure('renew_before_days must be an integer from 1 to 365')
        if not isinstance(self.certs, dict):
            raise Failure('certificates must be an object (an empty registry is allowed)')
        all_names = set()
        paths = set()
        for ident, spec in self.certs.items():
            if not valid_name(ident):
                raise Failure('Invalid certificate id (lowercase DNS names only; no wildcards)')
            if not isinstance(spec, dict) or not isinstance(spec.get('names'), list) or not spec['names'] or spec['names'][0] != ident:
                raise Failure('Primary domain must be first in names')
            for name in spec['names']:
                if not valid_name(name):
                    raise Failure('Invalid DNS name (wildcards are not supported)')
                if name in all_names:
                    raise Failure('Duplicate DNS name: ' + name)
                all_names.add(name)
            ports = spec.get('ports', [443])
            if not isinstance(ports, list) or not ports or len(ports) != len(set(ports)):
                raise Failure('ports must be a nonempty list without duplicates')
            for port in ports:
                if type(port) is not int or not 1 <= port <= 65535:
                    raise Failure('Invalid TLS port')
            safe_path(self.group(ident))
            safe_path(self.stage(ident))
            for k in ['certificate', 'private_key']:
                path = safe_path(spec[k])
                filename = 'fullchain.pem' if k == 'certificate' else 'privkey.pem'
                if path != self.root / 'cert' / ident / filename or str(path) in paths:
                    raise Failure('Unexpected or duplicate live path: ' + str(path))
                paths.add(str(path))

    def emit(self, event, **fields):
        record = dict(time=self.now().isoformat(), event=event, **fields)
        print(json.dumps(record, sort_keys=True), flush=True)

    def spec(self, ident):
        if ident not in self.certs:
            raise Failure('Unknown certificate group: ' + ident)
        return self.certs[ident]

    def group(self, ident):
        return self.root / 'cert' / ident

    def live_pair_digest(self, ident):
        group = safe_path(self.group(ident))
        if not group.is_dir() or set(p.name for p in group.iterdir()) != {'fullchain.pem', 'privkey.pem'}:
            raise Failure('Live group must contain only its certificate/key pair')
        return pair_digest(group)

    def stage(self, ident):
        return self.home / 'staging' / ident

    def validate_stage_targets(self, ident):
        """Check the actual files ACME will overwrite, not just metadata paths.

        Missing files and empty regular files are valid install-cert targets.
        Symlinks (including dangling links) and special files are never targets.
        Managed roots must stay administrator-owned while this lock is held.
        """
        stage = safe_path(self.stage(ident))
        if stage.exists() and not stage.is_dir():
            raise Failure('Staging must be a real directory')
        for filename in ('fullchain.pem', 'privkey.pem'):
            target = safe_path(stage / filename)
            if target.exists():
                regular_file(target)
        return stage

    def acme_conf(self, ident):
        return self.acme / ident / (ident + '.conf')

    def acme_metadata(self, ident, names=None):
        names = names or self.spec(ident)['names']
        conf = self.acme_conf(ident)
        if not conf.exists():
            if (self.acme / (ident + '_ecc')).exists():
                raise Failure('ECC acme.sh layout is unsupported; use RSA 2048')
            raise Failure('No RSA acme.sh registration for certificate group')
        meta = read_acme(conf)
        alternate = [] if meta.get('Le_Alt', '') in ('', 'no') else meta['Le_Alt'].split(',')
        if meta.get('Le_Domain') != ident or set([ident] + alternate) != set(names):
            raise Failure('ACME registration domain/SAN identity differs from registry')
        if meta.get('Le_Keylength') != '2048':
            raise Failure('Only the RSA 2048 acme.sh layout is supported')
        for hook in ['Le_PreHook', 'Le_PostHook', 'Le_RenewHook', 'Le_DeployHook']:
            if meta.get(hook, '') not in ('', 'no'):
                raise Failure('Unexpected ACME hook; review registration before writes')
        return meta

    def check_staging_owner(self, ident):
        self.validate_stage_targets(ident)
        meta = self.acme_metadata(ident)
        expected = {'Le_RealFullChainPath': str(self.stage(ident) / 'fullchain.pem'),
                    'Le_RealKeyPath': str(self.stage(ident) / 'privkey.pem')}
        for key, value in expected.items():
            if meta.get(key) != value:
                raise Failure('ACME installation target is not staging for ' + ident)
        for key in ['Le_ReloadCmd', 'Le_PreHook', 'Le_PostHook', 'Le_RenewHook',
                    'Le_DeployHook', 'Le_RealCertPath', 'Le_RealCACertPath']:
            if meta.get(key, '') not in ('', 'no'):
                raise Failure('Unexpected ACME hook/extra installation target: ' + key)
        return meta

    def nginx_test(self):
        run(self.config['nginx_test_command'])

    def reload(self):
        self.nginx_test()
        run(self.config['nginx_reload_command'])

    def verify(self, ident, expected, strict=True, attempts=3):
        spec = self.spec(ident)
        last = None
        for attempt in range(attempts):
            try:
                for name in spec['names']:
                    for port in spec.get('ports', [443]):
                        actual = tls_fingerprint(self.config['origin_address'], name, port, strict)
                        if actual != expected:
                            raise Failure('Served fingerprint differs for {}:{}'.format(name, port))
                return
            except (OSError, Failure) as exc:
                last = exc
                if attempt + 1 < attempts:
                    time.sleep(1)
        raise Failure('Origin TLS verification failed for {}: {}'.format(ident, last))

    def backup_pair(self, ident, cert, key, reason='before_publish', extra=None):
        parent = safe_path(self.backups / ident)
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        stamp = self.now().strftime('%Y-%m-%d_%H-%M-%S')
        name = stamp + '__cert'
        for suffix in range(10000):
            dest = parent / (name if not suffix else name + '__{:02d}'.format(suffix + 1))
            try:
                dest.mkdir(mode=0o700)
                break
            except FileExistsError:
                continue
        else:
            raise Failure('Unable to allocate certificate backup')
        files = copy_pair(cert, key, dest / 'payload')
        if files != {'fullchain.pem': hashlib.sha256(Path(cert).read_bytes()).hexdigest(),
                     'privkey.pem': hashlib.sha256(Path(key).read_bytes()).hexdigest()}:
            raise Failure('Certificate changed during backup')
        info = cert_info(dest / 'payload' / 'fullchain.pem')
        manifest = {'layout_version': 2, 'cert_id': ident, 'reason': reason,
                    'created_at': self.now().isoformat(),
                    'timezone': self.timezone_name, 'files': files, 'fingerprint': info['fingerprint'],
                    'expires_utc': utc_iso(info['expires']),
                    'automatic_deletion': False, 'source': {'certificate': str(cert), 'private_key': str(key)}}
        if extra:
            manifest['details'] = extra
        atomic_json(dest / 'manifest.json', manifest)
        atomic_bytes(dest / 'SHA256SUMS', ''.join('{}  payload/{}\n'.format(files[n], n)
                                               for n in sorted(files)).encode())
        sync_dir(parent)
        return dest

    def backup_material(self, record):
        backup = safe_path(record['previous_backup'])
        expected_parent = self.backups / record['cert_id']
        if backup.parent != expected_parent or backup.is_symlink() or backup.resolve() != backup:
            raise Failure('Unexpected certificate backup location')
        manifest = read_json(backup / 'manifest.json')
        if manifest.get('layout_version') != 2 or manifest['cert_id'] != record['cert_id']:
            raise Failure('Backup certificate group/version mismatch')
        material = backup / 'payload'
        actual = pair_digest(material)
        sums = ''.join('{}  payload/{}\n'.format(actual[n], n) for n in sorted(actual))
        if regular_file(backup / 'SHA256SUMS').read_text() != sums:
            raise Failure('Backup SHA256SUMS verification failed')
        if cert_info(material / 'fullchain.pem')['fingerprint'] != manifest['fingerprint']:
            raise Failure('Backup fingerprint verification failed')
        if actual != manifest['files'] or actual != record['previous_pair']:
            raise Failure('Certificate backup integrity verification failed')
        return material

    def new_work(self, ident, cert, key):
        parent = safe_path(self.work / ident)
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        job = Path(tempfile.mkdtemp(prefix='publish-', dir=str(parent)))
        copy_pair(cert, key, job / 'candidate')
        sync_dir(parent)
        return job

    def validate_record(self, record, filename=None):
        if not isinstance(record, dict) or record.get('layout_version') != 2:
            raise Failure('Unknown transaction layout; manual review is required')
        ident = record.get('cert_id')
        self.spec(ident)
        txid = record.get('id', '')
        if not isinstance(txid, str) or not re.fullmatch(r'[A-Za-z0-9-]+', txid):
            raise Failure('Invalid transaction identity')
        if filename is not None and filename != txid + '.json':
            raise Failure('Transaction file identity mismatch')
        if record.get('phase') not in ('prepared', 'switched', 'committed', 'rolled_back', 'rollback_failed'):
            raise Failure('Unknown transaction phase')
        for field in ('previous_pair', 'candidate_pair'):
            value = record.get(field)
            if not isinstance(value, dict) or set(value) != {'fullchain.pem', 'privkey.pem'} or any(
                    not isinstance(v, str) or not re.fullmatch(r'[0-9a-f]{64}', v) for v in value.values()):
                raise Failure('Invalid transaction pair digest')
        for field in ('previous_fingerprint', 'candidate_fingerprint'):
            if not isinstance(record.get(field), str) or not re.fullmatch(r'[0-9a-f]{64}', record[field]):
                raise Failure('Invalid transaction fingerprint')
        backup = safe_path(record['previous_backup'])
        if backup.parent != self.backups / ident:
            raise Failure('Unexpected transaction backup path')
        for field in ('work_dir', 'restore_work_dir'):
            if record.get(field):
                path = safe_path(record[field])
                if path.parent != self.work / ident or not re.fullmatch(r'publish-[A-Za-z0-9_-]+', path.name):
                    raise Failure('Unexpected transaction work directory')

    def journal(self, record):
        self.validate_record(record)
        atomic_json(self.home / 'state' / 'transactions' / (record['id'] + '.json'), record)

    def cleanup_work(self, record):
        job = record.get('work_dir')
        if not job:
            return
        path = safe_path(job)
        if path.parent != self.work / record['cert_id'] or not path.name.startswith('publish-') or path.is_symlink():
            raise Failure('Unexpected transaction work directory')
        if path.exists():
            shutil.rmtree(str(path))
            sync_dir(path.parent)

    def restore(self, record):
        self.validate_record(record)
        ident = record['cert_id']
        try:
            material = self.backup_material(record)
            restored_info = validate_pair(material / 'fullchain.pem', material / 'privkey.pem',
                                          self.spec(ident)['names'], check_time=False)
            if restored_info['fingerprint'] != record['previous_fingerprint']:
                raise Failure('Backup differs from transaction fingerprint')
            current = self.live_pair_digest(ident)
            if current not in (record['previous_pair'], record['candidate_pair']):
                raise Failure('Live certificate changed outside this transaction')
            if current != record['previous_pair']:
                # Rebuild from the verified backup. This is repeatable even if a
                # previous restore was interrupted immediately after exchange.
                job = self.new_work(ident, material / 'fullchain.pem', material / 'privkey.pem')
                record['restore_work_dir'] = str(job)
                self.journal(record)
                exchange_directories(job / 'candidate', self.group(ident))
            self.reload()
            self.verify(ident, record['previous_fingerprint'], strict=False)
            try:
                self.verify(ident, record['previous_fingerprint'], strict=True, attempts=1)
                record['rollback_tls_valid'] = True
            except (Failure, OSError):
                record['rollback_tls_valid'] = False
            record['phase'] = 'rolled_back'
            self.journal(record)
            self.emit('rolled_back', cert=ident, tls_valid=record['rollback_tls_valid'], transaction=record['id'])
            if not record['rollback_tls_valid']:
                raise Failure('Previous files restored but origin TLS is invalid; manual repair required')
        except Exception as exc:
            record['phase'] = 'rollback_failed'
            record['rollback_error'] = str(exc)
            self.journal(record)
            raise Failure('ROLLBACK FAILED; stop publication: ' + str(exc))

    def recover(self):
        for path in sorted((self.home / 'state' / 'transactions').glob('*.json')):
            record = read_json(path)
            self.validate_record(record, path.name)
            if record['phase'] in ('prepared', 'switched', 'rollback_failed'):
                self.spec(record['cert_id'])
                self.emit('recovering', cert=record['cert_id'], transaction=record['id'])
                # Conservative recovery: restore the known previous pair for
                # every uncommitted transaction, then allow a fresh reconcile.
                self.restore(record)
            if record['phase'] in ('committed', 'rolled_back'):
                for field in ('work_dir', 'restore_work_dir'):
                    if record.get(field):
                        clean = dict(record, work_dir=record[field])
                        self.cleanup_work(clean)

    def publish(self, ident, cert, key, manual=False):
        self.validate_config()
        supported_exchange()
        spec = self.spec(ident)
        candidate_info = validate_pair(cert, key, spec['names'], 0 if manual else 86400)
        self.backups.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.work.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.nginx_test()
        # The same pair-only guard protects normal publication and recovery:
        # exchanged directories are later removed from the work area.
        previous = self.live_pair_digest(ident)
        group = safe_path(self.group(ident))
        old = validate_pair(group / 'fullchain.pem', group / 'privkey.pem',
                            spec['names'], check_time=False)
        old_pair = previous
        if old['fingerprint'] == candidate_info['fingerprint']:
            self.verify(ident, old['fingerprint'])
            return 'unchanged'
        if not manual and candidate_info['expires'] <= old['expires']:
            raise Failure('Refusing a candidate without a later expiry')
        backup = self.backup_pair(ident, group / 'fullchain.pem', group / 'privkey.pem')
        job = self.new_work(ident, cert, key)
        staged = validate_pair(job / 'candidate' / 'fullchain.pem', job / 'candidate' / 'privkey.pem',
                               spec['names'], 0 if manual else 86400)
        if staged['fingerprint'] != candidate_info['fingerprint'] or pair_digest(group) != old_pair:
            raise Failure('Certificate changed during publication preparation')
        record = {'layout_version': 2,
                  'id': datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex[:8],
                  'cert_id': ident, 'previous_backup': str(backup), 'work_dir': str(job),
                  'previous_pair': old_pair, 'candidate_pair': pair_digest(job / 'candidate'),
                  'previous_fingerprint': old['fingerprint'],
                  'candidate_fingerprint': candidate_info['fingerprint'], 'phase': 'prepared'}
        self.journal(record)
        try:
            exchange_directories(job / 'candidate', group)
            record['phase'] = 'switched'
            self.journal(record)
            self.reload()
            self.verify(ident, candidate_info['fingerprint'])
            record['phase'] = 'committed'
            self.journal(record)
        except Exception as exc:
            record['error'] = str(exc)
            self.journal(record)
            self.restore(record)
            raise Failure('Publication failed and was rolled back: ' + str(exc))
        self.emit('deployed', cert=ident, fingerprint=candidate_info['fingerprint'], transaction=record['id'])
        self.cleanup_work(record)
        return 'deployed'

    def configure(self, ids):
        self.validate_config()
        self.nginx_test()
        for ident in ids:
            self.spec(ident)
            meta = self.acme_metadata(ident)
            # install-cert immediately copies material. Never run it while an
            # earlier install target or reload hook still points at live files.
            expected = {'Le_RealFullChainPath': str(self.stage(ident) / 'fullchain.pem'),
                        'Le_RealKeyPath': str(self.stage(ident) / 'privkey.pem')}
            for field in ('Le_RealFullChainPath', 'Le_RealKeyPath', 'Le_RealCertPath',
                          'Le_RealCACertPath', 'Le_ReloadCmd'):
                if meta.get(field, '') not in ('', 'no', expected.get(field)):
                    raise Failure('Unsafe existing ACME install target/hook; review it before configure')
            stage = self.validate_stage_targets(ident)
            stage.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.acme_run([self.acme / 'acme.sh', '--install-cert', '-d', ident,
                           '--fullchain-file', stage / 'fullchain.pem',
                           '--key-file', stage / 'privkey.pem', '--reloadcmd', ''],
                          ident, 'configure', timeout=60)
            self.check_staging_owner(ident)
            self.emit('staging_configured', cert=ident)

    def acme_run(self, args, ident, action, timeout=600):
        """ACME output is intentionally discarded: DNS plugins may print secrets.

        Persist only exit status and operation metadata, with mode 0600.
        Administrators can diagnose acme.sh separately in their trusted session.
        """
        self.validate_stage_targets(ident)
        logdir = safe_path(self.log_root / 'ssl-renew')
        logdir.mkdir(parents=True, exist_ok=True, mode=0o700)
        log = logdir / (self.now().strftime('%Y-%m-%d_%H-%M-%S') + '__' + action + '-' + ident + '__' + uuid.uuid4().hex[:8] + '.log')
        regular_file(self.acme / 'acme.sh')
        try:
            # The executable's location alone does not select acme.sh's state
            # directory. Bind --home to the same registration we just inspected.
            argv = [str(a) for a in args] + ['--home', str(self.acme)]
            proc = subprocess.run(argv, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, timeout=timeout)
            rc = proc.returncode
        except subprocess.SubprocessError:
            rc = -1
        atomic_json(log, {'time': self.now().isoformat(), 'timezone': self.timezone_name,
                          'cert_id': ident, 'operation': action, 'exit_code': rc,
                          'external_output': 'withheld'})
        if rc not in (0, 2):
            raise Failure('ACME operation failed (exit {}); metadata: {}'.format(rc, log))
        return rc

    def renew_acme(self, ident, force=False):
        self.check_staging_owner(ident)
        args = [str(self.acme / 'acme.sh'), '--renew', '-d', ident, '--keylength', '2048']
        if force:
            args.append('--force')
        rc = self.acme_run(args, ident, 'reissue' if force else 'renew')
        self.check_staging_owner(ident)
        self.emit('acme_skipped' if rc == 2 else 'acme_renewed', cert=ident)

    def reconcile_one(self, ident, force=False):
        spec = self.spec(ident)
        meta = self.check_staging_owner(ident)
        live = validate_pair(spec['certificate'], spec['private_key'], spec['names'], check_time=False)
        cert, key = self.stage(ident) / 'fullchain.pem', self.stage(ident) / 'privkey.pem'
        candidate_error = None
        try:
            candidate = validate_pair(cert, key, spec['names'])
        except Exception as exc:
            candidate = None
            candidate_error = str(exc)
        # Deploy an already-issued newer certificate BEFORE consulting renewal time.
        result = 'unchanged'
        if (candidate and candidate['fingerprint'] != live['fingerprint']
                and candidate['expires'] > live['expires']):
            result = self.publish(ident, cert, key)
            live = cert_info(spec['certificate'])
        due = time.time() >= int(meta.get('Le_NextRenewTime') or 0)
        near_expiry = live['expires'] - time.time() < self.config.get('renew_before_days', 30) * 86400
        reissue_no_replacement = False
        if force or due or near_expiry:
            self.renew_acme(ident, force)
            candidate = validate_pair(cert, key, spec['names'])
            if (candidate['fingerprint'] != live['fingerprint']
                    and candidate['expires'] > live['expires']):
                result = self.publish(ident, cert, key)
                live = cert_info(spec['certificate'])
            elif force:
                reissue_no_replacement = True
        elif candidate_error:
            raise Failure('Invalid staging candidate: ' + candidate_error)
        self.verify(ident, live['fingerprint'])
        if live['expires'] - time.time() < 7 * 86400:
            raise Failure('Live certificate has less than seven days remaining; ACME did not repair it')
        if reissue_no_replacement:
            raise Failure('Explicit reissue produced no replacement with a new fingerprint and later expiry; live certificate retained')
        self.emit('verified', cert=ident, result=result,
                  expires_utc=utc_iso(live['expires']))
        return result

    def status(self, ids, plan=False):
        rows = []
        for ident in ids:
            spec = self.spec(ident)
            row = {'cert': ident, 'names': spec['names'], 'ports': spec.get('ports', [443]),
                   'certificate': spec['certificate'], 'layout': 'rsa_domain_directory'}
            try:
                if not self.group(ident).exists():
                    row.update(action='enroll', state='pending', auto_renew=False)
                    if not plan:
                        row['error'] = 'No live certificate pair; enroll before configuring a site'
                    rows.append(row)
                    continue
                pair_digest(self.group(ident))
                live = validate_pair(spec['certificate'], spec['private_key'], spec['names'],
                                     min_seconds=0, check_time=False)
                stage = self.stage(ident) / 'fullchain.pem'
                candidate = cert_info(stage) if stage.exists() else None
                meta = self.check_staging_owner(ident)
                row.update(expires_utc=utc_iso(live['expires']),
                           auto_renew=True, fingerprint=live['fingerprint'],
                           renewal_due=time.time() >= int(meta.get('Le_NextRenewTime') or 0),
                           action='deploy' if (candidate and candidate['fingerprint'] != live['fingerprint']
                                               and candidate['expires'] > live['expires']) else 'check_renewal')
                if not plan:
                    self.verify(ident, live['fingerprint'], strict=False, attempts=1)
                    row['origin_fingerprint'] = 'matches_live'
                    self.verify(ident, live['fingerprint'], attempts=1)
                    row['origin_tls'] = 'verified'
            except Exception as exc:
                row['error'] = str(exc)
            rows.append(row)
        print(json.dumps(rows, indent=2))
        return 1 if any('error' in row for row in rows) else 0

    def enroll(self, ident, sans, dry_run=False):
        """Provision certificate material only; never create application routes."""
        names = list(dict.fromkeys([ident] + sans))
        registered = ident in self.certs
        if registered:
            spec = self.spec(ident)
            if sans and names != spec['names']:
                raise Failure('Changing SANs requires an explicit registry review')
            # --san need not be repeated when completing an existing registry
            # entry; preserve its configured names, ports and all other fields.
            names = spec['names']
            target = safe_path(self.group(ident))
            if target.exists():
                if not target.is_dir() or set(p.name for p in target.iterdir()) != {'fullchain.pem', 'privkey.pem'}:
                    raise Failure('Existing live group is incomplete or contains extra files; review it before enrollment')
                pair_digest(target)
                if dry_run:
                    return self.status([ident], plan=True)
                self.reconcile_one(ident)
                return 0
        else:
            if not valid_name(ident):
                raise Failure('Invalid certificate id; wildcards are unsupported')
            for name in names:
                if not valid_name(name):
                    raise Failure('Invalid SAN; wildcards are unsupported')
                if any(name in spec['names'] for spec in self.certs.values()):
                    raise Failure('DNS name is already owned by another certificate group')
            spec = {'names': names, 'certificate': str(self.group(ident) / 'fullchain.pem'),
                    'private_key': str(self.group(ident) / 'privkey.pem')}
            if safe_path(self.group(ident)).exists():
                raise Failure('Existing live directories must be explicitly registered before enrollment')
        if dry_run:
            self.emit('plan_enroll', cert=ident, names=names, action='issue_and_provision_only')
            return 0
        if (self.acme / (ident + '_ecc')).exists():
            raise Failure('ECC acme.sh layout is unsupported; use RSA 2048')
        if self.acme_conf(ident).exists():
            self.acme_metadata(ident, names)
        else:
            args = [str(self.acme / 'acme.sh'), '--issue', '--dns', self.config['dns_provider'], '--keylength', '2048']
            for name in names:
                args += ['-d', name]
            self.acme_run(args, ident, 'enroll')
            self.acme_metadata(ident, names)
        # A failed provision remains visibly pending and can be retried.
        if not registered:
            self.certs[ident] = spec
            self.validate_config()
            atomic_json(self.config_path, self.config)
        return self.provision(ident)

    def provision(self, ident):
        spec = self.spec(ident)
        self.configure([ident])
        cert, key = self.stage(ident) / 'fullchain.pem', self.stage(ident) / 'privkey.pem'
        validate_pair(cert, key, spec['names'])
        target = safe_path(self.group(ident))
        if target.exists() or target.is_symlink():
            if pair_digest(target) != pair_digest(self.stage(ident)):
                raise Failure('Refusing to replace existing files during provisioning')
        else:
            job = self.new_work(ident, cert, key)
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.parent.stat().st_dev != job.stat().st_dev:
                raise Failure('Provisioning requires one filesystem')
            os.rename(str(job / 'candidate'), str(target))
            sync_dir(target.parent)
            shutil.rmtree(str(job))
        self.emit('provisioned', cert=ident, action='configure_site_then_reconcile',
                  certificate=spec['certificate'], private_key=spec['private_key'])
        return 0

    def rollback(self, transaction):
        if not re.fullmatch(r'[A-Za-z0-9-]+', transaction):
            raise Failure('Invalid transaction id')
        record = read_json(self.home / 'state' / 'transactions' / (transaction + '.json'))
        self.validate_record(record, transaction + '.json')
        if record['phase'] != 'committed':
            raise Failure('Only a committed transaction can be explicitly rolled back')
        ident = record['cert_id']
        if record.get('layout_version') != 2:
            raise Failure('Legacy transaction requires migration before rollback')
        if pair_digest(self.group(ident)) != record['candidate_pair']:
            raise Failure('Current pair is not the transaction candidate; refusing stale rollback')
        old = self.backup_material(record)
        return self.publish(ident, old / 'fullchain.pem', old / 'privkey.pem', manual=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['status', 'plan', 'configure', 'reconcile', 'enroll', 'reissue', 'rollback'])
    parser.add_argument('--config', required=True, help='explicit administrator-owned JSON configuration')
    parser.add_argument('--cert', '--domain', dest='cert')
    parser.add_argument('--force', action='store_true', help='accepted only with the explicit reissue command')
    parser.add_argument('--dry-run', action='store_true', help='local reads only: no CA, network or filesystem changes')
    parser.add_argument('--transaction')
    parser.add_argument('--san', action='append', default=[])
    args = parser.parse_args(argv)
    if args.force and args.command != 'reissue':
        parser.error('--force is allowed only with reissue; scheduled reconciliation must never force')
    if args.command in ('enroll', 'reissue') and not args.cert:
        parser.error(args.command + ' requires --cert')
    if args.command == 'rollback' and not args.transaction:
        parser.error('rollback requires --transaction')
    if args.san and args.command != 'enroll':
        parser.error('--san is allowed only with enroll')
    manager = Manager(args.config)
    readonly = args.command in ('status', 'plan') or args.dry_run
    if not readonly:
        supported_exchange()
    with operation_lock(manager.lock_file, readonly):
        # Re-read under the lock so an earlier enroll cannot leave stale registry
        # data in a process which was waiting to acquire its lock.
        locked_manager = Manager(args.config)
        if locked_manager.lock_file != manager.lock_file:
            raise Failure('Lock configuration changed; retry using the current configuration')
        manager = locked_manager
        ids = [args.cert] if args.cert else sorted(manager.certs)
        if args.command != 'enroll':
            for ident in ids:
                manager.spec(ident)
        if args.command == 'enroll' and readonly:
            return manager.enroll(args.cert, args.san, dry_run=True)
        if readonly:
            if args.command == 'rollback':
                if not re.fullmatch(r'[A-Za-z0-9-]+', args.transaction):
                    raise Failure('Invalid transaction id')
                record = read_json(manager.home / 'state' / 'transactions' / (args.transaction + '.json'))
                manager.validate_record(record, args.transaction + '.json')
                manager.backup_material(record)
                manager.emit('plan_rollback', transaction=args.transaction, cert=record['cert_id'])
                return 0
            return manager.status(ids, plan=args.command != 'status' or args.dry_run)
        manager.recover()
        if args.command == 'enroll':
            return manager.enroll(args.cert, args.san)
        if args.command == 'configure':
            manager.configure(ids)
            return 0
        if args.command == 'rollback':
            manager.rollback(args.transaction)
            return 0
        results = {}
        for ident in ids:
            try:
                results[ident] = {'result': manager.reconcile_one(ident, force=args.command == 'reissue')}
            except Exception as exc:
                results[ident] = {'error': str(exc)}
                manager.emit('failed', cert=ident, error=str(exc))
                if 'ROLLBACK FAILED' in str(exc):
                    break
        atomic_json(manager.home / 'state' / 'status.json',
                    {'time_utc': utc_iso(), 'certificates': results})
        return 2 if any('error' in row for row in results.values()) else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Failure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        # JSON decoding/invalid config errors may embed secret source text.
        if isinstance(exc, (KeyError, TypeError, ValueError)):
            print('ssl-manage: invalid configuration or state data', file=sys.stderr)
        else:
            print('ssl-manage: ' + str(exc), file=sys.stderr)
        sys.exit(2)
