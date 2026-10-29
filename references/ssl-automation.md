# Automated certificate issuance, renewal and reissue

[English](ssl-automation.md) | [简体中文](ssl-automation.zh-CN.md)

`scripts/ssl_manage.py` is a configurable reference implementation adapted from an existing server workflow. It coordinates an installed `acme.sh` client with certificate validation, versioned backups, Nginx checks, graceful reloads, origin TLS verification and recovery records.

## Supported setup

- Linux with same-filesystem atomic directory exchange (`renameat2` on x86-64 or AArch64).
- Python 3.6+ standard library, OpenSSL 1.1.1+ (with `verify -no_check_time`) and an already configured `acme.sh` installation.
- RSA 2048 certificate groups. ECC account-directory layouts, other key sizes and wildcard enrollment are outside this implementation.
- Native or Docker Nginx, selected through administrator-owned argument arrays. No commands are run through a shell.
- One live directory per certificate group. The mounted certificate root remains in place; publication exchanges a group directory inside it.

This script does not install ACME clients, create DNS credentials, edit application routes or migrate an existing certificate layout automatically. Retain a working certificate system if it already provides these guarantees.

## Layout

```text
/srv/
├── nginx/
│   ├── cert/example.com/
│   │   ├── fullchain.pem
│   │   └── privkey.pem
│   └── ssl/
│       ├── staging/example.com/
│       └── state/transactions/
├── nginx-logs/ssl-renew/
├── nginx-backups/cert/example.com/
│   └── YYYY-MM-DD_HH-MM-SS__cert/
│       ├── payload/
│       ├── manifest.json
│       └── SHA256SUMS
└── nginx-work/ssl/
```

Paths are examples. Use canonical absolute paths without symlink components; for example, use `/run` instead of `/var/run` on systems where the latter is a symlink. Nginx, ACME, log, backup and work roots must not overlap. The lock file stays outside those roots and its parent must already exist. Publication requires work and live group directories on the same filesystem. The group must not itself be a Docker bind-mount root.

## Configure

Start from [certificates.example.json](../examples/ssl/certificates.example.json), adjust every path, domain, port and command to the inspected server, and save a restricted configuration such as `/etc/nginx-ops/certificates.json` with mode `0600`.

For native Nginx, replace the example Docker commands with administrator-selected commands such as:

```json
{
  "nginx_test_command": ["nginx", "-t"],
  "nginx_reload_command": ["systemctl", "reload", "nginx"]
}
```

The config and script are trusted administrative code. Do not let application users modify command arrays, certificate paths, backup paths or transaction records.

Use the DNS provider plugin supported by the installed ACME client. The example selects `dns_ali`; configure its credentials or supported workload identity outside this repository, following the provider documentation. The script does not choose a new CA or alter a client's global default CA.

Review the existing ACME group's hooks and install destinations before onboarding it. `configure` only accepts a safe staging/empty installation target and empty hooks; it refuses an existing live install destination or reload hook. Back up and explicitly remove or migrate conflicting client settings before running it. It does not silently take over another deployment chain.

## Inspect and plan

All commands require an explicit config file:

```bash
python3 scripts/ssl_manage.py --help
python3 scripts/ssl_manage.py plan --config /etc/nginx-ops/certificates.json
python3 scripts/ssl_manage.py status --config /etc/nginx-ops/certificates.json
```

`plan` reads local state; `status` also verifies the served origin certificate using SNI and the configured ports. Neither command issues or publishes certificates. They do not replace an authenticated application or payment test.

## Select the right action

| Situation | Action |
|---|---|
| A valid newer certificate is already in staging | `reconcile` publishes it before deciding whether renewal is due |
| A certificate is near expiry or ACME says renewal is due | `reconcile` attempts normal renewal, then validates and publishes |
| Staging has an older valid certificate | Keep the newer live pair; renew normally when due, or explicitly `reissue` |
| The CA must issue a replacement before the normal renewal date | Explicit `reissue`; never put this in a timer |
| A new group needs initial materials | Preview `enroll --dry-run`, then explicitly enroll and configure the site's certificate references |
| A live pair is missing, mismatched or changed outside the transaction | Inspect and restore/review the pair; do not blindly overwrite it |

### Onboard an existing ACME group

For the directory layout shown above, register the existing group and its SANs in the config first:

```bash
python3 scripts/ssl_manage.py configure \
  --config /etc/nginx-ops/certificates.json --cert example.com
```

This is a write operation that configures staging for an already reviewed ACME group. Back up the client configuration and certificate pair first. A group with an existing live destination or deployment hook must be explicitly migrated before this command can proceed.

### New certificate

```bash
python3 scripts/ssl_manage.py enroll \
  --config /etc/nginx-ops/certificates.json \
  --cert example.com --san www.example.com --dry-run

python3 scripts/ssl_manage.py enroll \
  --config /etc/nginx-ops/certificates.json \
  --cert example.com --san www.example.com
```

Enrollment provisions materials; it does not add `server_name`, routes or Nginx certificate directives. Configure those references and check the site before enabling scheduled reconciliation.

### Normal automatic renewal

```bash
python3 scripts/ssl_manage.py reconcile \
  --config /etc/nginx-ops/certificates.json
```

Adapt [renew.cron](../examples/ssl/renew.cron) to the server. Create the restricted log directory before enabling cron. Install one scheduler, not overlapping ACME auto-renew and wrapper jobs that can publish independently. The example runs four checks per day, not four forced CA issuances.

### Explicit early replacement

```bash
python3 scripts/ssl_manage.py reissue \
  --config /etc/nginx-ops/certificates.json --cert example.com
```

This requests a real CA reissue and can consume rate limits. It is separate from installing an already-issued certificate. If the client produces no replacement with a new fingerprint and later expiry, the command reports failure and retains the live certificate. There is no background default that forces reissuance.

## Publication and recovery

The manager uses a shared lock and records `prepared`, `switched` and `committed` phases. It validates SANs, validity, chain trust and key pairing; preserves the old pair in a checksummed backup; then exchanges the complete group, checks Nginx, reloads and verifies origin fingerprints.

Failures restore the previous pair and separately record whether it still provides valid TLS. An interrupted transaction is recovered before another write. Invalid backup hashes, unexpected live changes, unsupported exchange semantics or failed recovery stop publication.

An explicit rollback must reference a committed transaction that still matches the live candidate:

```bash
python3 scripts/ssl_manage.py rollback \
  --config /etc/nginx-ops/certificates.json --transaction TRANSACTION_ID
```

Keep transaction-linked certificate backups. Backing up the Nginx root alone may omit those backups and the external ACME account. A later reconcile may publish a newer valid staging candidate again; rollback is not a permanent renewal policy.

## Dates and logs

Backup folders and per-run logs use `YYYY-MM-DD_HH-MM-SS`, with an explicit offset and timezone label in manifests. The example uses `Asia/Shanghai` and `+08:00`; adapt both together. The implementation uses a fixed offset, not an IANA daylight-saving-time engine. Log files and backups containing key material stay restricted. Existing retention policy is preserved; this implementation does not automatically delete certificate history.

Continuous cron output needs its own log-rotation policy. Certificate automation does not mean all task logs are already rotated. Per-operation logs record metadata and exit codes; external ACME stdout/stderr is withheld because DNS plugins may print credentials. Diagnose the ACME client separately in an administrator-controlled session if needed.

## Local verification

```bash
python3 -m unittest discover -s tests -v
```

Tests use temporary directories and local fixtures/mocks. They do not issue certificates, connect to a production server or reload a real Nginx process. Review and test the implementation against the target operating system and installed ACME client before deployment.
