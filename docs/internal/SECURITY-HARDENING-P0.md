# NTPSense CE — Internal Technical Security Hardening Record

> **Internal engineering document — not a public security advisory.**

## Baseline
- Repository: `ntpsense/ntpsense-ce`
- Baseline branch/commit: `main @ 8c29b67c14b300e30e906b65f8d9c988ba34b23b`
- Working branch: `security-hardening-p0`
- Target: FreeBSD gateway appliance
- Runtime validation: project-owned **FreeBSD-Build VM**

## P0 sequence
1. SEC-01 — CSRF + session hardening
2. SEC-02 — remove production hardcoded `admin/admin` OS bootstrap
3. SEC-03 — atomic credential/lockout persistence
4. SEC-04 — unpredictable privileged temporary files + transaction locking
5. Deep Security Audit Pass #2
6. FreeBSD regression/integration validation

## SEC-01 implementation
CSRF is centralized in `webui/lib/Auth.php`:
- per-session token from `random_bytes(32)`;
- stored in `$_SESSION['ntpsense_csrf_token']`;
- compared with `hash_equals()`;
- forms render `Auth::csrfField()`;
- POST requests are rejected by `Auth::requireCsrf()` when missing/invalid;
- rejected requests are audit logged.

Session initialization is centralized in `Auth::startSession()`:
- `session.use_strict_mode=1`;
- `HttpOnly`;
- `SameSite=Strict`;
- `Path=/`;
- `Secure` when HTTPS is detected.

The HTTPS-aware Secure behavior is intentional because initial appliance bootstrap may occur over HTTP; HTTPS-only production deployment remains a separate hardening requirement.

## Covered Web UI
`Auth.php`, `login.php`, `change-password.php`, `firewall.php`, `system.php`, `network.php`, `security.php`, `multiwan.php`, `proxy.php`, `openvpn.php`, `vpn.php`, `nat.php`, `ipsec.php`, `services.php`, `package-manager.php`, `system-logs.php`, and `traffic-data.php`.

## FreeBSD-Build verification
Run:
```sh
find webui -name '*.php' -print0 | xargs -0 -n1 php -l
cargo test --all-targets
cargo check
```

Runtime checks:
1. login page creates a session;
2. verify cookie flags;
3. POST without `_csrf` → HTTP 403;
4. invalid token → HTTP 403;
5. valid current token → normal flow;
6. authenticated config POST without token → HTTP 403;
7. token from another session → HTTP 403;
8. valid form → normal mutation;
9. verify rejected requests do not mutate configuration;
10. verify TOTP and mandatory password-change flows remain functional.

## Acceptance criteria
SEC-01 is complete only when every mutating POST has a valid session-bound CSRF token, invalid requests return 403 and generate an audit event, existing valid operations still work, and FreeBSD-Build validation passes.

## SEC-02 status — IMPLEMENTED
The installer no longer ships a static `admin/admin` credential.

Bootstrap flow:
1. generate a 32-character random alphanumeric credential on the gateway;
2. pass it to `Auth::ensureBootstrapped()` through `NTPSENSE_BOOTSTRAP_PASSWORD`;
3. store only the password hash in `webui-admin.json`;
4. keep the plaintext bootstrap credential in `/usr/local/etc/ntpsense/webui/.bootstrap-credential` with mode 0600;
5. remove the bootstrap credential automatically after the administrator changes the password;
6. do not synchronize the Web UI bootstrap credential into the privileged OS account.

The OS administrator password is provisioned separately. The installer no longer advertises or sets a shared `admin/admin` credential.

Static source checks currently find no `admin/admin` literal and no `DEFAULT_PASSWORD` constant in the repository.

### SEC-02 validation required
On FreeBSD-Build:
- verify bootstrap credential length/entropy;
- verify file mode/ownership;
- verify `webui-admin.json` contains only a password hash;
- verify first login succeeds with bootstrap credential;
- verify `must_change_password` is enforced;
- change the password;
- verify `.bootstrap-credential` is deleted;
- verify the old bootstrap credential no longer authenticates;
- verify OS administrator password is independent;
- reinstall/upgrade tests must confirm an existing credential file is never overwritten.

## SEC-03 next
Serialize and atomically persist `webui-admin.json` and `lockout.json`: exclusive lock → read/modify → private temp file → flush/sync where supported → atomic rename → unlock. Add concurrency tests.

## SEC-03 status — IMPLEMENTED; RUNTIME VALIDATION PENDING
Security-state persistence now has two layers:
1. atomic same-directory temporary-file replacement with mode restoration and `fsync()` where supported;
2. exclusive transaction locks covering credential and lockout read-modify-write operations.

Credential transactions use `webui-admin.json.lock`; lockout transactions use `lockout.json.lock`. The lock inode is separate from the JSON payload, so atomic replacement cannot invalidate the lock.

All identified `saveAll()` mutation boundaries are covered, including external-user provisioning, password changes/resets, user creation/role/delete operations, and TOTP/recovery-code state changes.

Runtime concurrency testing is still required before SEC-03 can be marked PASS.

## SEC-04 next
Inventory all predictable `/tmp` paths in the Rust daemon. Use exclusive random temp files/private staging directories and configuration transaction locking.

## Deep Audit Pass #2
Inventory:
```
PHP action
 -> NtpsenseConfigd request
 -> Rust action
 -> parameter validation
 -> privileged side effect
 -> authorization
 -> audit event
 -> rollback/failure behavior
```
Check authorization/IDOR, injection, traversal, symlink/TOCTOU, races, fail-open paths, service restart abuse, config overwrite, privilege escalation, backup/restore, resource exhaustion, and audit coverage.

## FreeBSD-Build policy
Keep known-good snapshots such as `baseline-main`, `p0-sec01-before`, and `p0-sec01-after`. Do not use production data for destructive tests.

## Current status
| Item | Status |
|---|---|
| Baseline frozen | DONE |
| P0 branch | DONE |
| Central CSRF/session mechanism | IMPLEMENTED |
| Web UI CSRF rollout | IMPLEMENTED — runtime validation pending |
| FreeBSD validation | PENDING |
| SEC-02 | NEXT |
| SEC-03 | IMPLEMENTED — FreeBSD concurrency validation pending |
| SEC-04 | PENDING |
| Deep Audit Pass #2 | PENDING |
