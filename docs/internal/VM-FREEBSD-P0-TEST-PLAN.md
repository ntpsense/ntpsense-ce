# NTPSense CE — FreeBSD-Build P0 Validation Plan

## Purpose
Internal runtime validation plan for the `security-hardening-p0` branch. Run on the dedicated FreeBSD-Build VM only after the branch is declared VM TEST CHECKPOINT.

## Test environment
- FreeBSD version: `freebsd-version -ku`
- Kernel: `uname -a`
- Architecture: `uname -m`
- Rust: `rustc --version`
- Cargo: `cargo --version`
- PHP: `php -v`
- OpenSSL: `openssl version`
- Git commit under test: `git rev-parse HEAD`

## A. Static/source checks
Run from repository root:

    php -l webui/lib/Auth.php
    php -l webui/public/login.php
    php -l webui/public/change-password.php
    sh -n install-gateway-2eth-v2.sh
    cargo fmt -- --check
    cargo check

Expected: all commands exit 0.

## B. SEC-01 CSRF/session
1. Start Web UI normally over HTTPS.
2. Login normally.
3. Inspect the session cookie.
4. Confirm `Secure`, `HttpOnly`, and `SameSite=Strict`.
5. Submit a legitimate POST form with its CSRF field.
6. Remove/change `_csrf` and submit again.
7. Expected: HTTP 403 and no state change.
8. Repeat against firewall, system, user/password, network, and VPN mutations.

## C. SEC-02 bootstrap credential
Fresh install only:
1. Verify no static `admin/admin` credential is documented by installer output.
2. Verify generated bootstrap credential exists at `/usr/local/etc/ntpsense/webui/.bootstrap-credential`.
3. Check `stat -f '%Sp %Su:%Sg %N' /usr/local/etc/ntpsense/webui/.bootstrap-credential`.
4. Expected: mode 0600 and restricted ownership.
5. Verify `webui-admin.json` contains a password hash, not plaintext.
6. Login with generated bootstrap credential.
7. Confirm mandatory password change.
8. Set a new password.
9. Verify bootstrap credential file is deleted.
10. Verify old bootstrap credential no longer works.
11. Verify OS administrator credential is independent.

## D. SEC-03 concurrency
Do not mark PASS until transaction locking is implemented.
Test concurrent password/role/lockout mutations and verify no lost update, valid JSON, no truncation, no credential rollback, and consistent lockout counters.

## E. SEC-04 temporary files
Do not mark PASS until private temporary storage is implemented.
During representative operations check `/tmp` for legacy predictable artifacts. Expected after cleanup: none. Verify the daemon temporary directory is private/root-only and files are unique per operation.

## F. Regression operations
Run firewall config validation/apply, certificate regenerate/upload, backup create/restore, OpenVPN operations, Multi-WAN mutation, VLAN/LAGG mutation, and Squid/proxy mutation.
For each operation record action, timestamp, result, relevant logs, temporary files, and final state.

## G. Evidence bundle
Save outputs under `~/ntpsense-p0-evidence` and never include real passwords, private keys, API tokens, or backup secrets.

## PASS criteria
A P0 item is PASS only when source/static checks, FreeBSD runtime behavior, negative/security tests, regression testing, and reproducible evidence all pass. PASS must not be inferred from Linux/static testing alone.