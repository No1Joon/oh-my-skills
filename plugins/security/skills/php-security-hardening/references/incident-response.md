# Compromise assessment and incident response

Run for any host that was exposed while vulnerable to a critical RCE. For an open advisory, the exposure window starts at the date in its file under `advisories/` (PHP2Shell: 2026-10-17).

## 1. Preserve evidence first

Before restarting or rebuilding, snapshot the disk or copy access, error, FPM and system logs covering the full window. Restarts and rebuilds destroy the evidence you need.

## 2. Hunt

When no vendor-confirmed IOCs exist, rely on behavior, and remember a clean result does not rule out compromise.

- **Worker crashes**: php-fpm `exited on signal 11 (SIGSEGV)`, Apache `Segmentation fault`, unexplained 500/502 spikes — possible memory-corruption attempts.
- **Web workers spawning tools**: `sh`, `bash`, `curl`, `wget`, `nc`, `python`, `perl`, `whoami`, `id`, `uname` as children of php-fpm/httpd/apache2 (auditd, EDR, process accounting).
- **New or modified PHP files** since window start, especially in writable dirs:
  ```bash
  find /var/www -type f -name '*.php' -newermt '2026-10-17'
  ```
- **Persistence beyond `.php`**: changed `.htaccess` or `.user.ini` (`auto_prepend_file`), new cron entries for the web user, `authorized_keys` changes, modified PHP-FPM pool configs.
- **Obfuscation chains**: `base64_decode` / `gzinflate` / `str_rot13` feeding `eval` or `assert`.
- **Traffic**: unusual large `multipart/form-data` POSTs to arbitrary endpoints; unexpected outbound connections from web workers.
- **Integrity vs vendor**: `wp core verify-checksums`, `wp plugin verify-checksums --all`, fresh `composer install` diff, `git status` on deploy dirs.

## 3. If compromise is suspected

1. Isolate the host.
2. Rebuild from known-good images rather than cleaning in place.
3. Rotate every secret the worker could read: DB credentials, `APP_KEY`/`APP_SECRET`, API and PG keys, cloud credentials, SMTP.
4. Invalidate sessions.
5. Review the database for injected admin accounts and content.

## 4. Notification

Flag applicable breach-notification duties for the user's jurisdiction (e.g. GDPR's 72-hour supervisory-authority notice) and recommend legal review. Do not give legal advice.
