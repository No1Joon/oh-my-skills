# PHP2Shell — CVE-2026-109618 / CVE-2026-109619

> **Snapshot as of 2026-10-24.** Re-verify against the PHP security advisories (php.net news archive, `github.com/php/php-src/security/advisories`) and CISA KEV before acting.

## What it is

Two memory-safety flaws (CWE-416) in the PHP engine, both triggered when a request ends abnormally. CVSS v4.0 9.2 each.

- **CVE-2026-109618**: out-of-memory handling via `longjmp()` leaves request memory in an invalid state → RCE as the web worker.
- **CVE-2026-109619**: fatal-error handling via `longjmp()` leaves globals pointing to freed memory → unauthenticated heap use-after-free, process memory disclosure, RCE.

## Scope

- Every PHP installation that serves web requests: PHP-FPM, Apache mod_php, php-cgi, FrankenPHP, LiteSpeed.
- Branches back to 5.4 are affected by at least one of the two.
- **mod_php is highest risk**: a demonstrated unauthenticated trigger fires before any application code runs.
- Secure application code does not help, and updating the CMS or plugins does not replace a vulnerable runtime.

## Fixed releases

- **8.5.12, 8.4.27, 8.3.36, 8.2.35** (released 2026-10-21).
- **EOL branches (≤ 8.1)**: the PHP team published minimal source backports for 7.4, 8.0 and 8.1 for people building from source, but at least one major vendor states there is no fix for CVE-2026-109618 on EOL branches. Treat EOL runtimes as **unfixed** unless an LTS vendor explicitly confirms both CVEs, and start migration immediately.

## Exploitation

Attempts observed from **2026-10-17**, before disclosure; broad scanning since. Use 2026-10-17 (or earlier, if logs show it) as the start of the exposure window.

## Triage steps

1. **Inventory every PHP runtime**, internet-facing first: VMs, containers and their base images, managed/shared hosting, control panels with multiple PHP versions, appliances and vendor products that bundle PHP, internal tools.
2. **Identify the web SAPI version, not just the CLI.**
   - FPM: `php-fpm -v` (or the versioned binary, e.g. `php-fpm8.3 -v`)
   - Apache mod_php: `apachectl -M | grep -i php`, then check the loaded `libphp*.so` package version
   - Containers: inspect the image actually running (`docker inspect` digest), then check PHP inside it
   - cPanel/CloudLinux alt-php, Plesk, DirectAdmin, BT Panel: list every installed PHP version and which sites use each
3. **Confirm distro backports via changelog**, not version string:
   - Debian/Ubuntu (offline, check this first — it reflects what is actually installed): `zgrep -E 'CVE-2026-10961[89]' /usr/share/doc/php8.3-*/changelog.Debian.gz`
   - Debian/Ubuntu (online; fails without network access to the changelog server): `apt changelog php8.3-fpm | grep -E 'CVE-2026-10961[89]'`
   - RHEL/Alma/Rocky/Amazon Linux: `rpm -q --changelog php-fpm | grep -E 'CVE-2026-10961[89]'`
   - Third-party repos (sury.org, Remi): check the repo's release notes
4. **Patch, then restart every worker.** Use a full restart, not a graceful reload, so no old worker survives. For mod_php, restart Apache. For containers, rebuild from a patched base image and redeploy; do not patch running containers in place.
5. **Verify on the running process.** Re-check the SAPI version or changelog, and confirm no worker predates the restart:
   ```bash
   ps -eo pid,lstart,args | grep -E '[p]hp-fpm|[a]pache2|[h]ttpd'
   ```
   Do **not** use `ps -C php-fpm`: `-C` matches the exact process name, and Debian/Ubuntu run the versioned binary `php-fpm8.3`, so it returns nothing and falsely looks like "no old workers".
6. **Run `incident-response.md`** on every host that was exposed and unpatched at any point since the window start. Patching does not remove a backdoor that is already there.

## If patching must wait (partial — never report as fixed)

Apply where the application cannot override it, then **restart every worker**.

PHP-FPM pool:
```ini
; CVE-2026-109618 (OOM path)
php_admin_value[memory_limit] = -1            ; MUST pair with a container/cgroup memory limit as the availability boundary
php_admin_value[post_max_size] = 8M           ; 32M if the app needs uploads
; CVE-2026-109619 (stale global state)
php_admin_flag[session.upload_progress.enabled] = off
php_admin_flag[fatal_error_backtraces] = off  ; PHP 8.5 only; blocks only the confirmed backtrace path
```

Apache mod_php equivalents: `php_admin_value memory_limit -1`, `php_admin_value post_max_size 8M`, `php_admin_flag session.upload_progress.enabled off`.

Also:
- Remove invalid or deprecated per-request ini settings that emit diagnostics before initialization. Hiding diagnostics with `error_reporting`, `display_errors` or `@` does **not** help.
- Fix attacker-reachable fatal errors and execution timeouts, including failures inside callbacks, upload/import processing and cleanup (SKILL.md §5, "Fatal-error resilience").
- Edge controls are stopgaps: enable managed WAF rules in **block** mode (e.g. Cloudflare managed rulesets; AWS WAF CRS `SizeRestrictions_BODY` for the 8 KB body limit). Attackers are already mutating payloads.
- If none of the above is possible on an internet-facing host, recommend restricting access (VPN / IP allowlist) or taking it offline until patched, in line with national CERT guidance (NCSC UK, CERT-EU, FBI/NSA).

## Hosting-specific notes

- **AWS Lightsail**: running instances cannot be updated in place; launch from the updated blueprint and migrate.
- **AWS Elastic Beanstalk**: apply the new platform version if Managed Platform Updates is off.
- **Shared hosting** (any region, see `platforms-by-region.md`): the user usually cannot patch PHP; check the provider's status page, switch the site to a patched PHP version in the panel, and ask the provider to confirm both CVEs.

## Hunting notes

No vendor-confirmed IOCs as of this snapshot. Rely on behavioral hunting in `incident-response.md`, and treat a clean result as "nothing found", not "not compromised".
