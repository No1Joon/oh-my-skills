---
name: php-security-hardening
description: Diagnose and patch PHP vulnerabilities across code, runtime and server config, with region-specific platform playbooks and emergency response for runtime flaws like PHP2Shell.
---

# PHP Security Hardening

Find and fix security weaknesses in PHP applications and the runtime they run on, for systems the user **owns or administers**. Covers emergency triage for runtime-level CVEs, full code audits, platform-specific hardening for major PHP stacks worldwide, and post-compromise assessment.

Respond to the user in their own language; this skill is written in English for portability.

## References

Load only what the current step needs.

| File | Load when |
|---|---|
| `references/advisories/*.md` | Always check the index in §2; load the matching file when its advisory is open |
| `references/grep-patterns.md` | Step 5 code-level checks — copy-paste-ready ripgrep patterns (the §5 table is conceptual only) |
| `references/platforms-by-region.md` | Step 4 of a full audit, or the user names a specific platform or country |
| `references/incident-response.md` | Mode C, or any host was exposed while vulnerable to a critical RCE |

## 0. Ground rules

- **Defensive only.** Never write exploit PoCs, payloads, or step-by-step reproduction of an exploit chain, including "to test whether we're vulnerable". Describe flaws as *where / why / how to fix*.
- **Active scanning only on the user's own systems.** If asked to scan a third-party site, decline and offer a self-audit workflow instead.
- **Look up versions live.** Supported branches, CVEs and fixed versions change weekly. Use php.net and vendor advisories at run time. Advisory files under `references/advisories/` are dated snapshots and must be re-verified before acting on them.
- **A version string is not proof.** Distros backport fixes without changing the upstream version; the CLI binary can differ from the web SAPI. Confirm with changelogs and the running process.
- **Back up and stage first.** Show diffs before changing anything. Do not edit production directly without explicit approval.
- **Never report a partial mitigation as "fixed".** Label workarounds as reducing exposure only.

## 1. Pick a mode

| Mode | Trigger | Path |
|---|---|---|
| A. Emergency triage | An advisory in §2 is open, "are we vulnerable to X", fleet-wide patching | §2 → advisory file → `incident-response.md` |
| B. Full audit | Code review, hardening, pre-launch check, periodic audit | §3 → §7, then §8–§9 |
| C. Incident response | Signs of compromise, unexplained files/processes, defacement | `incident-response.md` |

While any §2 advisory is open, run its quick runtime check at the start of **every** mode. An unpatched runtime under an active emergency outranks every code finding.

## 2. Active emergency advisories

| Advisory | CVEs | Snapshot | Status | File |
|---|---|---|---|---|
| PHP2Shell | CVE-2026-109618, CVE-2026-109619 | 2026-10-24 | Open | `references/advisories/php2shell.md` |

Maintenance:
- Before acting on a snapshot, re-check php.net news and `github.com/php/php-src/security/advisories` for newer releases, regressions and CISA KEV status.
- Add a new runtime-level emergency as a new file in `references/advisories/` and a row here.
- Mark a row `Closed` once the user's fleet is patched and the advisory is more than 90 days old.

## 3. Stack fingerprinting

| Signature | Platform |
|---|---|
| `wp-config.php`, `wp-includes/version.php` | WordPress |
| `artisan`, `laravel/framework` in `composer.json` | Laravel |
| `bin/console`, `symfony/*` | Symfony |
| `core/lib/Drupal.php` | Drupal |
| `common.php` + `bbs/`, `adm/`, `data/` | Gnuboard 5 / Youngcart (KR) |
| `rhymix` in `common/constants.php`, or `modules/` + `classes/` layout | Rhymix / XpressEngine (KR) |
| `src/Eccube/`, `ECCUBE_*` in `.env` | EC-CUBE (JP) |
| `thinkphp/` or `topthink/framework` | ThinkPHP (CN) |
| `source/class/discuz/`, `uc_server/` | Discuz! (CN) |
| `bitrix/modules/main/` | 1C-Bitrix (RU) |
| `typo3conf/` or `config/system/settings.php` | TYPO3 (DE) |
| `classes/PrestaShopAutoload.php` | PrestaShop (FR) |
| `app/etc/env.php` | Magento / Adobe Commerce |

Also record: runtime version **per SAPI**, web server, process model (mod_php vs FPM), hosting type (shared / VPS / container / PaaS), control panel, and installed plugins/modules/extensions with versions.

## 4. Known-vulnerability lookup

- **Runtime**: php.net supported-versions page, php.net news archive, `github.com/php/php-src/security/advisories`.
- **Composer**: `composer audit --locked`; flag abandoned packages; verify `composer.lock` is committed and matches what is deployed.
- **Platform, plugins, modules**: advisory sources in `references/platforms-by-region.md`.
- **National CERT feeds** (use the one matching the user's jurisdiction, plus CISA KEV):

| Region | Feed |
|---|---|
| Korea | KISA / KrCERT (boho.or.kr) |
| Japan | JPCERT/CC, JVN |
| China | CNVD, CNNVD |
| EU | CERT-EU, ENISA EUVD |
| Germany | BSI / CERT-Bund |
| France | CERT-FR (ANSSI) |
| UK | NCSC |
| US | CISA KEV catalog |
| Australia | ACSC |
| Canada | Canadian Centre for Cyber Security |
| Russia | BDU FSTEC |

Record each finding as `ID · affected range · installed · fixed in · KEV yes/no · source`.

## 5. Code-level checks

Search custom code first (themes, in-house plugins, controllers). Fix vendor core by updating, not by patching it.

> **Patterns:** the table below is conceptual (what each class looks like and how to fix it). For the actual commands, load `references/grep-patterns.md` — those regexes are in code blocks so they paste into `rg` without the pipe/`$` escaping a Markdown table forces. Do **not** retype a regex from this table; it would be Markdown-escaped and match nothing.

| Class | What it looks like | Fix |
|---|---|---|
| SQL injection | A `->query` / `mysqli_query` / `sql_query` call built with string concatenation or an interpolated request variable | Prepared statements (PDO/mysqli), query-builder bindings; for Gnuboard wrap queries with bound params or cast integers |
| XSS | A request value echoed directly, or template auto-escape turned off (Blade `{!!`, Twig raw filter, Smarty `nofilter`) | Context-aware escaping (`htmlspecialchars($v, ENT_QUOTES, 'UTF-8')`), keep template auto-escape on, add CSP |
| Command execution | `system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open`, or backticks | Remove; else allowlist + `escapeshellarg` |
| Code execution | `eval`, `assert` on a string, `create_function`, or `preg_replace` with the `/e` modifier | Remove; replace dynamic logic with lookup maps |
| File inclusion | `include` / `require` with a variable path | Allowlist map, never user paths; `allow_url_include=Off` |
| File upload | `move_uploaded_file`, `$_FILES` handling | Extension allowlist + server-side MIME check, random filenames, store outside webroot or block PHP execution in upload dirs |
| Deserialization | `unserialize` on user input; a `phar://` path reachable via file functions | `json_decode`; else `['allowed_classes' => false]`; reject `phar://` and other wrappers in user paths |
| SSRF | `file_get_contents`, `fopen`, or a cURL URL built from input | Host allowlist, block private/link-local ranges after DNS resolution, don't follow redirects blindly |
| Path traversal | `fopen`, `file_put_contents`, `unlink`, `readfile` with request input | `realpath` then enforce base-directory prefix |
| Variable pollution | `extract($_...)`, variable variables, one-argument `parse_str` | Remove; assign explicitly |
| Type juggling | `==` on hashes/tokens, `strcmp` used for auth | `hash_equals`, `===` |
| Weak crypto/randomness | `md5`/`sha1` for passwords, `rand`/`mt_rand`/`uniqid` for tokens | `password_hash`/`password_verify`, `random_bytes`/`random_int` |
| CSRF | State-changing POST without token check | Framework CSRF middleware; Gnuboard `get_token()`/`check_token()` family |
| Broken access control / IDOR | Record fetched by ID from request without owner/role check | Enforce authorization on every object access (policies/voters/middleware) |
| Mass assignment | `Model::create($request->all())`, `$guarded = []` | Explicit `$fillable` / DTOs |
| Session | No `session_regenerate_id(true)` on login/privilege change | Regenerate; strict cookie flags (§7) |
| Header/mail injection | `header()` / `mail()` built with request input | Strip CR/LF; use a mail library |
| SSTI | User-controlled Twig/Smarty/Blade template strings | Never compile user input as templates; sandbox if unavoidable |
| Open redirect | `header('Location: ' . $_GET[...])` | Allowlist or relative-path-only redirects |
| Information exposure | `phpinfo(`, `var_dump(`, debug toolbars, `.env`/`.git` in webroot | Remove; move secrets out of webroot; block at web server |
| Payment tampering | PG return/callback trusting client-sent amount | Compare order total in DB with PG-approved amount server-side; verify webhook signature; idempotent approval |
| **Fatal-error resilience** | Uncaught errors / timeouts in callbacks, upload and import handlers, shutdown/cleanup code; deprecated per-request `ini_set` | Catch and handle errors, bound input sizes, avoid attacker-controlled memory blowups. Reduces the PHP2Shell CVE-2026-109619 attack surface and DoS risk generally |

Recommended tooling: `phpstan`/`psalm` (taint analysis), `semgrep --config p/php`, and for WordPress `wp core verify-checksums` / `wp plugin verify-checksums --all` plus WPScan on the user's own site only.

## 6. Platform-specific hardening

Load `references/platforms-by-region.md` and apply the row for the detected platform: **update → platform-specific weak spots → hardening**. Also apply the hosting-layer row for the user's region, since on shared hosting and PaaS someone else patches the runtime.

If a platform isn't listed, look up its official security page and GitHub advisories and produce a row in the same format.

## 7. Runtime and server hardening

### php.ini baseline
```ini
expose_php = Off
display_errors = Off
log_errors = On
allow_url_include = Off
allow_url_fopen = Off            ; use cURL with an allowlist if outbound HTTP is needed
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec
open_basedir = /var/www/app:/tmp
session.use_strict_mode = 1
session.cookie_httponly = 1
session.cookie_secure = 1
session.cookie_samesite = Lax
upload_max_filesize = 10M        ; size to the app's real needs
```
Check that the platform doesn't need a disabled function before applying (some backup or image plugins do). Set security-critical values with `php_admin_*` so `ini_set()` and `.user.ini` can't override them.

### Process model
- Prefer **PHP-FPM over mod_php**: per-site pools, separate system users, independent restarts. mod_php also carries the highest PHP2Shell risk.
- Put every PHP worker under a container/cgroup memory limit.
- In containers: read-only root filesystem for code, writable volumes only where needed, non-root user.

### Web server
- Block PHP execution in upload, cache and data directories (Apache: `php_admin_flag engine off` or a deny rule; nginx: `location ~* ^/(uploads|data|cache)/.*\.php$ { deny all; }`).
- Deny `.env`, `.git`, `composer.*`, `*.sql`, `*.bak`, `*.zip`, `.user.ini`, `.htaccess` over HTTP.
- Security headers: `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Strict-Transport-Security`.
- **Egress filtering**: web workers rarely need arbitrary outbound access; restricting it limits webshell callbacks and SSRF impact.
- File permissions: code read-only to the worker; writable dirs minimal.

## 8. Prioritization

- **P0** — Unpatched runtime under an open §2 advisory; any evidence of compromise.
- **Critical** — Unauthenticated RCE, auth bypass, unauthenticated SQLi, EOL runtime/platform with public RCE.
- **High** — Authenticated SQLi, stored XSS reaching admins, executable uploads, payment tampering, IDOR on sensitive data.
- **Medium** — Reflected XSS, CSRF, debug/phpinfo exposure, weak hashing.
- **Low** — Missing headers, version disclosure, hardening gaps.

Raise priority for internet exposure, no authentication required, and KEV listing or confirmed in-the-wild exploitation.

## 9. Output format

```markdown
# PHP Security Review — <project>

## Summary
- Stack: PHP x.y (FPM|mod_php|…) / <platform> x.y / <web server> / <hosting>
- Emergency advisories: PHP2Shell — <patched | mitigated (partial) | VULNERABLE>
- Findings: P0 n · Critical n · High n · Medium n · Low n
- Do now: 1) … 2) … 3) …

## Runtime status (one row per host/image)
| Host / image | SAPI | Version | Backport confirmed | Workers restarted | Exposed since window start | Compromise check |

## Findings
### [Critical] <title>
- Location: `path/to/file.php:42`
- Cause: <the defect, not how to attack it>
- Fix:
  ```diff
  - old
  + new
  ```
- Verify: <test or re-scan command>
- References: <CVE / advisory links>

## Updates required
| Component | Installed | Target | Reason |

## Server / config changes
<php.ini, FPM pool, nginx/Apache diffs>

## Residual risk and follow-ups
```

- Match the codebase's style and framework conventions in every fix.
- For multi-file patches, produce files and number the order of application.
- State clearly which items are full fixes and which are partial mitigations.
