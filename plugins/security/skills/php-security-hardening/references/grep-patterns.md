# Executable grep/ripgrep patterns

Copy-paste-ready regexes for the vulnerability classes in SKILL.md §5. They live in
fenced code blocks (not a Markdown table) so **no pipe or `$` escaping is applied** —
paste them verbatim into `rg`.

Usage:
```bash
rg -n --pcre2 -t php 'PATTERN' .
```
`--pcre2` is optional for these (they use basic ERE features), but it is safe to keep.
Run every match through human review: these find *candidate* sinks, not confirmed bugs.
A match on vendor/core code is fixed by updating that dependency, not by editing it.

## Injection and execution

```bash
# SQL injection — query call with a PHP variable in the string
rg -n -t php '(->query|mysqli_query|mysql_query|sql_query)\s*\(.*\$' .

# SQL injection — request var interpolated into a SELECT/INSERT/UPDATE/DELETE
# -i is required: much PHP code (e.g. Gnuboard) writes SQL in lowercase.
rg -n -i -t php '(SELECT|INSERT|UPDATE|DELETE).*\$_(GET|POST|REQUEST|COOKIE)' .

# Command execution sinks
rg -n -t php '\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(' .

# Backtick command execution — NOISY: MySQL identifier quoting inside SQL strings
# (e.g. "ALTER TABLE `{$table}`") also matches. Skip hits that sit inside a SQL string.
rg -n -t php '`[^`]*\$' .

# Code execution sinks
rg -n -t php '\b(eval|assert|create_function)\s*\(' .

# preg_replace with the /e modifier (removed in PHP 7, still seen in old code)
rg -n -t php 'preg_replace\s*\(\s*.[^,]*/e' .
```

## Input reaching dangerous sinks

```bash
# XSS — request value echoed directly
rg -n -t php 'echo\s+.*\$_(GET|POST|REQUEST|COOKIE)' .
rg -n -t php '<\?=\s*\$_(GET|POST|REQUEST|COOKIE)' .

# XSS — template auto-escape turned off (Blade, Twig, Smarty)
# Do NOT use -t php here: Twig (.twig) and Smarty (.tpl) templates are not PHP files.
rg -n -g '*.php' -g '*.twig' -g '*.tpl' '\{!!|\|\s*raw|nofilter' .

# File inclusion with a variable path (LFI/RFI)
rg -n -t php '(include|require)(_once)?\s*\(?\s*\$' .

# File upload handling
rg -n -t php 'move_uploaded_file|\$_FILES' .

# Unsafe deserialization / phar wrapper
rg -n -t php 'unserialize\s*\(' .
rg -n -t php 'phar://' .

# SSRF — remote fetch with a variable URL
rg -n -t php '(file_get_contents|fopen|curl_init)\s*\(\s*\$' .
rg -n -t php 'CURLOPT_URL' .

# Path traversal — file op with request input
rg -n -t php '\b(fopen|file_put_contents|file_get_contents|unlink|readfile|rename|copy)\s*\(.*\$_(GET|POST|REQUEST|COOKIE)' .

# Variable pollution
rg -n -t php 'extract\s*\(\s*\$_' .
rg -n -t php 'parse_str\s*\(\s*\$[A-Za-z_]+\s*\)' .     # one-argument parse_str
rg -n -t php '\$\$[A-Za-z_]' .                          # variable variables
```

## Auth, crypto, disclosure

```bash
# Type-juggling / timing issues in auth comparisons
rg -n -t php 'strcmp\s*\(' .
rg -n -t php '==\s*\$?(hash|token|sig|signature|mac|pass)' .

# Weak hashing for secrets
rg -n -t php '\b(md5|sha1)\s*\(' .

# Weak randomness used for tokens
rg -n -t php '\b(rand|mt_rand|uniqid)\s*\(' .

# Header / mail injection
rg -n -t php '\bheader\s*\(\s*.*\$' .
rg -n -t php '\bmail\s*\(' .

# Open redirect
rg -n -t php "header\s*\(\s*['\"]Location:" .

# Information disclosure
rg -n -t php '\b(phpinfo|var_dump|var_export|print_r|debug_zval_dump)\s*\(' .

# Debug output switched on — PHP code sets it with ini_set(), not "key = value"
rg -n -t php "ini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*['\"]?(1|on|true)" .

# Debug output switched on in ini-style config (php.ini, .user.ini, .htaccess)
rg -n -i -g '*.ini' -g '.user.ini' -g '.htaccess' 'display_errors\s*(=\s*|\s+)(On|1|true)' .
```

## Backdoor / obfuscation sweep (incident response)

```bash
# Common obfuscation primitives feeding execution
rg -n -t php 'base64_decode|gzinflate|gzuncompress|str_rot13|convert_uudecode' .

# Request superglobal called as a function (dynamic dispatch backdoor)
rg -n -t php '\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[[^]]*\]\s*\(' .

# Files changed since an exposure window start (set the date)
# find <webroot> -type f -name '*.php' -newermt '2026-10-17'
```

## Notes

- `-t php` covers `*.php`, `*.php3`–`*.php8`, `*.pht` and `*.phtml`. It does **not** cover
  `.inc` includes or templates (`.twig`, `.tpl`); add `-g '*.inc'` or drop `-t php` to scan those.
- Add `-g '!vendor/' -g '!node_modules/'` to skip dependencies, then audit those by
  version instead (`composer audit`).
- These are first-pass filters. Confirm each hit by reading the surrounding code: a
  sink is only a vulnerability when attacker-controlled input can actually reach it.
