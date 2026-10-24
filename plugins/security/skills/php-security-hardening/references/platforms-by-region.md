# Platform playbooks by region

For every platform: **update → platform-specific weak spots → hardening**. If a platform isn't listed, look up its official security page and GitHub advisories and produce a row in the same format.

## Global

| Platform | Weak spots | Key actions | Advisory sources |
|---|---|---|---|
| WordPress (+WooCommerce) | Most vulns are in **plugins/themes** | Remove unused plugins, `DISALLOW_FILE_EDIT`, limit XML-RPC, admin 2FA, block PHP in `wp-content/uploads` | WPScan, Wordfence Intelligence, Patchstack |
| Laravel | `APP_DEBUG=true` in prod, leaked `APP_KEY` | Debug off, `.env` outside webroot, rotate key on leak and invalidate sessions, audit `$fillable` | GitHub advisories, `composer audit` |
| Symfony | Profiler / `_fragment` exposed, `APP_SECRET` | `APP_ENV=prod`, no WebProfiler in prod, rotate secret | symfony.com security blog |
| Drupal | Core and contrib | Apply SAs promptly, `settings.php` read-only, `trusted_host_patterns` | drupal.org/security |
| Joomla | Extensions, public API endpoints | Update core, remove unused extensions, restrict API | Joomla Security Centre |
| Magento / Adobe Commerce | Payment skimmers, admin path | APSB patches, custom admin URL, 2FA, CSP, file-integrity monitoring | Adobe APSB, Sansec |
| phpMyAdmin | Being internet-exposed at all | VPN/IP-restrict or remove | phpmyadmin.net/security |
| Moodle, MediaWiki, Nextcloud, phpBB, Craft CMS | Plugins/extensions | Track official security notices, stay on LTS | Each project's security page |
| CodeIgniter, CakePHP, Yii | Old major versions left running (e.g. CI3) | Plan migration to supported branch; confirm CSRF/XSS filters | GitHub advisories |
| **Hosting layer** | Runtime patched by someone else | cPanel/CloudLinux alt-php, Plesk, DirectAdmin: update every installed PHP; PaaS (Beanstalk, Lightsail, Forge/Vapor, Platform.sh/Upsun, Heroku): follow the platform update path | Provider status pages |

## Korea

| Platform | Weak spots | Key actions | Advisory sources |
|---|---|---|---|
| Gnuboard 5 / Youngcart | Old versions left running, `data/` upload dir, raw queries in custom skins, `adm/` path | Apply latest patch, block PHP execution under `data/`, IP-restrict `adm/`, audit skins/plugins for concatenated `sql_query` | sir.kr notices & security patch board, KISA |
| Youngcart payments | Amount tampering on return pages | Server-side order vs PG-approved amount check, duplicate-approval guard | PG developer docs |
| Rhymix / XpressEngine | XE 1.x effectively unmaintained | Migrate to Rhymix, update modules/add-ons | rhymix.org, GitHub |
| Legacy (Zeroboard etc.) | EOL | Isolate now, plan migration | — |
| PG SDKs (KG Inicis, NHN KCP, Toss Payments, etc.) | Outdated PHP SDKs, hardcoded secret keys | Latest SDK, keys in env vars, verify webhook/noti IP and signature | Each PG's developer center |
| Hosting | Cafe24, Gabia, Dothome, NHN Cloud, Naver Cloud | Switch PHP version in panel; confirm provider patched runtime | Provider notices |
| Compliance | — | PIPA safeguards (one-way password hashing, access-log retention), map findings to KISA web vulnerability checklist | KISA, PIPC |

## Japan

| Platform | Weak spots | Key actions | Advisory sources |
|---|---|---|---|
| EC-CUBE | Default admin route, plugins, legacy 2.x/3.x | Stay on 4.x latest, change `ECCUBE_ADMIN_ROUTE` + IP-restrict, update plugins, migrate legacy | ec-cube.net security info, JVN |
| baserCMS, a-blog cms, concrete CMS | Core and plugins | Apply official security updates | JVN, vendor sites |
| Welcart (WP) | WP plugin | WordPress row + keep plugin current | JVN, WPScan |
| Hosting | Xserver, Sakura Internet, ConoHa WING, Lolipop | Switch PHP version in panel; confirm provider patch | Provider notices |
| Compliance | — | Map to IPA "How to Secure Your Website" checklist; APPI | IPA, JPCERT/CC |

## China

| Platform | Weak spots | Key actions | Advisory sources |
|---|---|---|---|
| ThinkPHP | Historic routing/multi-language RCEs in old branches, `app_debug` exposed | Upgrade to a supported major, debug off, enforce routing (`url_route_must`), block web access to `runtime/` | Official notices, CNVD |
| Discuz! | Leaked `UC_KEY`, plugins, old X3.x | Latest patches, rotate `UC_KEY`, lock down `data/` and `config/` | Official forum, CNVD |
| DedeCMS, PHPCMS, ECShop | Effectively unmaintained, accumulated vulns | No new deployments; if running: rename/IP-restrict admin, block upload-dir execution, migrate | CNVD, CNNVD |
| EmpireCMS, FastAdmin, WeEngine | Admin backends, plugin markets | Update, restrict backend access | Official notices, CNVD |
| Alipay / WeChat Pay SDKs | Unverified async callbacks | Verify callback signature and amount | Official developer docs |
| Hosting | Alibaba Cloud, Tencent Cloud, BT Panel (宝塔) | Update every panel-installed PHP version | Provider notices |
| Compliance | — | MLPS 2.0 (等保2.0), PIPL | — |

## Russia / CIS

| Platform | Weak spots | Key actions | Advisory sources |
|---|---|---|---|
| 1C-Bitrix | Historic module RCEs (vote, HTML editor), lapsed update licenses | Keep SiteUpdate current, enable Proactive Protection module, run the built-in security scanner | dev.1c-bitrix.ru, BDU FSTEC |
| MODX | Default `manager/`, `connectors/`, `core/` paths | Rename paths, move `core/` outside webroot, stay on 3.x | modx.com security notices |
| OpenCart / ocStore | Uneven extension quality, leftover `install/` | Delete `install/`, rename admin, audit extensions | GitHub advisories |
| DataLife Engine | Plugins, old versions | Update, restrict admin | Vendor site |
| Hosting | Timeweb, Beget, REG.RU, BitrixVM images | Switch/patch PHP, update VM images | Provider notices |

## Germany / DACH

| Platform | Weak spots | Key actions | Advisory sources |
|---|---|---|---|
| TYPO3 | Install Tool, host header, extensions | Lock Install Tool, set `trustedHostsPattern`, stay on LTS/ELTS | typo3.org security advisories |
| Shopware | 5.x EOL, `APP_ENV`, plugins | Stay on 6.x, security plugin for legacy, prod mode | shopware.com security |
| Contao, OXID eShop, Neos | Core and extensions | LTS, follow security releases | Official security pages |
| Hosting | IONOS, Strato, Hetzner, ALL-INKL | Switch/patch PHP | Provider notices |
| Compliance | — | GDPR, BSI IT-Grundschutz, NIS2 | BSI |

## France / Southern Europe

| Platform | Weak spots | Key actions | Advisory sources |
|---|---|---|---|
| PrestaShop | **Third-party modules**, leftover `install/`, admin folder | Update/remove modules, delete `install/`, apply MySQL Smarty cache recommendations when advised | PrestaShop security advisories, Friends-Of-Presta |
| SPIP | Core | Keep the security screen (écran de sécurité) current | spip.net |
| Dolibarr, GLPI | Internal tools exposed to internet | Update, VPN/IP-restrict | GitHub advisories |
| Hosting | OVHcloud, o2switch | Switch/patch PHP | Provider notices |
| Compliance | — | GDPR, ANSSI guides | CERT-FR |

## Other regions

- **South / Southeast Asia** (India, Indonesia, Vietnam): heavy CodeIgniter, Laravel, OpenCart use → Global rows. Also NukeViet (VN) and OJS (academic publishing).
- **Latin America**: WordPress/WooCommerce, PrestaShop, Magento → Global and France rows; verify local payment-gateway webhooks.
- **Payments everywhere**: Stripe/PayPal webhook signature verification; never store card data (PCI DSS).
