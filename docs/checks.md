# Checks

Every check cmsrecon runs or plans to run, the WPScan finder it corresponds to, and the release it is planned for. This is the implementation checklist for v1; rows marked **built** are implemented.

**Modes** have the same meaning as WPScan's `--detection-mode`:

- **passive** only parses responses the scan fetches anyway (homepage, 404 page, the feeds the homepage links to, the `/wp-json/` index).
- **aggressive** requests a specific path.
- **mixed** (the default) runs both.

Pre-flight always runs. In aggressive mode the passive checks are skipped, as in WPScan: no interesting headers, no versions from the homepage or its feeds, and no main theme (all of its signals are passive).

**Never in scope:** password guessing (`wp-login.php`, XML-RPC, `system.multicall`), username probing through login error messages, and exploitation of any kind.

**Confidence.** Each signal has a confidence from 0 to 100. Signals for the same thing are combined as independent probabilities, so 60% and 80% give 92%; repeats of the same signal count once.

## Soft-404 handling

Catch-all sites, WAFs and "403 for everything" setups answer every path, so an aggressive check that only looks at the status code would report files that do not exist. Checks without a strong content signature therefore also ask whether the response is a "not found" in disguise. It is if:

- the status is 404 or 410, or
- it has the same status and a similar body (or the same redirect target) as a request for a random name in the same directory with the same extension (for example `/wp-content/<random>.log` for `/wp-content/debug.log`), or
- it is a 200 whose body is similar to the homepage.

Bodies are compared after removing the requested name (404 pages often echo it) and collapsing numbers and hex runs (nonces, timestamps); "similar" means a Dice coefficient of at least 0.9 over tags and lines. The random-path baselines are fetched once per directory and extension. The random directory next to the homepage is also the 404 page that passive checks read.

## Pre-flight

| Check | How | Release |
|---|---|---|
| Reachability | Stop on connection failure, 401 (suggest `--http-auth`), 407, and 403 unless `--force` | v1 **built** |
| Redirects | Follow a redirect to the same URL on the other scheme (http↔https, same host and path) automatically. Any other homepage redirect, including a different path on the same host, stops the scan with the target URL as a hint unless `--follow-redirect` is set; followed hosts join the scope. Loops and chains over 10 stop. `--scope` adds in-scope domains (`*.example.com` for subdomains) | v1 **built** |
| WordPress detection | In-scope `wp-content` / `wp-includes` URLs in the homepage or 404 page, meta generator, `/wp-json/` `Link` header, `X-Pingback` header. Outside passive mode, `/wp-login.php` with the login form as a fallback. Stop unless `--force` | v1 **built** |
| Hosted on WordPress.com | A `*.wordpress.com` host, the `WordPress.com` meta generator, or, when the site serves no wp-content of its own, assets from `s<N>.wp.com` / `*.files.wordpress.com` (Jetpack sites load from wp.com too but have their own wp-content). Stop, even with `--force`: the platform, not the client, runs the infrastructure | v1 **built** |
| Unfinished install | Homepage redirects to `/wp-admin/install.php` (installer) or `/wp-admin/setup-config.php` (no `wp-config.php`): critical finding `unfinished-install`, and the scan stops | v1 **built** |
| Web server | `Server` header selects Apache, Nginx (also OpenResty, Tengine) or IIS directory-listing signatures; any other value tries all of them | v1 **built** |
| Content directory | The wp-content URL from page URLs, including a renamed one (e.g. Bedrock's `/app/`); `<base>/wp-content/` when none is seen. Aggressive checks under wp-content use it | v1 **built** |
| SAML / SSO login | Interactive browser login, then reuse the session cookies | later |

## Interesting findings

The ID is the `id` field of the [JSON report](json-report.md#finding). Paths under `/wp-content/` use the detected content directory; the others are relative to the scanned URL, except `robots.txt`, which is read from the host root.

| Check | ID | Request or signal | Severity | Mode | WPScan finder | Release |
|---|---|---|---|---|---|---|
| Interesting headers | `headers` | Homepage headers other than standard and security ones, such as `Server`, `X-Powered-By`, `Via` | info | passive | Headers | v1 **built** |
| robots.txt | `robots-txt` | `/robots.txt` with robots directives; lists `Allow`, `Disallow` and `Sitemap` entries except WordPress's own `/wp-admin/` rules | info | aggressive | RobotsTxt | v1 **built** |
| XML-RPC | `xmlrpc` | `X-Pingback` header, `<link rel="pingback">` (passive, 60%), "accepts POST requests only" from `/xmlrpc.php` (100%). **Improved:** a read-only `system.listMethods` call reports how many methods are exposed and whether `pingback.ping` and `system.multicall` are among them | info, low if either is exposed | mixed | XMLRPC | v1 **built** |
| readme | `readme` | `/readme.html` and its localized copies (`olvasdel.html`, `lisenssi.html`, `liesmich.html`): 200, mentions WordPress, not a soft-404 | info | aggressive | Readme | v1 **built** |
| Debug log | `debug-log` | `/wp-content/debug.log` whose first 64 KB contain a PHP log line (`[date] PHP …`) or `WordPress database error` | high | aggressive | DebugLog | v1 **built** |
| Full path disclosure | `full-path-disclosure` | A PHP error naming a `.php` path (any status, needs `display_errors`) from the first of `/wp-includes/rss.php`, `/wp-includes/template-loader.php`, `/wp-admin/includes/admin.php`, `/wp-includes/rss-functions.php` and `/wp-content/plugins/hello.php` that leaks one. **Changed:** WPScan only requests `rss-functions.php`, which exits early since WordPress added an `ABSPATH` check to it, so it misses on modern releases | low | aggressive | FullPathDisclosure | v1 **built** |
| Backup DB folder | `backup-db` | `/wp-content/backup-db/` answering 200 (70%) or 403 (60%), not a soft-404; 100% with directory listing | medium, high with a listing | aggressive | BackupDB | v1 **built** |
| Duplicator installer log | `duplicator-installer-log` | `/installer-log.txt` with a Duplicator log header in its first 16 KB | medium | aggressive | DuplicatorInstallerLog | v1 **built** |
| Multisite | `multisite` | `/wp-signup.php` returns 200 with the signup form (not a soft-404) or redirects to a `wp-signup.php` (a sub-site sends it to the main site). A single site redirects to `wp-login.php?action=register` instead | info | aggressive | Multisite | v1 **built** |
| Must-use plugins | `mu-plugins` | `wp-content/mu-plugins/` in page URLs (passive, 80%), then `/wp-content/mu-plugins/` answering 200 or 403, not a soft-404 (70%; 100% with directory listing) | info, low with a listing | mixed | MuPlugins | v1 **built** |
| Open registration | `registration` | `/wp-login.php?action=register` shows the registration form, following up to 3 in-scope redirects (a network sends it to `wp-signup.php`, whose signup form also counts) | low | aggressive | Registration | v1 **built** |
| Uploads listing | `upload-directory-listing` | Directory listing on `/wp-content/uploads/`; lists up to 20 entries | medium | aggressive | UploadDirectoryListing | v1 **built** |
| TMM DB Migrate export | `tmm-db-migrate` | `/wp-content/uploads/tmm_db_migrate/tmm_db_migrate.zip` starting with the zip signature, or served as a zip and not HTML | high | aggressive | TmmDbMigrate | v1 **built** |
| SQL dump in uploads | `upload-sql-dump` | `/wp-content/uploads/dump.sql` (requested with `Range: bytes=0-3071`) whose first 3 KB contain SQL: a dump header, `CREATE TABLE`, `INSERT INTO`, … | high | aggressive | UploadSQLDump | v1 **built** |
| Emergency password reset script | `emergency-password-reset` | `/emergency.php`: 200, not a soft-404 (60%; 100% if it mentions the reset form) | high | aggressive | EmergencyPwdResetScript | v1 **built** |
| WP-Cron | `wp-cron` | `/wp-cron.php`: 200, not a soft-404 | info | aggressive | WPCron | v1 **built** |
| PHP not executed | `php-disabled` | `/wp-includes/version.php` served as source (`<?php` and `$wp_version`); the version also feeds core version detection | high | aggressive | PHPDisabled | v1 **built** |
| Fantastico file list | `fantastico-fileslist` | `/fantastico_fileslist.txt` served as `text/plain`, not empty, not a soft-404 | medium | aggressive | FantasticoFileslist | v1 **built** |
| Search Replace DB script | `search-replace-db2` | `/searchreplacedb2.php`: 200, not a soft-404 (60%; 100% if it names the tool) | high | aggressive | SearchReplaceDB2 | v1 **built** |

## WordPress core version

Every signal is reported with the version it saw and its confidence. Signals that agree are combined; the version with the highest combined confidence wins, and below 40% the version is reported as unknown, as in WPScan. Conflicting candidates are listed in the report.

| Signal | Confidence | Mode | Release |
|---|---|---|---|
| `<generator>` in the RSS, Atom and RDF feeds: the feeds the homepage links to (passive), then `/feed/`, `/feed/atom/`, `/feed/rdf/`, and `/?feed=rss2` when `/feed/` fails (aggressive) | 80% | mixed | v1 **built** |
| Meta generator tag `WordPress X.Y.Z` | 60% | passive | v1 **built** |
| `?ver=` on core scripts and styles under `wp-includes`, ignoring bundled libraries (jQuery, TinyMCE, `dist/vendor`, …); the more core assets agree, the higher the confidence | 30% for one asset, +10% per extra asset, at most 60% | passive | v1 **built** |
| Version in `/readme.html` (only old releases print it) | 70% | aggressive | v1 **built** |
| `$wp_version` in `/wp-includes/version.php` served as source | 100% | aggressive | v1 **built** |
| Hashes of core static files, matched against our own hash database built from official WordPress releases | | aggressive | v1 |

## Themes

| Check | How | Mode | Release |
|---|---|---|---|
| Main theme | Signals from the homepage and the 404 page: the `wp-child-theme-<slug>` or `wp-theme-<slug>` body class (100%), the last theme `style.css` link on the page (70%; a child theme's stylesheet is enqueued after its parent's), the theme with the most URLs (40%; other themes seen get 10%), the WooFramework meta generator (80%). Outside passive mode, a runner-up whose `style.css` names the leader in `Template:` is the child theme and becomes the main theme | passive | v1 **built** |
| Theme version | `Version:` header in the theme's `style.css` (80%), plus the theme's name, URI and author. The parent theme comes from the `Template:` header or the `wp-theme-<slug>` body class and is read the same way | aggressive | v1 **built** |
| Theme discovery | Theme URLs in pages, then `/wp-content/themes/<slug>/` for the vulnerable, popular or all lists (`-e vt`, `t`, `at`) | mixed | v1 |

## Plugins

| Check | How | Mode | WPScan finder | Release |
|---|---|---|---|---|
| Page URLs | `/wp-content/plugins/<slug>/` in homepage and 404 page HTML | passive | UrlsInHomepage, UrlsIn404Page | v1 |
| REST namespaces | The `/wp-json/` index lists namespaces registered by active plugins (`yoast/v1`, `contact-form-7/v1`, …) | passive | none (new) | v1 |
| Signatures | Per-plugin HTML comments, headers, JS variables and body patterns. WPScan keeps these in its licensed `dynamic_finders.yml`; we build our own set | passive | Comment, HeaderPattern, Xpath, BodyPattern, JavascriptVar | v1 (starter set) |
| Brute force | `/wp-content/plugins/<slug>/` for the vulnerable, popular or all lists (`-e vp`, `p`, `ap`) | aggressive | KnownLocations | v1 |
| Version evidence | readme.txt `Stable tag`, newest changelog entry, `?ver=` on the plugin's own assets (ignored when it equals the core version), generator comments. Each signal is scored and reported with its source | mixed | Readme, dynamic finders | v1 (improved) |
| Outdated or closed | Latest version and closed status from WordPress.org metadata downloaded by `cmsrecon update` | n/a | partly | v1 |
| Hash fingerprinting | Hashes of each release's static JS and CSS from WordPress.org SVN tags, giving an exact version or a narrow range | aggressive | none (new) | v1.1 |

## Other enumerations

| Flag | What | Release |
|---|---|---|
| `cb` | Copies of `wp-config.php` left by editors and admins (`.bak`, `.old`, `.save`, `.swp`, `~`, …), from our own list | v1 |
| `dbe` | Database exports such as `<domain>.sql`, `dump.sql`, `backup.sql` and compressed variants, from our own list | v1 |
| `bf` | Backup plugin folders under `wp-content`, reported only when directory listing is enabled | v1 |
| `m` | Media files through `?attachment_id=N` | v1.1 |
| `tt` | Timthumb script locations and versions | v1.1 |

## Users (`-e u`)

| Check | How | Mode | Release |
|---|---|---|---|
| Author links | Author URLs and classes on the homepage | passive | v1 |
| REST API | `/wp-json/wp/v2/users`, falling back to `?rest_route=/wp/v2/users` when pretty permalinks are off | aggressive | v1 |
| oEmbed | `author_name` / `author_url` from `/wp-json/oembed/1.0/embed?url=<homepage>` | aggressive | v1 |
| RSS | `dc:creator` in the feed | mixed | v1 |
| Sitemaps | `/wp-sitemap-users-1.xml` and Yoast's `/author-sitemap.xml` | aggressive | v1 |
| Author IDs | `/?author=N` redirects and archive titles for N in the range (default 1-10) | aggressive | v1 |
| Login error messages | Not implemented: it submits a login attempt per username and can lock accounts | never | never |

## Authenticated inventory (`--wp-auth`)

With an administrator's Application Password, cmsrecon reads `/wp-json/wp/v2/plugins` (WordPress 5.5+) and `/wp-json/wp/v2/themes` (5.7+) to get exact slugs, versions and the active theme. This replaces plugin and theme enumeration. Release: v1.

## Vulnerabilities

`cmsrecon update` downloads everything below into `--data-dir`. During a scan, cmsrecon only contacts the target.

| Source | Use | Release |
|---|---|---|
| Wordfence Intelligence v3 feed | Primary database: the full JSON feed, downloaded with a free API key | v1 |
| CVE List V5 | Cross-check: plugin slugs come from `plugins.trac.wordpress.org` and `wordpress.org/plugins/` references, version ranges from the `affected` entries | v1 |
| WordPress.org API | Latest versions, popular slugs, closed plugins | v1 |
| retire.js database | Vulnerable JavaScript libraries in the scripts the scanned pages load | v1.1 |

Each match gets a verdict: **Confirmed** (detected version inside the affected range, high confidence), **Likely**, **Possible** (version unknown; listed collapsed) or **Not affected**. Findings show the affected range, the fixed version and which sources agree, and disagreements between sources are flagged.

## Output

| Format | Release |
|---|---|
| CLI (colored, `--no-color`, `-v` for evidence) | v1 **built** |
| JSON, documented in [json-report.md](json-report.md) | v1 **built** |
| SARIF, HTML | v1.1 |
