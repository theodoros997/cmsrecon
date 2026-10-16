# Checks

Every check cmsrecon runs or plans to run, the WPScan finder it corresponds to, and the release it is planned for. This is the implementation checklist for v1.

**Modes** have the same meaning as WPScan's `--detection-mode`:

- **passive** only parses responses the scan fetches anyway (homepage, 404 page, feeds, the `/wp-json/` index).
- **aggressive** requests a specific path.
- **mixed** (the default) runs both.

**Never in scope:** password guessing (`wp-login.php`, XML-RPC, `system.multicall`), username probing through login error messages, and exploitation of any kind.

## Pre-flight

| Check | How | Release |
|---|---|---|
| Reachability | Stop on connection failure, 401 (suggest `--http-auth`), 407, and 403 unless `--force` | v1 |
| Redirects | Follow http↔https on the same host automatically. Any other homepage redirect stops the scan unless `--follow-redirect` is set. `--scope` adds in-scope domains | v1 |
| WordPress detection | `wp-content` / `wp-includes` URLs, meta generator, `/wp-json/` link header. Stop unless `--force` | v1 |
| Hosted on WordPress.com | Stop: the platform, not the client, runs the infrastructure | v1 |
| Unfinished install | Homepage redirects to `/wp-admin/install.php`: report as critical | v1 |
| Web server | `Server` header selects Apache, Nginx or IIS directory-listing signatures | v1 |
| SAML / SSO login | Interactive browser login, then reuse the session cookies | later |

## Interesting findings

| Check | Request or signal | Mode | WPScan finder | Release |
|---|---|---|---|---|
| Interesting headers | Homepage headers such as `Server`, `X-Powered-By` | passive | Headers | v1 |
| robots.txt | `/robots.txt` entries | aggressive | RobotsTxt | v1 |
| XML-RPC | `X-Pingback` header, `<link rel="pingback">`, `/xmlrpc.php`. **Improved:** a read-only `system.listMethods` call reports whether `pingback.ping` and `system.multicall` are exposed | mixed | XMLRPC | v1 |
| readme | `/readme.html` and its localized copies (`olvasdel.html`, `lisenssi.html`, `liesmich.html`) | aggressive | Readme | v1 |
| Debug log | `/wp-content/debug.log` | aggressive | DebugLog | v1 |
| Full path disclosure | PHP error from `/wp-includes/rss-functions.php` | aggressive | FullPathDisclosure | v1 |
| Backup DB folder | `/wp-content/backup-db/` (200 or 403) | aggressive | BackupDB | v1 |
| Duplicator installer log | `/installer-log.txt` with a Duplicator header | aggressive | DuplicatorInstallerLog | v1 |
| Multisite | `/wp-signup.php` returns 200 or redirects to itself | aggressive | Multisite | v1 |
| Must-use plugins | `wp-content/mu-plugins/` in page URLs, then `/wp-content/mu-plugins/` | mixed | MuPlugins | v1 |
| Open registration | `/wp-login.php?action=register` shows the registration form | aggressive | Registration | v1 |
| Uploads listing | Directory listing on `/wp-content/uploads/` | aggressive | UploadDirectoryListing | v1 |
| TMM DB Migrate export | `/wp-content/uploads/tmm_db_migrate/tmm_db_migrate.zip` served as a zip | aggressive | TmmDbMigrate | v1 |
| SQL dump in uploads | `/wp-content/uploads/dump.sql` whose first 3 KB contain SQL | aggressive | UploadSQLDump | v1 |
| Emergency password reset script | `/emergency.php` | aggressive | EmergencyPwdResetScript | v1 |
| WP-Cron | `/wp-cron.php` reachable | aggressive | WPCron | v1 |
| PHP not executed | `/wp-includes/version.php` served as source | aggressive | PHPDisabled | v1 |
| Fantastico file list | `/fantastico_fileslist.txt` served as `text/plain` | aggressive | FantasticoFileslist | v1 |
| Search Replace DB script | `/searchreplacedb2.php` | aggressive | SearchReplaceDB2 | v1 |

## WordPress core version

The strongest signal wins; below 40% confidence the version is reported as unknown, as in WPScan.

| Signal | Mode | Release |
|---|---|---|
| `<generator>` in the RSS, Atom and RDF feeds | mixed | v1 |
| Meta generator tag, `?ver=` on core scripts and styles | passive | v1 |
| Version in `/readme.html` | aggressive | v1 |
| Hashes of core static files, matched against our own hash database built from official WordPress releases | aggressive | v1 |

## Themes

| Check | How | Mode | Release |
|---|---|---|---|
| Main theme | `style.css` links and theme URLs on the homepage and 404 page, WooFramework meta generator | passive | v1 |
| Theme version | `Version:` header in the theme's `style.css` | aggressive | v1 |
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
| CLI (colored, `--no-color`) | v1 |
| JSON | v1 |
| SARIF, HTML | v1.1 |
