# Checks

Every check cmsrecon runs or plans to run, the WPScan finder it corresponds to, and the release it is planned for. This is the implementation checklist for v1; rows marked **built** are implemented.

**Modes** have the same meaning as WPScan's `--detection-mode`:

- **passive** only parses responses the scan fetches anyway (homepage, 404 page, the feeds the homepage links to, the REST API index the homepage's `Link` header points to).
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

Bodies are compared after removing the requested name from both of them (404 pages often echo it) and collapsing numbers and hex runs (nonces, timestamps); "similar" means a Dice coefficient of at least 0.9 over tags and lines. The random-path baselines are fetched once per directory and extension. The random directory next to the homepage is also the 404 page that passive checks read.

**Brute force** (plugin and theme lists, only with `--plugins-detection` or `--themes-detection` `mixed` or `aggressive`) sends `HEAD` requests, which download no body. A 404 or 410 means absent, and a status that differs from the random path's means present (200, 403 and 401 for directories without an index, 500 for a theme's `index.php` failing outside WordPress). When the status is the same as the random path's, as on catch-all sites, only the bodies can tell, so that path is fetched with `GET` and compared as above. A redirect counts only when it stays on the same path (an added slash, another scheme). Servers that answer `HEAD` with 405 or 501 get `GET` requests for the rest of the scan. The requests run on `--threads` workers.

## Pre-flight

| Check | How | Release |
|---|---|---|
| Reachability | Stop on connection failure, 401 (suggest `--http-auth`), 407, and 403 unless `--force` | v1 **built** |
| Redirects | Follow a homepage redirect whose destination host is in scope: the target host (any path, port or scheme, so http↔https too) or a `--scope` domain (`*.example.com` for subdomains), as WPScan does. A redirect to any other host stops the scan with a hint to use `--follow-redirect` or `--scope <host>`; with `--follow-redirect` it is followed and the host joins the scope. Loops and chains over 10 stop. Each redirect is reported with why it was or was not followed | v1 **built** |
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
| TMM DB Migrate export | `tmm-db-migrate` | `/wp-content/uploads/tmm_db_migrate/tmm_db_migrate.zip` starting with a zip signature, or served as a zip and not HTML. Reports what was seen (size, `Content-Type`), not what the archive holds: only its first 512 bytes are read | high; low for an empty archive (22 bytes or less) | aggressive | TmmDbMigrate | v1 **built** |
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

## Discovery

Plugins and themes are found from what the site shows before anything is guessed, as WPScan does by default (`--plugins-detection passive`), but from more of the site. Every check below reads:

- **The homepage and the 404 page** (passive).
- **Crawled pages** (aggressive, skipped in passive mode and with `--crawl 0`). These are up to `--crawl` pages (default 10), plus the login page when it shows the login form. The pages come from the sitemap index (from `robots.txt`, then `/wp-sitemap.xml`, then `/sitemap_index.xml`): the first page of each of up to three sitemaps, pages first, then posts, then products, then other post types; taxonomy and user sitemaps are skipped. Then come the homepage's links, the first one of each first path segment, so the navigation's pages come first and each section is read once. Only in-scope pages under the scanned path are read. Admin, API, feed, comment and file URLs are skipped, and so are links with a query string other than `?p=` and `?page_id=`, so that nothing with side effects (add to cart, log out) is followed. The sitemap index itself is read too: Yoast SEO's links its stylesheet from the plugin's folder, and Rank Math and All in One SEO sign it.

Different templates load different plugins (a shop page the cart and payment plugins, a contact page the form plugin, a post the comment plugins, the login page the security and captcha plugins), so a few pages cover far more than the homepage. Plugin, theme, JavaScript library and author link signals from crawled pages are reported as aggressive evidence.

## Themes

| Check | How | Mode | Release |
|---|---|---|---|
| Main theme | Signals from the homepage and the 404 page: the `wp-child-theme-<slug>` or `wp-theme-<slug>` body class (100%), the last theme `style.css` link on the page (70%; a child theme's stylesheet is enqueued after its parent's), the theme with the most URLs (40%; other themes seen get 10%), the WooFramework meta generator (80%). Outside passive mode, a runner-up whose `style.css` names the leader in `Template:` is the child theme and becomes the main theme | passive | v1 **built** |
| Theme version | `Version:` header in the theme's `style.css` (80%, aggressive), plus the theme's name, URI and author. `?ver=` on the theme's `style.css` link (50%, passive), ignored when it equals a WordPress core version candidate, which is what WordPress adds when a theme enqueues its stylesheet without a version. The parent theme comes from the `Template:` header or the `wp-theme-<slug>` body class and gets the same version signals | mixed | v1 **built** |
| Theme discovery | Themes other than the main one and its parent: theme URLs in the [discovery](#discovery) pages (80%) and the `/wp-content/themes/` directory listing (100%). With `--themes-detection mixed` or `aggressive`, `/wp-content/themes/<slug>/` is also brute-forced for the vulnerable, popular or all lists (`-e vt`, `t`, `at`). Each theme's `style.css` gives its name and version (a `Theme Name` header adds 100%) | mixed | v1 **built** |
| Outdated themes | The latest version from the WordPress.org data `cmsrecon update` downloads | n/a | v1 **built** |

## Plugins

| Check | How | Mode | WPScan finder | Release |
|---|---|---|---|---|
| Page URLs | `/wp-content/plugins/<slug>/` (or the renamed plugins directory) in the URLs of the [discovery](#discovery) pages: the homepage, the 404 page and the crawled pages, 80% each. URLs on a CDN alias of the site (`cdn.`, `static.`, `www.`, … of the same domain) and Jetpack's image CDN (`i0.wp.com/<host>/…`) count too; they are read, never requested | passive | UrlsInHomepage, UrlsIn404Page | v1 **built** |
| REST namespaces | The namespaces in the REST API index: 80 known ones map to their plugin (`yoast/v1` is Yoast SEO, `wc/store/v1` WooCommerce, `tribe/tickets/v1` Event Tickets; 90%). An unknown namespace whose first segment is a known plugin slug counts at 60% | passive | none (new) | v1 **built** |
| Signatures | 160 signatures for 130 plugins: HTML comments (Yoast SEO, All in One SEO, MonsterInsights, LiteSpeed Cache, …), meta generators (Elementor, WooCommerce, Slider Revolution, WPML, …), JavaScript configuration objects, CSS classes specific to one plugin, response headers (`X-Powered-By: W3 Total Cache/…`, `X-LiteSpeed-Tag`, …), and the folders caching and builder plugins write to (`cache/autoptimize/`, `uploads/elementor/`, …). Signatures that print a version give it at 80%. A meta generator of the form `<known slug> <version>` (the Performance team plugins) counts at 60%. WPScan keeps its signatures in its licensed `dynamic_finders.yml`; these are cmsrecon's own | passive | Comment, HeaderPattern, Xpath, BodyPattern, JavascriptVar | v1 **built** |
| Sitemap post types | Post types and taxonomies only one plugin registers, as the sitemap index lists them: `product` is WooCommerce, `tribe_events` The Events Calendar, `job_listing` WP Job Manager, … (80%). Generic names such as `event` or `portfolio` are ignored | aggressive | none (new) | v1 **built** |
| Directory listing | `/wp-content/plugins/` with directory listing names every plugin installed, inactive ones included (100%). One request | aggressive | none (new) | v1 **built** |
| Brute force | Only with `--plugins-detection mixed` or `aggressive` (the default, `passive`, never brute-forces, as in WPScan): `/wp-content/plugins/<slug>/` for the vulnerable, popular or all lists (`-e vp`, `p`, `ap`), one request each; see [brute force](#soft-404-handling). Found with a listing 100%, a 200 80%, a 401 or 403 70%, another status 60%. The only way to find inactive plugins on a server without listings | aggressive | KnownLocations | v1 **built** |
| Readme | `readme.txt`, then `README.txt`: a readme proves the plugin is there (100%) and gives its name | aggressive | Readme | v1 **built** |
| Version evidence | The readme's `Stable tag` (80%, ignored when it is `trunk`) and the highest version in its changelog section (60%; some changelogs list the oldest release first); without either, `changelog.txt` or `CHANGELOG.md` (60%). `?ver=` on the plugin's assets: 40% for one asset, 50% for two, 60% for three or more, ignoring values equal to a core version candidate and bundled libraries (`/vendor/`, `/lib/`, files recognized as JavaScript libraries). Signature versions (80%) | mixed | Readme, dynamic finders | v1 **built** (improved) |
| Outdated | The latest version from the WordPress.org data `cmsrecon update` downloads (the 2,000 most installed plugins) | n/a | partly | v1 **built** |
| Closed plugins | Plugins removed from WordPress.org | n/a | partly | v1.1 |
| Hash fingerprinting | Hashes of each release's static JS and CSS from WordPress.org SVN tags, giving an exact version or a narrow range | aggressive | none (new) | v1.1 |

The brute-force lists come from `cmsrecon update`: the vulnerable list is every slug in the vulnerability data (slugs the CVE List only gives as product names are matched but not brute-forced), the popular list the 2,000 most installed WordPress.org plugins, the full list every slug in the WordPress.org SVN. Premium plugins that WordPress.org does not list (Elementor Pro, WPBakery, Slider Revolution, LayerSlider, Gravity Forms, WP Rocket, …) are always added to the popular list. Before the first update, cmsrecon uses its built-in list of 760 popular and 98 premium plugins for every list, and the report says so. The same applies to themes (218 popular and 44 premium built in; 500 popular after an update).

## Other enumerations

These are reported as [interesting findings](json-report.md#finding).

| Flag | ID | What | Severity | Release |
|---|---|---|---|---|
| `cb` | `config-backup` | 38 names of `wp-config.php` copies left by editors, admins and deployment tools (`.bak`, `.old`, `.save`, `.swp`, `~`, `#wp-config.php#`, …), from our own list. A copy counts when it defines two or more of the WordPress constants (`DB_NAME`, `DB_PASSWORD`, `AUTH_KEY`, …), or one plus `$table_prefix`, and is not an HTML page (a catch-all page or a tutorial showing `define()` calls). The report names the constants, never their values | critical with `DB_PASSWORD`, high otherwise | v1 **built** |
| `dbe` | `db-export` | About 70 paths: `<host>.sql`, `<domain>.sql`, `wordpress.sql`, `backup.sql`, `dump.sql`, `db.sql`, … with `.sql.gz`, plus `.zip` and `.tar.gz` for the host-based names, at the site root, in wp-content and in `backup/` folders, from our own list. Only the first 3 KB are requested (`Range`). SQL statements outside an HTML page, or an archive's magic bytes (contents not inspected) | high for SQL, medium for an archive | v1 **built** |
| `bf` | `backup-folder` | 23 folders backup plugins write to (UpdraftPlus `updraft/`, All-in-One WP Migration `ai1wm-backups/`, Duplicator `backups-dup-lite/`, WPvivid, BackupBuddy, …), reported only with directory listing, which shows the backups can be downloaded. `backup-db/` has its own finding | high; low for an empty listing | v1 **built** |
| `m` | | Media files through `?attachment_id=N` | | v1.1 |
| `tt` | | Timthumb script locations and versions | | v1.1 |

## Users (`-e u`)

A user's username is the login slug (`user_nicename`) WordPress puts in author URLs, which is usually the login name. Display names are reported as display names, never as usernames: they are attached to the account they belong to when another finder links them (the REST API, oEmbed or an author archive title), and listed as "display name only" otherwise. Sightings are merged by ID, then username, then display name.

| Check | How | Mode | Release |
|---|---|---|---|
| Author links | `/author/<username>/` links on the homepage and the 404 page (80%) | passive | v1 **built** |
| REST API | `/wp/v2/users?per_page=100`, up to 10 pages (`X-WP-TotalPages`), at the REST root the homepage links to, `/wp-json/` or `?rest_route=` when pretty permalinks are off: ID, username and display name (100%) | aggressive | v1 **built** |
| oEmbed | `author_name` and `author_url` from the homepage's oEmbed data, which exists when the homepage is a post or a page (100%) | aggressive | v1 **built** |
| Feeds | `dc:creator` in the feeds the homepage links to (passive) and `/feed/` (aggressive): display names (60%) | mixed | v1 **built** |
| Sitemaps | `/wp-sitemap-users-1.xml` and Yoast's `/author-sitemap.xml` (100%) | aggressive | v1 **built** |
| Author IDs | `/?author=N` for N in the range (default 1-10): the redirect to `/author/<username>/` (100%), or, without pretty permalinks, the archive's `author-<username> author-<N>` body class and the display name from its title (90%) | aggressive | v1 **built** |
| Login error messages | Not implemented: it submits a login attempt per username and can lock accounts | never | never |

## Authenticated inventory (`--wp-auth`)

With an administrator's Application Password, cmsrecon reads `/wp/v2/plugins` (WordPress 5.5+) and `/wp/v2/themes` (5.7+) from the REST API to get the exact slugs, versions, active and inactive plugins, and the active theme and its parent (100%). This replaces plugin and theme enumeration, in every detection mode. When the credentials are rejected or the endpoints are missing, a notice says why and the scan enumerates as usual. The Application Password is sent as HTTP Basic authentication on those two requests only, so it cannot be combined with `--http-auth` on a site that also needs that. Release: v1 **built**.

## JavaScript libraries

| Check | How | Mode | Release |
|---|---|---|---|
| Script URLs | The scripts and stylesheets the homepage and the 404 page load, including CDN URLs: the version in the path or file name (`/ajax/libs/jquery/3.4.1/`, `jquery-1.12.4.min.js`, `bootstrap@4.3.1`; 80%), or `?ver=` on a file named like the library: 80% for the copies WordPress bundles in `wp-includes/js/`, where `?ver=` is the library's version, 30% elsewhere, where it is often the plugin's or theme's version | passive | v1 **built** |
| Version banners | Up to 30 in-scope scripts are downloaded and searched for version banners (`/*! jQuery v3.6.0`, `* Bootstrap v4.1.3`; 100%) | aggressive | v1 **built** |

67 libraries are recognized without any data (jQuery, jQuery UI, jQuery Migrate, Bootstrap, Lodash, Underscore, Backbone, Moment, React, Vue, AngularJS, TinyMCE, Select2, Swiper, Slick, Owl Carousel, Magnific Popup, Font Awesome, …). The retire.js repository adds its own patterns and the vulnerabilities; its JavaScript regular expressions are converted for Go, and the few that need backreferences or lookarounds are skipped. A library's vulnerabilities are only matched when its version is known.

## Vulnerabilities

`cmsrecon update` downloads everything below into `--data-dir`. During a scan, cmsrecon only contacts the target.

| Source | Use | Release |
|---|---|---|
| Wordfence Intelligence v3 feed | Primary database: the full JSON feed, downloaded with a free API key and read record by record. Informational records are skipped | v1 **built** |
| CVE List V5 | Cross-check, and the only source without a Wordfence key. The daily release archive is read record by record and only WordPress records are kept. The slug comes from the record's package name (Patchstack), then from wordpress.org, Trac, SVN, Patchstack, WPScan and Wordfence reference URLs, then from MITRE's "the `<slug>` (aka …) plugin" wording, then from the product name; version ranges from the `affected` entries, including GitHub's `< 5.8.3` expressions and WPScan's repeated bounds, and from the description ("before 5.3.2", "up to, and including, 1.2", "5.6.1 and lower") when there are none | v1 **built** |
| WordPress.org API | The latest WordPress release, the 2,000 most installed plugins and 500 most popular themes with their latest versions, and every plugin and theme slug from SVN | v1 **built** |
| retire.js repository | Vulnerable JavaScript libraries | v1 **built** |

Vulnerabilities from the two sources are merged by CVE: a CVE List record whose CVE Wordfence already has becomes a cross-check of the Wordfence entry, under Wordfence's slug. Version ranges are compared with PHP's `version_compare` order (`dev` < `alpha` < `beta` < `RC` < release < `patch`); missing parts count as zero, so 6.4 equals 6.4.0.

Each match gets a verdict:

- **confirmed:** the detected version is inside the primary source's affected range, was detected with at least 70% confidence, no other candidate version with 40% or more is outside the range, and the sources agree;
- **likely:** inside the range, but one of those conditions fails; the note says which;
- **possible:** the version is unknown, or only the secondary source says it is affected. Listed with `-v`, counted otherwise.

Versions outside every source's range are not reported. Each match shows the affected ranges, the first fixed version above the detected one (for core, the fix on the same branch), or that no fix exists, the CVSS score, CVEs, CWE and references. Core vulnerabilities are only matched against a known version: every WordPress vulnerability ever published "may" apply to an unknown one. A notice says when the data is missing, comes from the CVE List only, or is more than 7 days old.

## Output

| Format | Release |
|---|---|
| CLI (colored, `--no-color`, `-v` for evidence) | v1 **built** |
| JSON, documented in [json-report.md](json-report.md) | v1 **built** |
| SARIF, HTML | v1.1 |
