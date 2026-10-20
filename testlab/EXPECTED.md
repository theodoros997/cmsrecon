# Expected findings

What a correct scan of the lab reports, and what it must not report. `check-lab.sh` confirms the lab serves all of this; use these tables to score a scanner's output.

## Should be reported

### Target

| Finding | Evidence |
|---|---|
| WordPress 5.8.1 | Meta generator, feed `<generator>`, `?ver=` on core assets |
| Main theme `twentytwenty` 1.8 | Homepage stylesheet, `Version:` in its `style.css` |
| Installed themes | `twentynineteen`, `twentytwenty`, `twentytwentyone` (bundled) |
| Headers | `Server: Apache/2.4.51 (Debian)`, `X-Powered-By: PHP/7.4.25` |

### Interesting findings (17)

| Finding | Path |
|---|---|
| readme | `/readme.html` |
| robots.txt with an interesting entry | `/robots.txt` (`Disallow: /old-backups/`) |
| XML-RPC enabled, `pingback.ping` and `system.multicall` exposed | `/xmlrpc.php` |
| Debug log | `/wp-content/debug.log` |
| Full path disclosure | `/wp-includes/rss.php`, `/wp-includes/template-loader.php`, the theme's `functions.php`, and others. **Not** `/wp-includes/rss-functions.php`, which has an `ABSPATH` guard in 5.8.1 |
| Backup DB folder, listing enabled | `/wp-content/backup-db/` |
| Duplicator installer log | `/installer-log.txt` |
| Must-use plugins folder (403, no listing) | `/wp-content/mu-plugins/` |
| Open registration | `/wp-login.php?action=register` |
| Uploads directory listing | `/wp-content/uploads/` |
| TMM DB Migrate export (an empty 22-byte zip, so "empty archive" is the accurate report) | `/wp-content/uploads/tmm_db_migrate/tmm_db_migrate.zip` |
| SQL dump in uploads | `/wp-content/uploads/dump.sql` |
| Emergency password reset script | `/emergency.php` (harmless placeholder) |
| WP-Cron reachable | `/wp-cron.php` |
| Fantastico file list | `/fantastico_fileslist.txt` |
| Search Replace DB script | `/searchreplacedb2.php` (harmless placeholder) |
| Interesting headers | see above |

### Plugins

| Plugin | Version | State | How a scanner can find it |
|---|---|---|---|
| `contact-form-7` | 5.3.1 | active | `?ver=5.3.1` on its assets, `readme.txt`, REST namespace `contact-form-7/v1` |
| `wordpress-seo` (Yoast) | 15.0 | active | "Yoast SEO plugin v15.0" HTML comment, `readme.txt`, REST namespace `yoast/v1` |
| `duplicator` | 1.3.26 | inactive | Aggressive only: `readme.txt` |
| `akismet` | 4.1.12 | inactive | Folder exists; its `.htaccess` blocks `readme.txt`, so "version unknown" is correct until hash fingerprinting (v1.1) |

Hello Dolly (`/wp-content/plugins/hello.php`, a single-file plugin) is optional: few scanners look for single-file plugins.

### Exposed files and folders

| Finding | Path |
|---|---|
| Config backups | `/wp-config.php.bak`, `/wp-config.php.save` (contain the lab's DB credentials) |
| Database exports | `/backup.sql`, `/wp-content/uploads/dump.sql` |
| Backup folders with listing | `/wp-content/updraft/`, `/wp-content/backup-db/` |

### Users

| Username | ID | Display name | Sources |
|---|---|---|---|
| `labadmin` | 1 | labadmin | REST API, `?author=1`, feed, Yoast author sitemap |
| `alice` | 2 | Alice Author | same |
| `bob` | 3 | Bob Editor | same |

Display names are not usernames and should not be reported as such.

### Vulnerabilities (once matching lands)

| Component | Example CVE | Fixed in |
|---|---|---|
| WordPress 5.8.1 | CVE-2022-21661 (SQL injection via `WP_Query`) | 5.8.3 |
| Contact Form 7 5.3.1 | CVE-2020-35489 (unrestricted file upload) | 5.3.2 |
| Duplicator 1.3.26 | CVE-2020-11738 (arbitrary file download) | 1.3.28 |

These are examples; each component has more published vulnerabilities.

## Should NOT be reported

| Not present | Why a scanner might wrongly report it |
|---|---|
| Multisite | `/wp-signup.php` exists but redirects to `wp-login.php?action=register` |
| PHP not executed | `/wp-includes/version.php` executes and returns an empty page |
| Full path disclosure via `rss-functions.php` | Guarded by `ABSPATH` in 5.8.1 |
| Live `wp-config.php` as a config backup | It executes and returns nothing |
| Display names as usernames | They appear in the feed's `dc:creator` |

## WPScan baseline

WPScan 4.1.0 from Kali WSL, no API token, run on 2026-10-20:

```bash
wpscan --url http://localhost:8080/ --clear-cache -e p,t,cb,dbe,bf,u1-5 \
  --plugins-detection mixed --plugins-version-detection mixed -t 20
```

`-e vp` or `-e vt` (WPScan's default) aborts the whole scan without an API token, so the popular lists were used instead. 2,210 requests in 20 seconds.

| Area | Expected | WPScan |
|---|---|---|
| Interesting findings | 17 | 16: missed full path disclosure (it only tries the guarded `rss-functions.php`) |
| Absent items | 0 reported | 0: multisite and PHP-disabled correctly not reported |
| Core version | 5.8.1 | 5.8.1, marked insecure, no vulnerabilities listed |
| Main theme and themes | twentytwenty 1.8, 3 themes | correct |
| Plugins | 4 (3 with versions) | 4: versions for Contact Form 7, Yoast and Duplicator; Akismet without a version |
| Config backups | 2 | 2. Earlier, when a lab misconfiguration made `wp-config.php` print a PHP notice containing "defined", WPScan also reported the live `wp-config.php` as a backup |
| Database exports | 2 | 2 |
| Backup folders | 2 | 2 |
| Users | 3 | 3, plus the 2 display names reported as extra users |
| Vulnerabilities | 3+ CVEs | none without an API token |
