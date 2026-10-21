# cmsrecon

WordPress reconnaissance for authorized security assessments. cmsrecon runs the same kind of checks as WPScan, with vulnerability matching that needs no paid API subscription.

> **Status: v1 feature-complete, not yet released.** `cmsrecon scan` runs the pre-flight checks, the interesting findings, core version detection, theme, plugin, JavaScript library and user enumeration, the backup searches, and matches everything it finds against offline vulnerability data that `cmsrecon update` downloads. See the [roadmap](#roadmap).

## Why

WPScan's checks are free, but its vulnerability data comes from an API with a small free daily quota. Without a token, it finds plugins but reports no vulnerabilities. cmsrecon:

- **Matches vulnerabilities offline** against free data (Wordfence Intelligence and the CVE List). There is no per-request quota, and a scan only contacts the target.
- **Shows its evidence for every version** it detects: which signals agreed and how confident it is.
- **Separates confirmed vulnerabilities from guesses.** When a version is unknown, cmsrecon says so instead of listing every vulnerability the plugin has ever had.

cmsrecon is reconnaissance only. It never guesses passwords, submits login forms or exploits anything. **Only scan sites you are authorized to test.**

## Build

Requires Go 1.26 or later.

```bash
git clone https://github.com/theodoros997/cmsrecon.git
cd cmsrecon
go build -o cmsrecon ./cmd/cmsrecon
```

## Usage

Download the vulnerability data first, and again whenever you want fresh data:

```bash
export WORDFENCE_API_KEY=...   # free, from your Wordfence account; optional
cmsrecon update
```

Then scan:

```bash
cmsrecon -u https://example.com
cmsrecon scan https://example.com -v --proxy http://127.0.0.1:8080
cmsrecon scan https://example.com --detection-mode passive -f json -o report.json
cmsrecon -u https://example.com --plugins-detection mixed -e vp,vt   # also brute-force plugin folders
cmsrecon -u https://example.com --plugins-list akismet,elementor      # also check these plugins, and no others
cmsrecon -u https://example.com --stealthy                            # browser User-Agent, passive detection
cmsrecon -u https://example.com --possible                            # list every possible vulnerability
cmsrecon -u https://example.com -e vp,vt,u,tt,m                       # also TimThumb scripts and uploaded files
cmsrecon -u https://example.com --max-scan-duration 15m               # stop after 15 minutes, report what was found
cmsrecon -u https://example.com --dry-run
cmsrecon scan -h
cmsrecon update -h
```

Without `cmsrecon update`, a scan still detects plugins, themes, libraries and versions with the lists built into cmsrecon, but matches no vulnerabilities and says so.

`cmsrecon update` stores its data in `--data-dir` (default: `<user cache dir>/cmsrecon`). Each source is replaced atomically and independently, so a source that fails keeps its previous data. The CVE List is a daily release of about 500 MB; it is downloaded only when a new release is out. The downloads use the `HTTPS_PROXY` environment variable or `--proxy`.

### How plugins and themes are found

By default cmsrecon finds the plugins and themes the site actually uses, then matches vulnerabilities against those, in a few dozen requests. A default scan of a typical site sends about 250 requests in total, most of them for the backup-file checks.

- **Pages:** it reads the homepage, a 404 page and up to 10 more pages, one of each kind (`--crawl N` changes the number). Pages are picked from the sitemaps, one per post type such as a page, a post or a product, and from the homepage's links, one per section. The login page is always read. Only links are followed: nothing is guessed, and links with side effects (add to cart, log out) are skipped. Different templates load different plugins: a shop page shows the payment plugins, a contact page the form plugin, the login page the security and captcha plugins.
- **Asset links and signatures:** in every page read, it looks for `/wp-content/plugins/<name>/` and `/themes/<name>/` links, 160 signatures (HTML comments, generator tags, JavaScript settings, CSS classes, headers, cache folders) and the version hints in `?ver=`.
- **REST API and sitemaps:** the REST API index names the plugins that register routes (`yoast/v1` is Yoast SEO), and the sitemaps' post types name more (`product` is WooCommerce).
- **Directory listings:** one request each to `/wp-content/plugins/` and `/wp-content/themes/`. On a misconfigured server, these list everything installed, inactive plugins included.
- **Versions:** each plugin found gets its `readme.txt` read for its name and version, then its changelog, then the banner at the top of one of its own scripts or stylesheets the pages load (`/*! elementor - v3.5.0 */`). Each theme gets its `style.css` read.
- **Nothing made up:** a name is only a plugin or theme if it looks like a WordPress slug, so template placeholders such as `${slug}` or `%s` in a page's JavaScript are ignored. A plugin known only from a link is checked by requesting the linked file, and dropped when the file is gone (a link left in an old post to a removed plugin). A plugin known only from a hint (a REST namespace or a generator tag that names it) is kept only when its folder or readme answers. The location printed is a folder the site linked to or answered for, never a guessed path.

This is what WPScan does by default (its `--plugins-detection` is `passive`), plus the crawl, the REST API, the sitemaps and the listings, which WPScan does not read.

Inactive plugins load nothing on the pages, so only brute force finds them: `--plugins-detection mixed` (or `--themes-detection mixed`) also requests the folder of every plugin on the `-e` list, one request each. That is thousands of requests: the vulnerable list holds about 17,000 plugins after `cmsrecon update`. As in WPScan, `aggressive` brute-forces without the discovery.

To check only a few plugins or themes you suspect, name them: `--plugins-list akismet,elementor` or `--themes-list astra` (a comma-separated list, or a file with one slug per line and `#` comments). The scan then requests those folders and no others, whatever `--plugins-detection` says. When the site moved its folders and detection misses it, `--wp-content-dir` and `--wp-plugins-dir` set them (a path relative to the target, or a full URL).

For each plugin and theme found, the report says when WordPress.org last saw an update and warns when that was more than two years ago. Outside passive mode it also requests the item's folder, warning when the server lists its files, and its `error_log`, a PHP error log some hosts write next to the failing script that can disclose paths and data. That is two requests per item.

`-e` takes the same choices as WPScan's `--enumerate`: `vp`/`p`/`ap` (vulnerable, popular or all plugins), `vt`/`t`/`at` (themes), `tt` (TimThumb scripts in the folders of the themes and plugins found), `cb` (config backups), `dbe` (database exports), `bf` (backup folders), `u[RANGE]` (users) and `m[RANGE]` (uploaded files: the REST API lists them a hundred at a time, and only when it is closed are the attachment IDs of the range requested one by one; default `m1-100`). The default is `vp,vt,cb,dbe,bf,u`; `tt` and `m` are opt-in because they cost more requests. The plugin and theme lists only matter with brute force. They come from `cmsrecon update`: the vulnerable lists from the vulnerability data, the full lists from WordPress.org. Without them the popular lists are used and the report says so. For the quietest scan, `-e vp,vt,u` skips the backup-file guesses and `--detection-mode passive` reads only the homepage, the 404 page and its feeds.

`--detection-mode` works as in WPScan: `passive` only reads pages the scan fetches anyway, `aggressive` only runs the checks that request specific paths, and `mixed` (the default) runs both. `-v` shows how each finding was detected and how confident cmsrecon is. The JSON format is documented in [docs/json-report.md](docs/json-report.md).

The default User-Agent is `cmsrecon/<version>`, so the scan is easy to find in the target's logs; `--random-user-agent` or `--user-agent` changes it. `--stealthy`, as in WPScan, is `--random-user-agent --detection-mode passive`. Only an explicit `--proxy` is used: `HTTP_PROXY` and similar variables are ignored.

### Reading the vulnerabilities

Each vulnerability has a verdict:

- **confirmed:** the detected version is in the affected range, and the version is certain.
- **likely:** the version is in the range but less certain, or the sources disagree. Also used when the version is unknown but every release up to the latest is affected, since then any installed version is.
- **possible:** the version is unknown, or only a secondary source puts it in the range.

A plugin with no known version "may" be affected by every vulnerability ever published for it, often dozens. Listing them all buries the ones that matter, so the possible ones are summed up in one line per plugin or theme:

```
[+] wpforms-lite (confidence 80%)
    | Version: unknown (the latest is 1.9.2)
    | Possible vulnerabilities: 23 (2 critical, 6 high), all fixed in 1.8.9 (not listed: the version is unknown; --possible lists them)
```

`--possible` lists them in full, in the CLI and in the JSON report. The JSON report always has the summary in `possible_vulnerabilities`.

### Public exploits and proofs of concept

After `cmsrecon update`, each vulnerability lists the public exploits for its CVEs, most trustworthy first: Metasploit modules (with the module to `use`), Exploit-DB entries (marked when Exploit-DB verified them), Nuclei templates (to confirm the finding with `nuclei -id CVE-…`), Exploit-DB and Packet Storm links from the advisory, and up to five GitHub repositories from PoC-in-GitHub:

```
|   [CRITICAL] WordPress File Manager 6.0-6.8 - Unauthenticated Remote Code Execution
|     confirmed - CVE-2020-25213 - CVSS 9.8 - fixed in 6.9
|     Public exploits: 1 Metasploit module, 2 Exploit-DB entries (1 verified), 1 Nuclei template, 5 GitHub repositories (unreviewed)
|       Metasploit: exploit/multi/http/wp_file_manager_rce - https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/http/wp_file_manager_rce.rb
|       Exploit-DB, verified: WP-file-manager v6.9 - Unauthenticated Arbitrary File Upload leading to RCE - https://www.exploit-db.com/exploits/51224
|       Exploit-DB: WordPress Plugin Wp-FileManager 6.8 - RCE - https://www.exploit-db.com/exploits/49178
|       6 more: -v lists them
```

These are links only: cmsrecon never downloads or runs exploit code. GitHub repositories are unreviewed, and some fake proofs of concept have carried malware, so read any code before running it, and only against systems you are authorized to test.

### Exit codes

`cmsrecon scan`:

| Code | Meaning |
|---|---|
| 0 | The scan completed |
| 1 | cmsrecon failed, e.g. the report file could not be written |
| 2 | Invalid command line |
| 3 | A pre-flight check stopped the scan: unreachable, authentication required, 403, a redirect to an out-of-scope host, not WordPress, hosted on WordPress.com, or an unfinished install. The report says why |
| 4 | The scan reached `--max-scan-duration`; the partial report is still written |
| 5 | The scan completed and found confirmed or likely vulnerabilities (possible ones do not count), as WPScan's exit code 5 |
| 130 | Interrupted with Ctrl-C; the partial report is still written |

`cmsrecon update` exits with 0 when every requested source was updated or skipped (Wordfence without a key), 1 when a source failed (the others are still updated), 2 for an invalid command line and 130 when interrupted.

## What it checks

- **Pre-flight:** reachability, redirects, WordPress detection, unfinished installs
- **Interesting findings:** exposed logs, dumps, backup folders, readme, directory listings, XML-RPC, open registration, multisite and more
- **WordPress core version** from feeds, meta tags, assets, `readme.html` and the hashes of its static files (compared with WordPress.org's checksums of every release since 3.0; a handful of requests)
- **Themes and plugins:** discovery from a small crawl, sitemaps, REST API namespaces, 160 passive signatures (130 plugins) and directory listings, with optional brute force; versions from readmes, changelogs, file banners, `style.css` and `?ver=`, whether each is outdated or abandoned, and whether its folder lists files or exposes an error log
- **JavaScript libraries:** jQuery, Bootstrap, Lodash, Moment and 60 more, from script URLs and version banners
- **Users:** REST API, oEmbed, feeds, sitemaps and author IDs
- **TimThumb** (`-e tt`): the vulnerable image script old themes and plugins bundled, with its version
- **Media** (`-e m`): uploaded files from the REST API or attachment IDs, documents and archives listed first
- **Exposed backups:** `wp-config.php` copies, database exports and backup plugin folders
- **Authenticated inventory:** the exact plugin and theme list via an Application Password (`--wp-auth`)
- **Vulnerabilities** for core, themes, plugins, JavaScript libraries and TimThumb, with links to public exploits and proofs of concept, each with a verdict: **confirmed** (the detected version is affected), **likely** (affected, but the version is less certain or the sources disagree) or **possible** (the version is unknown; summed up per plugin, listed with `--possible`)

[docs/checks.md](docs/checks.md) lists every check, the request it makes, the WPScan finder it corresponds to, and its planned release. Its last section compares cmsrecon with WPScan feature by feature.

## Vulnerability data

| Source | Needs | Used for |
|---|---|---|
| [Wordfence Intelligence](https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/) v3 feed | A free API key from your Wordfence account (`WORDFENCE_API_KEY` or `--wordfence-key`) | Primary vulnerability database |
| [CVE List V5](https://github.com/CVEProject/cvelistV5) | Nothing | Cross-checking version ranges; the only source without a Wordfence key |
| [WordPress.org API](https://codex.wordpress.org/WordPress.org_API) | Nothing | Latest versions, popular slugs, every slug for `-e ap`/`at` |
| [retire.js](https://github.com/RetireJS/retire.js) database | Nothing | Vulnerable JavaScript libraries |
| [Exploit-DB](https://gitlab.com/exploit-database/exploitdb), [Metasploit](https://github.com/rapid7/metasploit-framework), [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates), [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) | Nothing | Public exploits and proofs of concept by CVE (`exploits`, about 30 MB) |
| [WordPress.org checksums](https://codex.wordpress.org/WordPress.org_API#Checksum) | Nothing | Core version from file hashes (`corehashes`). The first update asks for every release since 3.0, several hundred small requests; later ones only for new releases |

Without a Wordfence key, the vulnerabilities come from the CVE List alone. Its records name the affected plugin less reliably (cmsrecon reads the slug from package names, wordpress.org, Trac, Patchstack, WPScan and Wordfence links, and as a last resort from the product name), so expect fewer matches.

Data from each source remains subject to that provider's terms.

## Roadmap

**v1**

- [x] Command-line options and scan plan (`--dry-run`)
- [x] HTTP client: proxy, authentication, headers, throttling, scope
- [x] Pre-flight checks
- [x] Interesting findings
- [x] WordPress core version from feeds, meta tags, asset versions and readme
- [x] WordPress core version from file hashes (WordPress.org's checksums of every release)
- [x] Main theme and its version
- [x] Theme and plugin discovery with version evidence
- [x] User enumeration
- [x] Config backups, database exports, backup folders
- [x] REST API inventory (`--wp-auth`)
- [x] Vulnerability database (`cmsrecon update`) and matching
- [x] JavaScript library detection (moved up from v1.1)
- [x] TimThumb and media enumeration, `--max-scan-duration` (moved up from v1.1)
- [x] Links to public exploits and proofs of concept
- [x] CLI and JSON reports

**v1.1:** plugin and theme hash fingerprinting, closed-plugin detection, SARIF and HTML reports.

## Not affiliated with WPScan

cmsrecon is an independent, clean-room project. It is not affiliated with WPScan or Automattic, and it uses no WPScan code or WPScan data files.

## License

[MIT](LICENSE)
