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
cmsrecon -u https://example.com -e ap,at,cb,dbe,bf,u1-20
cmsrecon -u https://example.com --dry-run
cmsrecon scan -h
cmsrecon update -h
```

Without `cmsrecon update`, a scan still detects plugins, themes, libraries and versions with the lists built into cmsrecon, but matches no vulnerabilities and says so.

`cmsrecon update` stores its data in `--data-dir` (default: `<user cache dir>/cmsrecon`). Each source is replaced atomically and independently, so a source that fails keeps its previous data. The CVE List is a daily release of about 500 MB; it is downloaded only when a new release is out. The downloads use the `HTTPS_PROXY` environment variable or `--proxy`.

`-e` takes the same choices as WPScan's `--enumerate`: `vp`/`p`/`ap` (vulnerable, popular or all plugins), `vt`/`t`/`at` (themes), `cb` (config backups), `dbe` (database exports), `bf` (backup folders) and `u[RANGE]` (users). The default is `vp,vt,cb,dbe,bf,u`. The vulnerable lists come from the vulnerability data and the full lists from WordPress.org, both downloaded by `cmsrecon update`; without them the popular lists are used and the report says so. Plugins and themes found passively are always reported, whatever the list.

`--detection-mode` works as in WPScan: `passive` only reads pages the scan fetches anyway, `aggressive` only runs the checks that request specific paths, and `mixed` (the default) runs both. `-v` shows how each finding was detected and how confident cmsrecon is. The JSON format is documented in [docs/json-report.md](docs/json-report.md).

The default User-Agent is `cmsrecon/<version>`, so the scan is easy to find in the target's logs; `--random-user-agent` or `--user-agent` changes it. Only an explicit `--proxy` is used: `HTTP_PROXY` and similar variables are ignored.

### Exit codes

`cmsrecon scan`:

| Code | Meaning |
|---|---|
| 0 | The scan completed |
| 1 | cmsrecon failed, e.g. the report file could not be written |
| 2 | Invalid command line |
| 3 | A pre-flight check stopped the scan: unreachable, authentication required, 403, a redirect to an out-of-scope host, not WordPress, hosted on WordPress.com, or an unfinished install. The report says why |
| 130 | Interrupted with Ctrl-C; the partial report is still written |

`cmsrecon update` exits with 0 when every requested source was updated or skipped (Wordfence without a key), 1 when a source failed (the others are still updated), 2 for an invalid command line and 130 when interrupted.

## What it checks

- **Pre-flight:** reachability, redirects, WordPress detection, unfinished installs
- **Interesting findings:** exposed logs, dumps, backup folders, readme, directory listings, XML-RPC, open registration, multisite and more
- **WordPress core version** from feeds, meta tags, assets and file hashes
- **Themes and plugins:** discovery from page URLs, REST API namespaces, 160 passive signatures (130 plugins) and path brute force, versions from readmes, changelogs, `style.css` and `?ver=`, and whether each is outdated
- **JavaScript libraries:** jQuery, Bootstrap, Lodash, Moment and 60 more, from script URLs and version banners
- **Users:** REST API, oEmbed, feeds, sitemaps and author IDs
- **Exposed backups:** `wp-config.php` copies, database exports and backup plugin folders
- **Authenticated inventory:** the exact plugin and theme list via an Application Password (`--wp-auth`)
- **Vulnerabilities** for core, themes, plugins and JavaScript libraries, each with a verdict: **confirmed** (the detected version is affected), **likely** (affected, but the version is less certain or the sources disagree) or **possible** (the version is unknown; listed with `-v`)

[docs/checks.md](docs/checks.md) lists every check, the request it makes, the WPScan finder it corresponds to, and its planned release.

## Vulnerability data

| Source | Needs | Used for |
|---|---|---|
| [Wordfence Intelligence](https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/) v3 feed | A free API key from your Wordfence account (`WORDFENCE_API_KEY` or `--wordfence-key`) | Primary vulnerability database |
| [CVE List V5](https://github.com/CVEProject/cvelistV5) | Nothing | Cross-checking version ranges; the only source without a Wordfence key |
| [WordPress.org API](https://codex.wordpress.org/WordPress.org_API) | Nothing | Latest versions, popular slugs, every slug for `-e ap`/`at` |
| [retire.js](https://github.com/RetireJS/retire.js) database | Nothing | Vulnerable JavaScript libraries |

Without a Wordfence key, the vulnerabilities come from the CVE List alone. Its records name the affected plugin less reliably (cmsrecon reads the slug from package names, wordpress.org, Trac, Patchstack, WPScan and Wordfence links, and as a last resort from the product name), so expect fewer matches.

Data from each source remains subject to that provider's terms.

## Roadmap

**v1**

- [x] Command-line options and scan plan (`--dry-run`)
- [x] HTTP client: proxy, authentication, headers, throttling, scope
- [x] Pre-flight checks
- [x] Interesting findings
- [x] WordPress core version from feeds, meta tags, asset versions and readme
- [ ] WordPress core version from file hashes (hash database built from official releases)
- [x] Main theme and its version
- [x] Theme and plugin discovery with version evidence
- [x] User enumeration
- [x] Config backups, database exports, backup folders
- [x] REST API inventory (`--wp-auth`)
- [x] Vulnerability database (`cmsrecon update`) and matching
- [x] JavaScript library detection (moved up from v1.1)
- [x] CLI and JSON reports

**v1.1:** plugin and theme hash fingerprinting, closed-plugin detection, SARIF and HTML reports, media and timthumb enumeration.

## Not affiliated with WPScan

cmsrecon is an independent, clean-room project. It is not affiliated with WPScan or Automattic, and it uses no WPScan code or WPScan data files.

## License

[MIT](LICENSE)
