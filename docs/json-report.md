# JSON report

`cmsrecon scan -f json` writes one JSON object, to stdout or to the file given with `-o`. This page describes every field.

**Stability.** `schema_version` is `1`. Fields are never removed, renamed or given a new meaning without bumping it; new fields can appear at any time, so ignore the ones you do not know. Finding IDs, stop codes, severities and modes are stable identifiers. The `method`, `title`, `message` and `entries` strings are written for people and may be reworded, so do not match on them.

Lists are always arrays (`[]` when empty), never `null`. Objects documented as "or null" are `null` when the scan did not get that far or found nothing.

## Top level

| Field | Type | Description |
|---|---|---|
| `schema_version` | integer | Version of this format, currently `1` |
| `tool` | object | `name` (`"cmsrecon"`), `version`, `user_agent` (the User-Agent the scan sent) |
| `target` | [Target](#target) | What was scanned |
| `detection_mode` | string | `passive`, `mixed` or `aggressive` |
| `started_at`, `finished_at` | string | RFC 3339 UTC timestamps, second precision |
| `status` | string | `completed`, `stopped` (a pre-flight check stopped the scan, see `stop`) or `interrupted` (Ctrl-C; results are partial) |
| `stop` | [Stop](#stop) or null | Why the scan stopped early |
| `web_server` | object or null | `header`: the homepage's `Server` header (empty when absent); `family`: `apache`, `nginx`, `iis` or `unknown` |
| `wordpress` | object or null | `detected` (boolean; `false` only when `--force` scanned anyway), `content_url` (the wp-content directory, omitted when it was not seen), `evidence` ([Evidence](#evidence) list) |
| `interesting_findings` | [Finding](#finding) list | In the order of the table below |
| `version` | [Version](#version) or null | WordPress core version; null when the scan stopped first |
| `main_theme` | [Theme](#theme) or null | Null when not detected, in aggressive mode (its signals are passive) or when the scan stopped first |
| `notices` | string list | Things the user should know, e.g. enumerations that are not implemented yet |
| `errors` | list | Requests that failed (`url`, `error`). A failed request does not stop the scan; the check that needed it reports nothing |
| `stats` | object | `requests`, `bytes_sent`, `bytes_received` (measured on the network connections, so including headers, TLS and proxy overhead) and `elapsed_seconds` |

## Target

| Field | Type | Description |
|---|---|---|
| `url` | string | The URL from the command line, normalized (scheme added, path ending in `/`) |
| `effective_url` | string | The URL scanned after followed redirects |
| `redirects` | list | Homepage redirects seen during pre-flight: `from`, `to`, `status` (HTTP code) and `followed` (boolean) |
| `scope` | string list | In-scope hosts; `*.example.com` entries cover subdomains |

## Stop

| Field | Type | Description |
|---|---|---|
| `code` | string | One of the codes below |
| `message` | string | What happened |
| `hint` | string | What to do about it; omitted when there is nothing to suggest |

| Code | Meaning |
|---|---|
| `connection_failed` | The homepage could not be fetched (DNS, TCP, TLS or timeout error) |
| `http_auth_required` | HTTP 401; use `--http-auth`, or the credentials given were rejected |
| `proxy_auth_required` | HTTP 407 from the proxy |
| `forbidden` | HTTP 403 on the homepage without `--force` |
| `redirect` | The homepage redirects somewhere other than the same URL on the other scheme, without `--follow-redirect`, or redirects in a loop |
| `not_wordpress` | No WordPress signal, without `--force` |
| `wordpress_com` | The site is hosted on WordPress.com |
| `unfinished_install` | The homepage redirects to the installer; the `unfinished-install` finding has the details |

## Evidence

One signal behind a finding, version or theme.

| Field | Type | Description |
|---|---|---|
| `method` | string | How it was found, e.g. `Meta generator`, `X-Pingback header`, `Direct access` |
| `mode` | string | `passive` (read from a page the scan fetches anyway) or `aggressive` (a request to a specific path) |
| `url` | string | The page or file the signal came from; omitted when not applicable |
| `value` | string | What the signal said, e.g. a version number or header value; omitted when empty |
| `confidence` | integer | 0-100 |

## Finding

| Field | Type | Description |
|---|---|---|
| `id` | string | Stable identifier from the table below |
| `title` | string | One-line summary |
| `severity` | string | `info`, `low`, `medium`, `high` or `critical` |
| `url` | string | Where it is |
| `confidence` | integer | 0-100. With several signals they are combined as independent probabilities: 60% and 80% give 92% |
| `entries` | string list | Interesting details: robots.txt rules, header lines, listed files, … |
| `data` | object | Machine-readable details, only for the IDs that list keys below; omitted otherwise |
| `references` | string list | Further reading |
| `evidence` | [Evidence](#evidence) list | How it was detected, strongest first |

| ID | Severity | `data` keys |
|---|---|---|
| `unfinished-install` | critical | |
| `headers` | info | |
| `robots-txt` | info | |
| `xmlrpc` | info; low when `pingback.ping` or `system.multicall` is exposed | `methods` (integer), `pingback_ping`, `system_multicall` (booleans); present only when `system.listMethods` returned a method list |
| `readme` | info | |
| `debug-log` | high | |
| `full-path-disclosure` | low | `path` (string) |
| `backup-db` | medium; high with directory listing | |
| `duplicator-installer-log` | medium | |
| `multisite` | info | |
| `mu-plugins` | info; low with directory listing | |
| `registration` | low | |
| `upload-directory-listing` | medium | |
| `tmm-db-migrate` | high | |
| `upload-sql-dump` | high | |
| `emergency-password-reset` | high | |
| `wp-cron` | info | |
| `php-disabled` | high | `wp_version` (string, from the leaked `version.php`) |
| `fantastico-fileslist` | medium | |
| `search-replace-db2` | high | |

[checks.md](checks.md#interesting-findings) describes what each check requests and matches.

## Version

| Field | Type | Description |
|---|---|---|
| `number` | string | The detected version; empty when unknown |
| `confidence` | integer | Combined confidence of `number`; 0 when unknown |
| `candidates` | list | Every version number seen (`number`, `confidence`), most likely first. The first one is `number` when its confidence is at least 40 |
| `evidence` | [Evidence](#evidence) list | Every signal, with the version it reported in `value` |

## Theme

| Field | Type | Description |
|---|---|---|
| `slug` | string | Directory name under `themes/` |
| `location` | string | The theme directory URL |
| `style_url` | string | Its `style.css` |
| `confidence` | integer | Combined confidence that this is the active theme |
| `name`, `theme_uri`, `author`, `author_uri` | string | From the `style.css` header; omitted when not read (passive mode) or empty |
| `version` | [Version](#version) | The theme version; `number` is empty when unknown |
| `parent` | Theme | The parent of a child theme; omitted otherwise. Its own `parent` is always omitted |
| `evidence` | [Evidence](#evidence) list | Why this theme was chosen |

## Example

Abridged output of a mixed-mode scan:

```json
{
  "schema_version": 1,
  "tool": { "name": "cmsrecon", "version": "v0.1.0", "user_agent": "cmsrecon/v0.1.0" },
  "target": {
    "url": "http://blog.example.com/",
    "effective_url": "https://blog.example.com/",
    "redirects": [
      { "from": "http://blog.example.com/", "to": "https://blog.example.com/", "status": 301, "followed": true }
    ],
    "scope": ["blog.example.com"]
  },
  "detection_mode": "mixed",
  "started_at": "2026-10-20T10:00:00Z",
  "finished_at": "2026-10-20T10:00:04Z",
  "status": "completed",
  "stop": null,
  "web_server": { "header": "nginx/1.25.3", "family": "nginx" },
  "wordpress": {
    "detected": true,
    "content_url": "https://blog.example.com/wp-content/",
    "evidence": [
      { "method": "Meta generator", "mode": "passive", "url": "https://blog.example.com/", "value": "WordPress 6.4.2", "confidence": 100 }
    ]
  },
  "interesting_findings": [
    {
      "id": "xmlrpc",
      "title": "XML-RPC is enabled",
      "severity": "low",
      "url": "https://blog.example.com/xmlrpc.php",
      "confidence": 100,
      "entries": ["system.listMethods: 80 methods exposed", "pingback.ping is exposed: …"],
      "data": { "methods": 80, "pingback_ping": true, "system_multicall": true },
      "references": ["https://codex.wordpress.org/XML-RPC_Pingback_API"],
      "evidence": [
        { "method": "system.listMethods", "mode": "aggressive", "url": "https://blog.example.com/xmlrpc.php", "value": "80 methods", "confidence": 100 }
      ]
    }
  ],
  "version": {
    "number": "6.4.2",
    "confidence": 92,
    "candidates": [{ "number": "6.4.2", "confidence": 92 }],
    "evidence": [
      { "method": "RSS feed generator", "mode": "passive", "url": "https://blog.example.com/feed/", "value": "6.4.2", "confidence": 80 },
      { "method": "Meta generator", "mode": "passive", "url": "https://blog.example.com/", "value": "6.4.2", "confidence": 60 }
    ]
  },
  "main_theme": {
    "slug": "twentytwentyfour",
    "location": "https://blog.example.com/wp-content/themes/twentytwentyfour/",
    "style_url": "https://blog.example.com/wp-content/themes/twentytwentyfour/style.css",
    "confidence": 64,
    "name": "Twenty Twenty-Four",
    "author": "the WordPress team",
    "version": {
      "number": "1.0",
      "confidence": 80,
      "candidates": [{ "number": "1.0", "confidence": 80 }],
      "evidence": [
        { "method": "style.css Version header", "mode": "aggressive", "url": "https://blog.example.com/wp-content/themes/twentytwentyfour/style.css", "value": "1.0", "confidence": 80 }
      ]
    },
    "evidence": [
      { "method": "Theme URLs in the homepage", "mode": "passive", "url": "https://blog.example.com/", "value": "twentytwentyfour", "confidence": 40 },
      { "method": "Theme URLs in the 404 page", "mode": "passive", "url": "https://blog.example.com/3f9c0a1b2c4d5e6f/", "value": "twentytwentyfour", "confidence": 40 }
    ]
  },
  "notices": ["Not implemented yet, skipped: vulnerable plugins (vp), …"],
  "errors": [],
  "stats": { "requests": 41, "bytes_sent": 10240, "bytes_received": 352000, "elapsed_seconds": 3.912 }
}
```
