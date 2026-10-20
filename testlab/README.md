# Test lab

A deliberately outdated and misconfigured WordPress for testing cmsrecon and comparing it with WPScan. [EXPECTED.md](EXPECTED.md) lists what a correct scan reports.

> **Local use only.** The lab runs plugins with published vulnerabilities. It is published on `127.0.0.1:8080` only; never expose it to a network. The planted PHP scripts are harmless placeholders that print text and do nothing else.

## Requirements

Docker Desktop (or any Docker engine with Compose v2). The first start downloads about 1 GB of images and the plugins from WordPress.org.

## Start

From the repository root:

```bash
docker compose -f testlab/docker-compose.yml up -d
```

```bash
docker compose -f testlab/docker-compose.yml wait seed
```

The second command returns once seeding has finished (about a minute the first time). The site is at <http://localhost:8080/>.

Check that the lab serves every planted finding (Git Bash, WSL or Linux):

```bash
bash testlab/check-lab.sh
```

## Scan it

With cmsrecon:

```bash
go build -o cmsrecon ./cmd/cmsrecon
```

```bash
./cmsrecon -u http://localhost:8080 -e p,t,cb,dbe,bf,u1-5
```

Until the scan engine is merged, add `--dry-run` to see the scan plan instead.

With WPScan, for comparison (Kali WSL reaches the lab on `localhost`):

```bash
wpscan --url http://localhost:8080/ --clear-cache -e p,t,cb,dbe,bf,u1-5 --plugins-detection mixed
```

Without an API token, WPScan 4.x aborts on `-e vp` and `-e vt`, so use the popular lists. Use `--clear-cache` after changing the lab: WPScan caches responses for 10 minutes.

## Stop or reset

Stop the lab and keep its data:

```bash
docker compose -f testlab/docker-compose.yml down
```

Delete everything, including the database and site files:

```bash
docker compose -f testlab/docker-compose.yml down -v
```

## Files

| File | Purpose |
|---|---|
| `docker-compose.yml` | WordPress 5.8.1 (PHP 7.4, Apache), MariaDB, and a one-shot WP-CLI seeder |
| `seed.sh` | Installs WordPress, users, old plugins and the planted files; safe to rerun |
| `php-lab.ini` | Turns on `display_errors` so path disclosure can be tested |
| `check-lab.sh` | Confirms the lab serves every expected finding |
| `EXPECTED.md` | Ground truth and the WPScan baseline |
