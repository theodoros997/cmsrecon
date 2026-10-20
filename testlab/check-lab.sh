#!/usr/bin/env bash
# Confirms the lab serves every planted finding, and none of the absent ones.
# Run it before comparing scanners, so a broken lab is not blamed on a scanner.
# Usage: testlab/check-lab.sh [base-url]    (default http://localhost:8080)
set -u
B=${1:-http://localhost:8080}
B=${B%/}
pass=0
fail=0

# fetch PATH [curl args...]: sets $code and $body
fetch() {
  local path=$1
  shift
  local out
  # Binary bodies (the zip) contain NUL bytes, which bash drops with a warning.
  { out=$(curl -s -w '\n%{http_code}' "$@" "$B$path") || out=$'\n000'; } 2>/dev/null
  code=${out##*$'\n'}
  body=${out%$'\n'*}
}

report() { # ok? name detail
  if [[ $1 == yes ]]; then
    printf 'ok    %s\n' "$2"
    pass=$((pass + 1))
  else
    printf 'FAIL  %s (%s)\n' "$2" "$3"
    fail=$((fail + 1))
  fi
}

# expect NAME PATH STATUS [BODY_REGEX]   STATUS "any" accepts every code
expect() {
  fetch "$2"
  local ok=no
  if [[ $3 == any || $code == "$3" ]] && { [[ -z ${4:-} ]] || grep -qiE -- "$4" <<<"$body"; }; then
    ok=yes
  fi
  report "$ok" "$1" "$2 -> $code"
}

# expect_absent NAME PATH BODY_REGEX: the pattern must NOT appear
expect_absent() {
  fetch "$2"
  local ok=yes
  grep -qiE -- "$3" <<<"$body" && ok=no
  report "$ok" "$1" "$2 -> $code, pattern found"
}

echo "== Core, theme, headers"
expect "Core 5.8.1 in meta generator" / 200 'content="WordPress 5\.8\.1"'
expect "Core 5.8.1 in feed generator" /feed/ 200 'wordpress\.org/\?v=5\.8\.1'
expect "Main theme twentytwenty 1.8" /wp-content/themes/twentytwenty/style.css 200 '^Version: 1\.8'

echo "== Interesting findings (should be reported)"
expect "readme.html" /readme.html 200 wordpress
expect "robots.txt entry" /robots.txt 200 old-backups
expect "XML-RPC endpoint" /xmlrpc.php 405 'POST requests only'
fetch /xmlrpc.php -X POST -H 'Content-Type: text/xml' \
  --data '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
m=$(grep -oE 'pingback\.ping|system\.multicall' <<<"$body" | sort -u | wc -l)
report "$([[ $m -eq 2 ]] && echo yes || echo no)" "XML-RPC exposes pingback.ping and system.multicall" "found $m of 2"
expect "debug.log" /wp-content/debug.log 200 'PHP Notice'
expect "backup-db folder listing" /wp-content/backup-db/ 200 'Index of'
expect "Duplicator installer log" /installer-log.txt 200 DUPLICATOR
expect "Open registration" '/wp-login.php?action=register' 200 'name="user_login"'
expect "Uploads directory listing" /wp-content/uploads/ 200 'Index of'
expect "TMM DB Migrate export" /wp-content/uploads/tmm_db_migrate/tmm_db_migrate.zip 200
expect "SQL dump in uploads" /wp-content/uploads/dump.sql 200 'CREATE TABLE'
expect "emergency.php" /emergency.php 200 password
expect "wp-cron.php reachable" /wp-cron.php 200
expect "Fantastico file list" /fantastico_fileslist.txt 200
expect "Search Replace DB script" /searchreplacedb2.php 200 interconnect
expect "mu-plugins folder exists (403)" /wp-content/mu-plugins/ 403
expect "Full path disclosure via rss.php" /wp-includes/rss.php any '/var/www/html/'

echo "== Absent (should NOT be reported)"
expect "Not multisite (wp-signup.php redirects)" /wp-signup.php 302
expect_absent "Live wp-config.php leaks nothing" /wp-config.php 'define|/var/www/html/'
expect_absent "PHP executes (version.php source hidden)" /wp-includes/version.php 'wp_version ='
expect_absent "No path from rss-functions.php (guarded)" /wp-includes/rss-functions.php '/var/www/html/'

echo "== Enumerations"
expect "wp-config.php.bak" /wp-config.php.bak 200 DB_PASSWORD
expect "wp-config.php.save" /wp-config.php.save 200 DB_PASSWORD
expect "DB export backup.sql" /backup.sql 200 'CREATE TABLE'
expect "UpdraftPlus backup folder listing" /wp-content/updraft/ 200 'Index of'
expect "Users via REST API" /wp-json/wp/v2/users 200 '"slug":"alice"'
expect "Author ID 2 redirects to its slug" '/?author=2' 301
expect "Yoast author sitemap" /author-sitemap.xml 200 '/author/bob/'
expect "REST namespaces reveal plugins" /wp-json/ 200 'contact-form-7\\/v1'
expect "Contact Form 7 readme 5.3.1" /wp-content/plugins/contact-form-7/readme.txt 200 'Stable tag: 5\.3\.1'
expect "Yoast SEO readme 15.0" /wp-content/plugins/wordpress-seo/readme.txt 200 'Stable tag: 15\.0'
expect "Duplicator readme 1.3.26 (inactive)" /wp-content/plugins/duplicator/readme.txt 200 'Stable tag: 1\.3\.26'

echo
echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
