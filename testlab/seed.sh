#!/bin/sh
# Seeds the cmsrecon lab with known findings. Everything planted here is
# listed in EXPECTED.md. Safe to run again.
set -eu
cd /var/www/html

echo "Waiting for WordPress files and the database..."
until [ -f wp-config.php ] && wp db query "SELECT 1" >/dev/null 2>&1; do
  sleep 3
done

# Random passwords that are never printed: the lab is scanned, not logged into.
randpw() { head -c 24 /dev/urandom | base64; }

if ! wp core is-installed 2>/dev/null; then
  wp core install --url=http://localhost:8080 --title="cmsrecon lab" \
    --admin_user=labadmin --admin_email=labadmin@lab.test \
    --admin_password="$(randpw)" --skip-email
fi

# Users with published posts, so they show up in REST, feeds and sitemaps.
wp user get alice >/dev/null 2>&1 ||
  wp user create alice alice@lab.test --role=author --display_name="Alice Author" --porcelain
wp user get bob >/dev/null 2>&1 ||
  wp user create bob bob@lab.test --role=editor --display_name="Bob Editor" --porcelain
for u in alice bob; do
  id=$(wp user get "$u" --field=ID)
  if [ "$(wp post list --author="$id" --post_type=post --format=count)" -eq 0 ]; then
    wp post create --post_type=post --post_status=publish --post_author="$id" \
      --post_title="Post by $u" --post_content="Lab content." --porcelain
  fi
done

wp option update users_can_register 1
wp rewrite structure '/%postname%/' --hard

# Outdated plugins with published CVEs. Duplicator stays inactive, so only
# aggressive detection (readme.txt) can find it.
wp plugin install contact-form-7 --version=5.3.1 --force --activate
wp plugin install wordpress-seo --version=15.0 --force --activate
wp plugin install duplicator --version=1.3.26 --force
wp theme activate twentytwenty

# Planted exposures. The PHP files are harmless placeholders that only print
# the text scanners look for.
mkdir -p wp-content/uploads/tmm_db_migrate wp-content/backup-db \
  wp-content/updraft wp-content/mu-plugins

cat > robots.txt <<'EOF'
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
Disallow: /old-backups/
EOF

echo "[20-Oct-2026 08:00:00 UTC] PHP Notice:  Undefined index: lab in /var/www/html/wp-content/plugins/contact-form-7/includes/lab.php on line 42" \
  >> wp-content/debug.log

cp wp-config.php wp-config.php.bak
cp wp-config.php wp-config.php.save

sql='CREATE TABLE `wp_lab` (`id` int);
INSERT INTO `wp_lab` VALUES (1);'
printf '%s\n' "$sql" > backup.sql
printf '%s\n' "$sql" > wp-content/uploads/dump.sql
printf '%s\n' "$sql" > wp-content/backup-db/wordpress_lab.sql
printf '%s\n' "$sql" > wp-content/updraft/backup_lab-db.sql

# 22-byte empty zip (end-of-central-directory record only).
printf 'PK\005\006\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000' \
  > wp-content/uploads/tmm_db_migrate/tmm_db_migrate.zip

printf 'DUPLICATOR-LITE INSTALL-LOG\nSTEP-1 START @ 08:00:00\n' > installer-log.txt
printf 'wp-config.php\nwp-login.php\n' > fantastico_fileslist.txt
echo '<?php echo "Emergency password reset (cmsrecon lab placeholder, does nothing)";' > emergency.php
echo '<?php echo "Search and Replace DB v2 by interconnect/it (cmsrecon lab placeholder, does nothing)";' > searchreplacedb2.php
echo '<?php // cmsrecon lab must-use plugin' > wp-content/mu-plugins/lab-mu.php

# The image disables directory listing globally; re-enable it where a
# misconfigured site would have it. mu-plugins/ stays 403 on purpose.
for d in wp-content/uploads wp-content/backup-db wp-content/updraft; do
  echo 'Options +Indexes' > "$d/.htaccess"
done

# Plugins add rewrite rules (e.g. Yoast sitemaps) only after a flush.
wp rewrite flush --hard

echo "Lab ready at http://localhost:8080/"
