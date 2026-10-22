# Stock WordPress 6.x on PINNED PRE-PATCH php 8.2.34 (x86_64 native).
# CVE-2026-109618/619 were fixed in 8.2.35; the floating php:8.2 tag now
# ships the patched release, so the PHP base is pinned explicitly here
# (HOWTO-RANGE.md §5 gotcha: never let a floating tag silently roll the
# target). Assert the version after build:
#   docker compose exec wordpress-x86 php -v   # must say 8.2.34
FROM php:8.2.34-apache

RUN docker-php-ext-install -j "$(nproc)" mysqli pdo_mysql && a2enmod rewrite

# Range staging (documented deviation, ONE knob): post_max_size raised so
# the scorecard's untested P10 "stock-128M trigger" (~64-100MB field) can
# reach the parser. memory_limit stays at STOCK 128M - the point of this
# lane is that the stock memory limit does not stop the 618 OOM encode.
# At pure-stock post_max_size=8M the oversized POST is rejected pre-parse
# (observed 2026-10-21, poc_wp_stock.py first fire).
RUN printf 'post_max_size=128M\nupload_max_filesize=128M\n' > /usr/local/etc/php/conf.d/zz-range.ini

# WordPress core straight from the official image (same WP the arm64
# census lane used) - zero WP-side modification. This is stock WP.
COPY --from=wordpress:6-php8.2-apache /usr/src/wordpress /var/www/html
COPY --from=wordpress:6-php8.2-apache /usr/local/bin/docker-entrypoint.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

# wp-config.php is generated from WORDPRESS_* env by the stock entrypoint.
# No /CANARY here by design: this lane stages the ZERO-GADGET core bug
# (618), whose point is that no app code is involved; WP provides the
# "arbitrary stock app" surface only.
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["apache2-foreground"]
