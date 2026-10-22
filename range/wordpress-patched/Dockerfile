# PATCHED CONTROL lane for wordpress-x86: identical shape, but the PHP
# base is the FIXED 8.2.35 release (CVE-2026-109618/619 fixed there).
# Same unmodified WP 7.1.2 core, same INI defaults, same compose pattern.
# Assert after build:
#   docker compose exec wordpress-patched php -v   # must say 8.2.35
# Purpose (Daybreak review point 3): matched patched-build negative control
# for every producer/consumer experiment run on the vulnerable lane.
# NOTE: WORDPRESS_DB_NAME=wp_patched is intentionally NOT created in wpdb;
# this lane's control fires (multipart parse / session machinery / request
# shutdown) are all pre-script and never touch the DB. Front pages will
# show the WP DB-error banner - irrelevant to the tested paths, and it
# keeps this lane from sharing tables with the vulnerable lane.
FROM php:8.2.35-apache

RUN docker-php-ext-install -j "$(nproc)" mysqli pdo_mysql && a2enmod rewrite

COPY --from=wordpress:7.1.2-php8.2-apache /usr/src/wordpress /var/www/html
COPY --from=wordpress:7.1.2-php8.2-apache /usr/local/bin/docker-entrypoint.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

RUN echo "FLAG{wordpress-patched:$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')}" > /CANARY && chmod 0444 /CANARY

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["apache2-foreground"]
