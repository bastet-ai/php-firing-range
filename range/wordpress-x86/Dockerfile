# Stock WordPress 7.1.2 on PINNED PRE-PATCH php 8.2.34 (x86_64 native).
# CVE-2026-109618/619 were fixed in 8.2.35; the floating php:8.2 tag now
# ships the patched release, so the PHP base is pinned explicitly here
# (HOWTO-RANGE.md §5 gotcha). Assert after build:
#   docker compose exec wordpress-x86 php -v   # must say 8.2.34
# WP version matches the vendor's claimed demo target (calif.io/php2shell
# lists WordPress 7.1.2). Core copied UNMODIFIED from the official image.
FROM php:8.2.34-apache

RUN docker-php-ext-install -j "$(nproc)" mysqli pdo_mysql && a2enmod rewrite

# WordPress core straight from the official 7.1.2 image - zero WP-side
# modification. This is stock WP.
COPY --from=wordpress:7.1.2-php8.2-apache /usr/src/wordpress /var/www/html
COPY --from=wordpress:7.1.2-php8.2-apache /usr/local/bin/docker-entrypoint.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

# Scored canary (range plumbing only - the WP app itself stays untouched).
# This lane stages the ZERO-GADGET decode-side route: the producer is an
# interrupted maybe_unserialize() of stored (attacker-influenced) option
# data on a plain GET, at PURE-STOCK php INIs (no post_max_size staging -
# that was only needed for the upload-shaped producer; see WP-X86-NOTES).
RUN echo "FLAG{wordpress-x86:$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')}" > /CANARY && chmod 0444 /CANARY

# wp-config.php is generated from WORDPRESS_* env by the stock entrypoint.
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["apache2-foreground"]
