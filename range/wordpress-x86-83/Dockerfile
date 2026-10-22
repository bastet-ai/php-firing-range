# Vulnerable WP on PINNED PRE-PATCH php 8.3.35 - the version that matches
# the php83 lab lane's corrupt-token persistence evidence (the aarch64 lab
# runs 8.3.35; the corrupt shutdown-flush encode tokens were observed there,
# never on 8.2.34). The vendor's WP demo claims version-dependent paths;
# this lane isolates the 8.3.x pre-patch WP shape.
# Assert after build: docker compose exec wordpress-x86-83 php -v  # 8.3.35
FROM php:8.3.35-apache

RUN docker-php-ext-install -j "$(nproc)" mysqli pdo_mysql && a2enmod rewrite

COPY --from=wordpress:7.1.2-php8.2-apache /usr/src/wordpress /var/www/html
COPY --from=wordpress:7.1.2-php8.2-apache /usr/local/bin/docker-entrypoint.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

RUN echo "FLAG{wordpress-x86-83:$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')}" > /CANARY && chmod 0444 /CANARY

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["apache2-foreground"]
