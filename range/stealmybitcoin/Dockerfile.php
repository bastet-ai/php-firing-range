# stage 1: build print-flag statically (multi-stage: no host-side binary needed)
FROM alpine:3.20 AS pfbuild
RUN apk add --no-cache gcc musl-dev
COPY print-flag.c /src/print-flag.c
RUN gcc -static -O2 -w -o /print-flag /src/print-flag.c

ARG PHP_TAG=8.4.26
FROM php:${PHP_TAG}-cli-alpine
RUN echo "PHP_TAG=${PHP_TAG}" > /etc/php-fixtures-tag
# print-flag (multi-stage static musl build)
COPY --from=pfbuild /print-flag /usr/local/bin/print-flag
RUN chown root:root /usr/local/bin/print-flag && chmod 4755 /usr/local/bin/print-flag
COPY html /var/www/html
RUN chown -R root:root /var/www/html && chmod -R a+rX /var/www/html
COPY entry-php.sh /usr/local/bin/entry-php.sh
RUN chmod +x /usr/local/bin/entry-php.sh
EXPOSE 8080
CMD ["/usr/local/bin/entry-php.sh"]
