# cb-C (GLM5-ToB): nginx front for the php-fpm lane. Serves the SAME WP
# app (core copied unmodified from the official image for static files),
# fastcgi_pass to the wpfpm service. Host-native arch, no platform pin.
FROM nginx:stable

COPY --from=wordpress:7.1.2-php8.2-apache /usr/src/wordpress /var/www/html
COPY wpfpm-nginx.conf /etc/nginx/conf.d/default.conf
