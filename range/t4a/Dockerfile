FROM php:8.2-apache
COPY index.php /var/www/html/index.php
RUN echo "FLAG{t4a:$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')}" > /CANARY && chmod 444 /CANARY
