FROM php:8.2-apache
RUN a2dismod mpm_event 2>/dev/null; a2enmod mpm_prefork 2>/dev/null; true
COPY index.php /var/www/html/index.php
RUN echo "FLAG{bleed82:$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')}" > /CANARY && chmod 444 /CANARY
