FROM --platform=linux/arm64 php:8.1-apache
RUN a2dismod mpm_event 2>/dev/null; a2enmod mpm_prefork 2>/dev/null; true
COPY index.php /var/www/html/index.php
RUN chmod 777 /var/www/html
RUN echo "FLAG{bleed81arm:$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')}" > /CANARY && chmod 444 /CANARY
RUN echo '\nMaxRequestWorkers 256\nServerLimit 256\nStartServers 16\n' >> /etc/apache2/apache2.conf
