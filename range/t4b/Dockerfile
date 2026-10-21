FROM php:8.2-apache
RUN a2dismod mpm_event 2>/dev/null; a2enmod mpm_prefork 2>/dev/null; true
COPY index.php /var/www/html/index.php
RUN echo "FLAG{t4b:$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')}" > /CANARY && chmod 444 /CANARY
RUN echo '\nStartServers 1\nMinSpareServers 1\nMaxSpareServers 1\nServerLimit 1\nMaxRequestWorkers 1\nMaxConnectionsPerChild 0\n' >> /etc/apache2/apache2.conf
