FROM php:8.5-apache

RUN a2dismod mpm_event 2>/dev/null; a2enmod mpm_prefork 2>/dev/null; true

# Deploy the vulnerable app
COPY index.php /var/www/html/index.php
RUN chmod 777 /var/www/html

# Scored canary (range contract): readable ONLY by code execution on target
RUN echo "FLAG{phpbleed:$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')}" > /CANARY && chmod 444 /CANARY

# Survive probing
RUN echo '\nStartServers 1\nMinSpareServers 1\nMaxSpareServers 1\nServerLimit 1\nMaxRequestWorkers 1\nMaxConnectionsPerChild 0\n' >> /etc/apache2/apache2.conf

EXPOSE 80
