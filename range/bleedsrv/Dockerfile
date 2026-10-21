FROM php:8.4-cli
COPY index.php /var/www/html/index.php
RUN chmod 777 /var/www/html
RUN echo "FLAG{bleedsrv:$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')}" > /CANARY && chmod 444 /CANARY
CMD ["php","-S","0.0.0.0:8080","-t","/var/www/html"]
