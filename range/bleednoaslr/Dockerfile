FROM php:8.5.11-apache

# Explicit NO-ASLR target variant (contrast lab for the exploit):
# kernel randomize_va_space stays 2 (host-global), but Apache is exec'd
# under setarch --addr-no-randomize => per-process ADDR_NO_RANDOMIZE:
# no PIE base slide, no mmap/heap randomization for this process tree.
RUN a2dismod mpm_event 2>/dev/null; a2enmod mpm_prefork 2>/dev/null; true
COPY index.php /var/www/html/index.php
RUN chmod 777 /var/www/html
RUN echo "FLAG{bleednoaslr:$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')}" > /CANARY && chmod 444 /CANARY
RUN echo '\nMaxRequestWorkers 256\nServerLimit 256\nStartServers 16\n' >> /etc/apache2/apache2.conf
# replace entrypoint's apache2ctl exec with setarch-wrapped apache2
RUN sed -i 's|exec apache2|exec setarch $(uname -m) --addr-no-randomize apache2|' /etc/apache2/entrypoint.sh 2>/dev/null; \
    grep -q addr-no-randomize /etc/apache2/entrypoint.sh || sed -i '1a exec setarch $(uname -m) --addr-no-randomize "$@"' /etc/apache2/docker-entrypoint.sh 2>/dev/null; true
CMD ["setarch", "aarch64", "--addr-no-randomize", "apache2", "-DFOREGROUND"]
