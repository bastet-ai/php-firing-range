FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential autoconf pkg-config bison re2c libxml2-dev libssl-dev \
    curl apache2 apache2-dev libonig-dev libsqlite3-dev libzip-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
COPY . /usr/src/php-src
RUN cd /usr/src/php-src && ./buildconf --force && \
    ./configure --with-apxs2 --disable-cgi --disable-debug --enable-cgi=no \
      --with-openssl --with-sqlite3 --with-zip --enable-zend-test=no \
      --prefix=/usr/local >/dev/null && make -j"$(nproc)" >/dev/null && \
    make install >/dev/null && \
    cp /usr/local/lib/php.ini-production /usr/local/lib/php.ini
RUN a2enmod php8 || a2enmod php
RUN echo 'DirectoryIndex index.php' > /etc/apache2/conf-enabled/php.conf && \
    echo 'AddType application/x-httpd-php .php' >> /etc/apache2/conf-enabled/php.conf
STOPSIGNAL SIGTERM
CMD ["apache2ctl", "-D", "FOREGROUND"]
