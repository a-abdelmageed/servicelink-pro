# ============================================================
# ServiceLink Pro — Web Application Container
# PHP 7.4 + Apache (older PHP = more legacy vuln surface)
# FOR CONTROLLED IDS TESTING ONLY
# ============================================================

FROM php:7.4-apache

# Enable Apache mod_rewrite
RUN a2enmod rewrite

# Install mysqli extension
RUN docker-php-ext-install mysqli && docker-php-ext-enable mysqli

# Install additional utilities useful in a lab environment
RUN apt-get update && apt-get install -y \
    curl \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# !! INTENTIONALLY INSECURE PHP CONFIG
# Exposes errors, disables security hardening
RUN echo "display_errors = On"            >> /usr/local/etc/php/php.ini && \
    echo "display_startup_errors = On"    >> /usr/local/etc/php/php.ini && \
    echo "error_reporting = E_ALL"        >> /usr/local/etc/php/php.ini && \
    echo "log_errors = On"                >> /usr/local/etc/php/php.ini && \
    echo "expose_php = On"                >> /usr/local/etc/php/php.ini && \
    echo "allow_url_fopen = On"           >> /usr/local/etc/php/php.ini && \
    echo "allow_url_include = On"         >> /usr/local/etc/php/php.ini && \
    echo "session.cookie_httponly = 0"    >> /usr/local/etc/php/php.ini && \
    echo "session.cookie_secure = 0"      >> /usr/local/etc/php/php.ini && \
    echo "session.use_strict_mode = 0"    >> /usr/local/etc/php/php.ini && \
    echo "session.gc_maxlifetime = 86400" >> /usr/local/etc/php/php.ini

# Apache config — disable security headers, enable directory listing
RUN echo '<Directory /var/www/html/>\n\
    Options Indexes FollowSymLinks\n\
    AllowOverride All\n\
    Require all granted\n\
</Directory>' > /etc/apache2/conf-available/lab.conf \
    && a2enconf lab

# Copy application source
COPY ./html/ /var/www/html/

# Set loose permissions (insecure — intentional for lab)
RUN chmod -R 777 /var/www/html/

# Expose HTTP port
EXPOSE 80

CMD ["apache2-foreground"]
