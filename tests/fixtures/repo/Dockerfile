# The first stage borrows Composer from its own image, which is not PHP.
FROM composer:2 AS vendor
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-interaction

FROM php:8.3.35-fpm AS app
COPY --from=vendor /app/vendor /var/www/html/vendor
