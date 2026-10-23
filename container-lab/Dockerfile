ARG PHP_BASE_IMAGE
FROM ${PHP_BASE_IMAGE}

ARG LAB_VARIANT
ARG PHP_VERSION_EXPECTED
LABEL org.opencontainers.image.title="PHP2Shell isolated runtime assessment lab" \
      org.opencontainers.image.description="Authorized dev-only vulnerable/fixed comparison; no exploit endpoint." \
      org.ninjapaw.lab.variant="${LAB_VARIANT}"

COPY container-lab/apache.conf /lab/apache.conf
COPY container-lab/php.ini /usr/local/etc/php/conf.d/zzz-isolated-lab.ini
COPY container-lab/index.php container-lab/health.php app/lab.php /var/www/html/
COPY app/assets /var/www/html/assets
ENV LAB_VARIANT=${LAB_VARIANT} PHP_VERSION_EXPECTED=${PHP_VERSION_EXPECTED}
USER 10001:10001
EXPOSE 8080
CMD ["apache2", "-f", "/lab/apache.conf", "-DFOREGROUND"]
