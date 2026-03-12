FROM postgres:15-alpine

# Türkçe karakterleri desteklemek için
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

COPY init.sql /docker-entrypoint-initdb.d/

EXPOSE 5432
