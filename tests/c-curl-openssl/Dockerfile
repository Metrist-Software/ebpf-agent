FROM ubuntu:22.04

ENV UPDATED_AT 20220908T151922Z

# Note that it's trivial to sub nss or gnutls
RUN apt-get update && apt-get install -y gcc libcurl4-openssl-dev

COPY . /app

ARG FORCE=1
RUN cd /app; cc -o test test.c -lcurl
CMD /app/test
