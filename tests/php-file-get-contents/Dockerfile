FROM ubuntu:22.04

ENV UPDATED_AT 20220908T151922Z
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y php

COPY . /app


CMD cd /app; php test.php; sleep 1; php test.php
