FROM ubuntu:22.04

ENV UPDATED_AT 20220908T151922Z

RUN apt-get update && apt-get install -y nodejs

COPY . /app

# Somehow, Node manages to elude our hookup. Run it twice.
CMD cd /app; node test.js; sleep 1; node test.js
