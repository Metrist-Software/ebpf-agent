FROM ubuntu:22.04

ENV UPDATED_AT 20220908T151922Z

RUN apt-get update && apt-get install -y ruby

COPY . /app

CMD ruby /app/test.rb
