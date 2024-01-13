FROM ubuntu:22.04

ENV UPDATED_AT 20220908T151922Z

RUN apt-get update && apt-get install -y golang ssl-cert ca-certificates

COPY . /app
RUN cd /app; go build test.go

CMD /app/test
