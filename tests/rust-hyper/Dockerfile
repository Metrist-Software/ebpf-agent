FROM ubuntu:22.04

ENV UPDATED_AT 20220908T151922Z

RUN apt-get update && apt-get install -y rustc cargo libssl-dev pkg-config

COPY . /app
RUN cd /app; cargo build

CMD /app/target/debug/test
