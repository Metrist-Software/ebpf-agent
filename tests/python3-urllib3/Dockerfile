FROM ubuntu:22.04

ENV UPDATED_AT 20220908T151922Z

RUN apt-get update && apt-get install -y python3-pip

RUN pip3 install --upgrade pip
RUN pip3 install requests

COPY . /app

CMD python3 /app/test.py
