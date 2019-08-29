FROM python:3.7-alpine

WORKDIR /usr/local/src
USER nobody

COPY . .

RUN set -eu \
    ;pip3 install -r requirements.txt --no-cache-dir \
    ;

# CMD [ "tiffy.py" ]