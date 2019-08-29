FROM python:3.7-alpine AS build
RUN set -eu \
    ;mkdir -p /tiffy \
    ; python3 -m venv /tiffy/venv
WORKDIR /tiffy
COPY . .
RUN set -eu \
    ;/tiffy/venv/bin/pip3 install -r requirements.txt --no-cache-dir \
    ;chown -R nobody:nobody /tiffy \
    ;
#################################
# FROM gcr.io/distroless/python3
# COPY --from=build /tiffy /tiffy
USER nobody
WORKDIR /tiffy
ENTRYPOINT [ "/tiffy/venv/bin/python", "/tiffy/tiffy.py" ]