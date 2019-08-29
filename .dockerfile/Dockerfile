FROM python:3.7-alpine AS build
RUN set -eu \
    ;mkdir -p /tiffy \
    ; python3 -m venv /tiffy/venv
WORKDIR /tiffy
COPY . .
RUN set -eu \
    ; rmdir /tiffy/.dockerfile \
    ;/tiffy/venv/bin/pip3 install -r requirements.txt --no-cache-dir \
    ;rm requirements.txt  \
    ;chown -R nobody:nobody /tiffy \
    ;



FROM alpine
COPY --from=build /tiffy /tiffy
ENV PATH=/tiffy/venv/bin:$PATH
USER nobody
WORKDIR /tiffy
ENTRYPOINT [ "python", "tiffy.py" ]

# Build Arguments
    ARG BUILD_DATE
    ARG GIT_REPO
    ARG VCS_REF
    ARG NAME="tiffy"
    ARG DESCRIPTION="This docker container is an feed generator from DCSO TIE to MISP."
    ARG AUTHOR="DCSO TI Team <ti-support@dcso.de>"
    ARG LICENSE="BSD-3-Clause"

# Environment Variables
    ENV NAME=${NAME} \
        VERSION=${VCS_REF} \
        BUILD_DATE=${BUILD_DATE}
# Label
    LABEL   org.opencontainers.image.created="${BUILD_DATE}" \
            org.opencontainers.image.url="${GIT_REPO}" \
            org.opencontainers.image.source="${GIT_REPO}" \
            org.opencontainers.image.version="${VCS_REF}" \
            org.opencontainers.image.revision="${VCS_REF}" \
            org.opencontainers.image.vendor="${VENDOR}" \
            org.opencontainers.image.title="${NAME}" \
            org.opencontainers.image.description="${DESCRIPTION}" \
            #org.opencontainers.image.documentation="${DOCUMENTATION}" \
            org.opencontainers.image.authors="${AUTHOR}" \
            org.opencontainers.image.licenses="${LICENSE}"
