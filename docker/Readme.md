## Docker

### Usage

Tiffy is automatically built on a daily base via Travis CI in an Docker container.
Tiffy itself generate only the Feed from our TIE. It requires a webserver to provide it to MISP.

#### docker run

docker run \
    --name tiffy \
    -e ENV=VALUE \
    dcso/tiffy:latest

#### docker-compose

Example file is in ./docker/docker-compose.yml

### Customization

#### Required Variables

| Variable                          | Default | Example                                | Description                    |
| --------------------------------- | ------- | -------------------------------------- | ------------------------------ |
| TIFFY_CONF_TIE_APIURL             |         | "https://tie.dcso.de/v1/api"           | URL to TIE.                    |
| TIFFY_CONF_TIE_APIKEY             |         | "12345683127481209123789"              | API token for TIE access       |
| TIFFY_CONF_MISP_ORGANISATION_NAME |         | "ACME"                                 | Name of your MISP organization |
| TIFFY_CONF_MISP_ORGANISATION_UUID |         | "5804adw2-12fe-1234-34av-07lk82aw012a" | UUID of your MISP organization |

#### Optional Variables

| Variable                                 | Default              | Example                  | Description                                                       |
| ---------------------------------------- | -------------------- | ------------------------ | ----------------------------------------------------------------- |
| TIFFY_CONF_MISP_EVENTS_BASE_THREAT_LEVEL | "3"                  |                          | IoC will get this threat level if it is added                     |
| TIFFY_CONF_MISP_EVENTS_BASE_CONFIDENCE   | "80                  |                          | IoC will get this confidence if it is added                       |
| TIFFY_CONF_MISP_EVENTS_BASE_SEVERITY     | "2"                  |                          | IoC will get this severity if it is added                         |
| TIFFY_CONF_MISP_EVENTS_PUBLISHED         | false                |                          | IoC will get published in MISP                                    |
| TIFFY_CONF_MISP_ATTRIBUTES_TO_IDS        | false                |                          | Set IDS flag for this IoC                                         |
| TIFFY_PARAM_TIE_SEEN_FIRST               |                      | "YYYY-MM-DD"             | Download only IoC which are first seen at ... and newer           |
| TIFFY_PARAM_TIE_SEEN_LAST                |                      | "YYYY-MM-DD"             | Download only IoC which are last seen at ... and older            |
| TIFFY_PARAM_TIE_ACTOR                    |                      | "example1,example2"      | Download only IoC with this actor                                 |
| TIFFY_PARAM_TIE_CATEGORY                 |                      | "example1,example2"      | Download only IoC with this category                              |
| TIFFY_PARAM_TIE_FAMILY                   |                      | "example1,example2"      | Download only IoC with this family                                |
| TIFFY_PARAM_TIE_SOURCE                   |                      | "example1,example2"      | Download only IoC from this source                                |
| TIFFY_PARAM_TIE_SEVERITY_MIN             |                      | 2                        | Download only IoC with this minimum severity                      |
| TIFFY_PARAM_TIE_SEVERITY_MAX             |                      | 4                        | Download only IoC with this maximum severity                      |
| TIFFY_PARAM_TIE_CONFIDENCE_MIN           |                      | 2                        | Download only IoC with this minimum confidence                    |
| TIFFY_PARAM_TIE_CONFIDENCE_MAX           |                      | 4                        | Download only IoC with this maximum confidence                    |
| TIFFY_PARAM_TIE_MISP_EVENT_TAGS          |                      | {\"name\":\"tlp:amber\"} | Tag Event with the defined tags                                   |
| TIFFY_PARAM_OUTPUT_FORMAT                | "MISP"               |                          | You can choose the output format of the feed.                     |
| TIFFY_PARAM_TIE_DISABLE_DEFAULT_FILTER   |                      | true / false             | To disable the default TIE filter.                                |
| TIFFY_PARAM_LOG_LEVEL                    | "warning"            |                          | Define one of these log levels: debug,info,warning,error,critical |
| TIFFY_PARAM_LOG_DISABLE_CONSOLE          | true                 | true / false             | Disables log output to stdout                                     |
| TIFFY_PARAM_LOG_DISABLE_FILE             |                      | true / false             | Disables log output to file                                       |
| TIFFY_PARAM_LOG_FILE                     | "/var/log/tiffy.log" |                          | Define the log path                                               |

#### Proxy Variables

| Variable    | Default | Example                               | Description                              |
| ----------- | ------- | ------------------------------------- | ---------------------------------------- |
| HTTP_PROXY  |         | "http://10.8.0.1:8000                 | Set an Proxy server for HTTP connections |
| HTTPS_PROXY |         | "https://<user>:<pass>@10.8.0.1:8000" | Set Proxy server for HTTPS connections   |
