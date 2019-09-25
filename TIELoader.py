"""
DCSO tiffy
Copyright (c) 2019, DCSO GmbH
"""
import hashlib
import json
import logging
import os
import sys
from pathlib import Path

import requests
from requests import HTTPError, ConnectionError, ConnectTimeout

from helpers import fileHelper, MISPHelper, iocHelper


def get_csv_value(field, src):
    if field == 'src':
        return src
    else:
        return 0


class TIELoader:

    @staticmethod
    def start(out_format, conf, tags, category, actor, family, source, first_seen, last_seen, min_confidence,
              min_severity, max_confindence, max_severity, proxy_tie_addr, no_filter=False, disable_cert_verify=False):

        # Building Auth Header
        conf_authHeader = {'Authorization': 'Bearer ' + conf.tie_api_key}

        # Building URL
        if first_seen:
            date_since = first_seen.strftime("%Y-%m-%d")
        if last_seen:
            date_until = last_seen.strftime("%Y-%m-%d")
        category = category
        finished = False
        event = None
        connection_error = False

        # Building parameters
        payload = dict()
        if category:
            payload['category'] = category
        if first_seen:
            payload['first_seen_since'] = date_since
        if last_seen:
            payload['first_seen_until'] = date_until
        if actor:
            payload['actor'] = actor
        if family:
            payload['family'] = family
        if source:
            payload['source_pseudonym'] = source
        if min_confidence and max_confindence:
            payload['confidence'] = str(min_confidence) + '-' + str(max_confindence)
        elif min_confidence:
            payload['confidence'] = str(min_confidence) + '-'
        elif max_confindence:
            payload['confidence'] = '-' + str(max_confindence)
        if min_severity and max_severity:
            payload['severity'] = str(min_severity) + '-' + str(max_severity)
        elif min_severity:
            payload['severity'] = str(min_severity) + '-'
        elif max_severity:
            payload['severity'] = '-' + str(max_severity)
        if not no_filter:
            payload['filter'] = 'default'
        payload['limit'] = 1000

        url = conf.tie_api_url + 'observations'
        index = 0
        connection_retrys = 1
        deduplicated_observations = dict()

        while not finished:

            try:
                myResponse = requests.get(url, params=payload, headers=conf_authHeader, proxies=proxy_tie_addr,
                                          verify=not disable_cert_verify)

                # For successful API call, response code will be 200 (OK)
                if myResponse.ok:
                    # print(myResponse.status_code)
                    # Loading the response data into a dict variable
                    # json.loads takes in only binary or string variables so using content to fetch binary content
                    # Loads (Load String) takes a Json file and converts into python data structure
                    # (dict or list, depending on JSON)

                    try:
                        jsonResponse = myResponse.json()

                        # check is TIE Response is complete
                        response_has_more = None
                        response_observations = None
                        response_params = None
                        if 'has_more' in jsonResponse and 'observations' in jsonResponse and 'params' in jsonResponse:
                            response_has_more = jsonResponse['has_more']
                            response_observations = jsonResponse['observations']
                            response_params = jsonResponse['params']
                        else:
                            raise ValueError("Error: TIE answered with an invalid or empty JSON Response")

                        TIELoader.deduplicate_observations(response_observations, deduplicated_observations)

                        # parsing received observations
                        logging.info(
                            "Parsing... - Offset: " + str(index) + " to " + str(index + len(response_observations)))
                        index += len(response_observations)

                        if response_has_more is not True:
                            finished = True
                            logging.info("There are no more attributes")
                            logging.info("#### Finished #####")
                            break
                        else:
                            if isinstance(myResponse.links, dict):
                                res = myResponse.links["next"]
                                url = res["url"]
                                payload = dict()
                                logging.info("#### Continue #####")

                    except ValueError:
                        logging.error("Error: Invalid or empty JSON Response")
                elif myResponse.status_code >= 500 and myResponse.status_code <= 550:
                    logging.warning("It seems there are connection issues with TIE at the moment")
                    logging.warning(
                        "Status-Code: " + str(myResponse.status_code) + " - Try: " + str(
                            connection_retrys) + " from 5")

                    connection_retrys += 1
                    if connection_retrys < 6:
                        continue
                    else:
                        logging.error("TIE seems not to be available at the moment or connection is interrupted")
                        raise ConnectionError
                else:
                    # If response code is not ok (200), print the resulting http error code with description
                    logging.error("Error:")
                    logging.error(myResponse.content)
                    myResponse.raise_for_status()
            except (HTTPError, ConnectionError, ConnectTimeout) as e:
                logging.error("Error:")
                logging.error("TIE seems not to be available at the moment or connection is interrupted")
                logging.debug(e)
                connection_error = True
                finished = True
                return
        # TIE is available?

        if out_format == 'MISP':
            # Serialize event as MISP Event

            event, attr_hashes = MISPHelper.generate_MISP_Event(deduplicated_observations, conf, tags)
            event_json = event.to_json()
            event_from_json = json.loads(event_json)
            event_from_json['publish_timestamp'] = str(event_from_json['publish_timestamp'])
            json_output = '{"Event" :' + json.dumps(event_from_json) + '}'
            event_no_attr = MISPHelper.generate_Manifest_Entry(event_from_json)
            manifest_output = {event['uuid']: event_no_attr}
            fileHelper.save_events_to_file(event['uuid'], json_output)
            fileHelper.save_manifest_to_file(manifest_output)
            fileHelper.save_hashes(attr_hashes)

    @staticmethod
    def deduplicate_observations(response_observations, deduplicated_observations):
        for observation in response_observations:
            hashed_value = hashlib.md5(observation['value'].encode())
            if hashed_value.hexdigest() in deduplicated_observations:
                ioc = deduplicated_observations[hashed_value.hexdigest()]
                if ioc:
                    iocHelper.update_ioc(ioc, observation)
                else:
                    deduplicated_observations[hashed_value.hexdigest()] = iocHelper.generate_new_ioc(
                        observation)
            else:
                deduplicated_observations[hashed_value.hexdigest()] = iocHelper.generate_new_ioc(
                    observation)

    @staticmethod
    def init_logger(logPath, fileName, logLvl, consoleLog, fileLog):

        logger = logging.getLogger()
        logger.setLevel(logLvl)
        formatter = logging.Formatter('%(asctime)s [%(levelname)-5.5s]  %(message)s')

        consoleHandler = logging.StreamHandler(sys.stdout)

        consoleHandler.setFormatter(formatter)
        logger.addHandler(consoleHandler)

        if consoleLog is False:
            consoleHandler.setLevel(logLvl)
        else:
            consoleHandler.setLevel(100)

        if fileLog is False:
            out_path = Path(logPath)
            if not out_path.exists():
                out_path.mkdir()
            fileHandler = logging.FileHandler(out_path / fileName)
            fileHandler.setFormatter(formatter)
            fileHandler.setLevel(logLvl)
            logger.addHandler(fileHandler)
