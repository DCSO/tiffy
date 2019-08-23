import copy
from datetime import datetime
import hashlib
import json
import uuid

from pymisp import MISPEvent, MISPOrganisation, MISPAttribute


def generate_MISP_Event(deduplicated_observations, conf, tags):
    dt = datetime.now()

    event = MISPEvent()
    event.info = dt.strftime("%Y%m%d ") + 'TIE'
    event.publish_timestamp = dt.strftime("%s")
    event.timestamp = dt.strftime("%s")
    event['timestamp'] = dt.strftime("%s")
    event.analysis = 2
    event.published = True
    orgc = MISPOrganisation()
    orgc.from_json(json.dumps({'name': conf.org_name, 'uuid': conf.org_uuid}))
    event.orgc = orgc
    event.threat_level_id = conf.event_base_thread_level
    event.date = dt
    event['uuid'] = str(uuid.uuid1())
    if len(tags) > 0:
        event['Tag'] = tags

    attr_hashes = []

    for key, attr in deduplicated_observations.items():
        misp_attr = MISPAttribute()
        misp_attr.timestamp = dt.strftime("%s")
        misp_attr['timestamp'] = dt.strftime("%s")
        misp_attr.type = get_Attribute_Type(attr)
        misp_attr.value = get_MISP_Fitted_Value(attr["value"], misp_attr.type)
        misp_attr.category = get_Attribute_Category(attr)
        misp_attr.to_ids = True
        misp_attr['comment'] = 'categories: ' + str(attr['categories']) + ' actors: ' + str(attr['actors']) + \
                               ' families: ' + str(attr['families']) + ' sources: ' + str(attr['sources']) + \
                               ' severity: ' + str(attr['max_severity']) + \
                               ' confidence: ' + str(attr['max_confidence'])
        misp_attr.edited = False
        event.add_attribute(**(misp_attr.to_dict()))
        attr_hashes.append([hashlib.md5(attr['value'].encode("utf-8")).hexdigest(), event['uuid']])

    event.edited = False
    return event, attr_hashes


def generate_Manifest_Entry(event):
    event_no_attr = copy.deepcopy(event)
    if "Attribute" in event_no_attr.keys():
        event_no_attr.pop("Attribute")

    orgc = event_no_attr['Orgc']
    orgc['id'] = "42"
    event_no_attr['Orgc'] = orgc
    event_no_attr.pop('publish_timestamp')
    event_no_attr.pop('published')
    event_no_attr.pop('uuid')
    return event_no_attr


def get_Attribute_Category(attr):
    if attr['data_type'] == 'ExactHash' or attr['data_type'] == 'EMail':
        return 'Payload delivery'
    else:
        return 'Network activity'


def get_Attribute_Type(attr):
    if attr['data_type'] == 'ExactHash':
        value = attr['value']
        if value.startswith('md5'):
            return 'md5'
        if value.startswith('sha1'):
            return 'sha1'
        if value.startswith('sha256'):
            return 'sha256'
    elif attr['data_type'] == 'EMail':
        return 'email-dst'
    elif attr['data_type'] == 'DomainName':
        return 'domain'
    elif attr['data_type'] == 'URLVerbatim':
        return 'url'
    elif attr['data_type'] == 'IPv4' or attr['data_type'] == 'IPv6':
        return 'ip-dst'


def get_MISP_Fitted_Value(value, event_type):
    if event_type == 'ip-dst' and value.find('/32', 0, len(value)):
        return value.replace('/32', '')
    if event_type == 'md5' and value.startswith('md5:'):
        return value.replace('md5:', '')
    if event_type == 'sha1' and value.startswith('sha1:'):
        return value.replace('sha1:', '')
    if event_type == 'sha256' and value.startswith('sha256:'):
        return value.replace('sha256:', '')
    return value
