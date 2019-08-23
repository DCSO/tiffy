from collections import OrderedDict

from dateutil.parser import *

def generate_new_ioc(observation):
    ioc = dict()
    ioc['data_type'] = observation['data_type']
    ioc['first_seen'] = observation['first_seen']
    ioc['last_seen'] = observation['last_seen']
    ioc['created_at'] = observation['created_at']
    ioc['updated_at'] = observation['updated_at']
    ioc['max_confidence'] = observation['confidence']
    ioc['min_confidence'] = observation['confidence']
    ioc['max_severity'] = observation['severity']
    ioc['min_severity'] = observation['severity']
    ioc['n_occurrences'] = 1
    ioc['sources'] = [observation['source']]
    ioc['value'] = observation['value']
    ioc['categories'] = []
    for cat in observation['categories']:
        ioc['categories'].append(cat)
    ioc['actors'] = []
    for act in observation['actors']:
        ioc['actors'].append(act)
    ioc['families'] = []
    for fam in observation['families']:
        ioc['families'].append(fam)
    return ioc


def update_ioc(ioc, observation):
    date_format = '%Y-%m-%d %H:%M:%S %z'
    ioc['last_seen'] = observation['last_seen'] \
        if parse(observation['last_seen']) > parse(ioc['last_seen']) \
        else ioc[
        'last_seen']
    ioc['first_seen'] = observation['first_seen'] \
        if parse(observation['first_seen']) < parse(ioc['first_seen']) \
        else ioc[
        'first_seen']
    ioc['created_at'] = observation['created_at'] \
        if parse(observation['created_at']) < parse(ioc['created_at']) \
        else ioc[
        'created_at']
    ioc['updated_at'] = observation['updated_at'] \
        if parse(observation['updated_at']) > parse(ioc['updated_at']) \
        else ioc[
        'updated_at']
    ioc['min_severity'] = observation['severity'] \
        if observation['severity'] < ioc['min_severity'] else ioc['min_severity']
    ioc['max_severity'] = observation['severity'] \
        if observation['severity'] > ioc['max_severity'] else ioc['max_severity']
    ioc['min_confidence'] = observation['confidence'] \
        if observation['confidence'] < ioc['min_confidence'] else ioc['min_confidence']
    ioc['max_confidence'] = observation['confidence'] \
        if observation['confidence'] < ioc['max_confidence'] else ioc['max_confidence']
    ioc['n_occurrences'] += 1
    if not observation['source'] in ioc['sources']:
        ioc['sources'].append(observation['source'])
    for cat in observation['categories']:
        ioc['categories'].append(cat)
        ioc['categories'] = list(OrderedDict.fromkeys(ioc['categories']))
    for act in observation['actors']:
        ioc['actors'].append(act)
        ioc['actors'] = list(OrderedDict.fromkeys(ioc['actors']))
    for fam in observation['families']:
        ioc['families'].append(fam)
        ioc['families'] = list(OrderedDict.fromkeys(ioc['families']))
