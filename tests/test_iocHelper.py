import hashlib
import json

import pytest
from helpers import iocHelper
from pathlib import Path


@pytest.mark.describe('iocHelper')
class TestIocHelper:
    @pytest.mark.it('Should create a new ioc from an observation received from TIE.')
    def test_generate_new_ioc(self):
        test_observation = {
            "data_type": "DomainName",
            "id": "59201df8-9182-4e76-8004-40df42ffc83e",
            "created_at": "2019-08-21 10:54:23.390628+02:00",
            "value": "testval.ue",
            "last_seen": "2019-08-21 12:38:36.914553+02:00",
            "confidence": 80,
            "updated_at": "2019-08-21 12:49:38.049944+02:00",
            "seq": 6218329471,
            "event": {
                "memo": "testmemo",
                "id": "75c13a88-94d9-41f8-89db-879305e01207"
            },
            "actors": [],
            "categories": [
                "whitelist"
            ],
            "first_seen": "2019-08-21 10:38:40.383226+02:00",
            "severity": 0,
            "source": {
                "name": "testname",
                "pseudonym": "testpseudo"
            },
            "families": []
        }
        ioc = iocHelper.generate_new_ioc(test_observation)
        assert ioc['data_type'] == test_observation['data_type']
        assert ioc['first_seen'] == test_observation['first_seen']
        assert ioc['last_seen'] == test_observation['last_seen']
        assert ioc['created_at'] == test_observation['created_at']
        assert ioc['updated_at'] == test_observation['updated_at']
        assert ioc['max_confidence'] == test_observation['confidence']
        assert ioc['min_confidence'] == test_observation['confidence']
        assert ioc['max_severity'] == test_observation['severity']
        assert ioc['min_severity'] == test_observation['severity']
        assert ioc['n_occurrences'] == 1
        assert ioc['sources'] == [test_observation['source']]
        assert ioc['value'] == test_observation['value']
        assert ioc['categories'] == test_observation['categories']
        assert ioc['actors'] == test_observation['actors']
        assert ioc['families'] == test_observation['families']

    @pytest.mark.it('Should update an ioc with another observation from TIE.')
    def test_update_ioc(self):
        test_observation = {
            "data_type": "DomainName",
            "id": "59201df8-9182-4e76-8004-40df42ffc83e",
            "created_at": "2019-08-21 10:54:23.390628+02:00",
            "value": "testval.ue",
            "last_seen": "2019-08-21 12:38:36.914553+02:00",
            "confidence": 80,
            "updated_at": "2019-08-21 12:49:38.049944+02:00",
            "seq": 6218329471,
            "event": {
                "memo": "testmemo",
                "id": "75c13a88-94d9-41f8-89db-879305e01207"
            },
            "actors": [],
            "categories": [
                "whitelist"
            ],
            "first_seen": "2019-08-21 10:38:40.383226+02:00",
            "severity": 0,
            "source": {
                "name": "testname",
                "pseudonym": "testpseudo"
            },
            "families": []
        }
        ioc = iocHelper.generate_new_ioc(test_observation)
        test_observation_2 = {
            "data_type": "DomainName",
            "id": "bf19a8d7-b93a-43c7-8df6-a4884ac2772c",
            "created_at": "2019-08-21 8:55:05.685111+02:00",
            "value": "testval.ue",
            "last_seen": "2019-08-21 14:38:36.914553+02:00",
            "confidence": 80,
            "updated_at": "2019-08-21 13:49:41.109552+02:00",
            "seq": 6218331054,
            "event": {
                "memo": "testmemo",
                "id": "75c13a88-94d9-41f8-89db-879305e01207"
            },
            "actors": ['testactor'],
            "categories": [
                "testcategory"
            ],
            "first_seen": "2019-08-21 8:38:40.383226+02:00",
            "severity": 0,
            "source": {
                "name": "testname2",
                "pseudonym": "testpseudo2"
            },
            "families": ['testfamily']
        }

        iocHelper.update_ioc(ioc, test_observation_2)
        assert ioc['data_type'] == test_observation_2['data_type']
        assert ioc['first_seen'] == test_observation_2['first_seen']
        assert ioc['last_seen'] == test_observation_2['last_seen']
        assert ioc['created_at'] == test_observation_2['created_at']
        assert ioc['updated_at'] == test_observation_2['updated_at']
        assert ioc['max_confidence'] == test_observation_2['confidence']
        assert ioc['min_confidence'] == test_observation_2['confidence']
        assert ioc['max_severity'] == test_observation_2['severity']
        assert ioc['min_severity'] == test_observation_2['severity']
        assert ioc['n_occurrences'] == 2
        assert ioc['sources'] == [test_observation['source'], test_observation_2['source']]
        assert ioc['value'] == test_observation_2['value']
        assert ioc['categories'] == test_observation['categories'] + test_observation_2['categories']
        assert ioc['actors'] == test_observation['actors'] + test_observation_2['actors']
        assert ioc['families'] == test_observation['families'] + test_observation_2['families']
