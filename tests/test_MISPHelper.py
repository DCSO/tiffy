import hashlib
import json
from datetime import datetime

import pytest
from pymisp import MISPOrganisation, MISPEvent, AbstractMISP

from helpers import MISPHelper
from pathlib import Path

from model import Config


@pytest.mark.describe('MISPHelper')
class TestMISPHelper:
    @pytest.mark.it('Should generate a MISPEvent from deduplicatedObservations')
    def test_generate_MISP_event(self):
        conf = Config.parse("settings/config.yml")
        test_obs = {"3ad54db13a7b6129902b0ee0acf3e2d1": {
            "data_type": "IPv4",
            "first_seen": "2019-08-21 08:38:29+02:00",
            "last_seen": "2019-08-21 13:38:28+02:00",
            "created_at": "2019-08-21 08:51:20.242089+02:00",
            "updated_at": "2019-08-21 13:51:10.270419+02:00",
            "max_confidence": 40,
            "min_confidence": 40,
            "max_severity": 1,
            "min_severity": 1,
            "n_occurrences": 1,
            "sources": [
                {
                    "pseudonym": "testpseudo1",
                    "name": "testname1"
                }
            ],
            "value": "123.45.67.89/32",
            "categories": [],
            "actors": [],
            "families": []
        },
            "a3475b4484bed2a863720110e8099208": {
                "data_type": "ExactHash",
                "first_seen": "2019-08-21 13:38:17+02:00",
                "last_seen": "2019-08-21 13:38:26+02:00",
                "created_at": "2019-08-21 13:40:02.575150+02:00",
                "updated_at": "2019-08-21 13:40:02.575150+02:00",
                "max_confidence": 90,
                "min_confidence": 90,
                "max_severity": 1,
                "min_severity": 1,
                "n_occurrences": 1,
                "sources": [
                    {
                        "pseudonym": "testpseudo2",
                        "name": "testname2"
                    }
                ],
                "value": "sha1:930A0029225AA4C28B8EF095B679285EAAE27078",
                "categories": [],
                "actors": [],
                "families": [
                    "testfamily"
                ]
            }}
        event, attr_hashes = MISPHelper.generate_MISP_Event(test_obs, conf, [])

        dt = datetime.now()
        assert isinstance(event, MISPEvent)
        assert event.info == dt.strftime("%Y%m%d ") + 'TIE'
        assert event.publish_timestamp == dt.strftime("%s")
        assert event.timestamp == dt.strftime("%s")
        assert event['timestamp'] == dt.strftime("%s")
        assert event.analysis == 2
        assert event.published
        orgc = MISPOrganisation()
        orgc.from_json(json.dumps({'name': conf.org_name, 'uuid': conf.org_uuid}))
        assert event.orgc == orgc
        assert event.threat_level_id == conf.event_base_thread_level
        assert len(event['Attribute']) == 2

    @pytest.mark.it('Should generate an entry for the manifest file of the stream')
    def test_generate_Manifest_Entry(self):
        test_obs = {"3ad54db13a7b6129902b0ee0acf3e2d1": {
            "data_type": "IPv4",
            "first_seen": "2019-08-21 08:38:29+02:00",
            "last_seen": "2019-08-21 13:38:28+02:00",
            "created_at": "2019-08-21 08:51:20.242089+02:00",
            "updated_at": "2019-08-21 13:51:10.270419+02:00",
            "max_confidence": 40,
            "min_confidence": 40,
            "max_severity": 1,
            "min_severity": 1,
            "n_occurrences": 1,
            "sources": [
                {
                    "pseudonym": "testpseudo1",
                    "name": "testname1"
                }
            ],
            "value": "123.45.67.89/32",
            "categories": [],
            "actors": [],
            "families": []
        },
            "a3475b4484bed2a863720110e8099208": {
                "data_type": "ExactHash",
                "first_seen": "2019-08-21 13:38:17+02:00",
                "last_seen": "2019-08-21 13:38:26+02:00",
                "created_at": "2019-08-21 13:40:02.575150+02:00",
                "updated_at": "2019-08-21 13:40:02.575150+02:00",
                "max_confidence": 90,
                "min_confidence": 90,
                "max_severity": 1,
                "min_severity": 1,
                "n_occurrences": 1,
                "sources": [
                    {
                        "pseudonym": "testpseudo2",
                        "name": "testname2"
                    }
                ],
                "value": "sha1:930A0029225AA4C28B8EF095B679285EAAE27078",
                "categories": [],
                "actors": [],
                "families": [
                    "testfamily"
                ]
            }}
        conf = Config.parse("settings/config.yml")
        event, attr_hashes = MISPHelper.generate_MISP_Event(test_obs, conf, [])
        manifest_entry = MISPHelper.generate_Manifest_Entry(event)
        assert 'Attribute' not in manifest_entry.keys()
        assert 'publish_timestamp' not in manifest_entry.keys()
        assert 'published' not in manifest_entry.keys()
        assert 'uuid' not in manifest_entry.keys()

    @pytest.mark.it('should return the fitting MISP Category for the TIE data_type')
    def test_get_Attribute_Category(self):
        attr = {'data_type': 'ExactHash'}
        assert MISPHelper.get_Attribute_Category(attr) == 'Payload delivery'
        attr = {'data_type': 'DomainName'}
        assert MISPHelper.get_Attribute_Category(attr) == 'Network activity'

    @pytest.mark.it('Should return the matching MISP attribute type for the TIE data_type and value')
    def test_get_Attribute_Type(self):
        attr = {'data_type': 'ExactHash', 'value': 'md5'}
        assert MISPHelper.get_Attribute_Type(attr) == 'md5'
        attr = {'data_type': 'ExactHash', 'value': 'sha1'}
        assert MISPHelper.get_Attribute_Type(attr) == 'sha1'
        attr = {'data_type': 'ExactHash', 'value': 'sha256'}
        assert MISPHelper.get_Attribute_Type(attr) == 'sha256'
        attr = {'data_type': 'EMail', 'value': 'EMail'}
        assert MISPHelper.get_Attribute_Type(attr) == 'email-dst'
        attr = {'data_type': 'DomainName', 'value': 'DomainName'}
        assert MISPHelper.get_Attribute_Type(attr) == 'domain'
        attr = {'data_type': 'URLVerbatim', 'value': 'URLVerbatim'}
        assert MISPHelper.get_Attribute_Type(attr) == 'url'
        attr = {'data_type': 'IPv4', 'value': 'IPv4'}
        assert MISPHelper.get_Attribute_Type(attr) == 'ip-dst'
        attr = {'data_type': 'IPv6', 'value': 'IPv6'}
        assert MISPHelper.get_Attribute_Type(attr) == 'ip-dst'

    @pytest.mark.it('Should remove unnecessary parts of the TIE value to make it MISP compatible')
    def test_get_MISP_Fitted_Value(self):
        assert MISPHelper.get_MISP_Fitted_Value('123.456.789/32', 'ip-dst') == '123.456.789'
        assert MISPHelper.get_MISP_Fitted_Value('md5:testtest', 'md5') == 'testtest'
        assert MISPHelper.get_MISP_Fitted_Value('sha1:testtest', 'sha1') == 'testtest'
        assert MISPHelper.get_MISP_Fitted_Value('sha256:testtest', 'sha256') == 'testtest'
        assert MISPHelper.get_MISP_Fitted_Value('testtest', 'somethingelse') == 'testtest'
