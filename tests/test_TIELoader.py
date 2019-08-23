import hashlib

import pytest

from TIELoader import TIELoader


@pytest.mark.describe('TIELoader')
class TestTIELoader:
    @pytest.mark.it('Should successfully deduplicate Observations from response')
    def test_deduplicate_observations(self):
        test_response_observations = [{
            "seq": 6211635542,
            "updated_at": "2019-08-20 10:09:05.446414+02:00",
            "created_at": "2018-04-22 14:00:42.129490+02:00",
            "confidence": 80,
            "families": ['testfamily1'],
            "actors": ['testactor1'],
            "severity": 0,
            "id": "46fa290b-8fa7-4fd9-9c81-0943164bf6b9",
            "categories": [
                "whitelist"
            ],
            "event": {
                "id": "2f76d2e1-8f86-4df7-b781-cf70c751256a",
                "memo": "test_memo1"
            },
            "last_seen": "2019-08-20 09:39:44.252599+02:00",
            "value": "*.testval.ue",
            "data_type": "DomainName",
            "first_seen": "2018-04-22 13:55:47.365489+02:00",
            "source": {
                "pseudonym": "testpseudo1",
                "name": "testname1"
            }
        },
            {
                "seq": 6211635545,
                "updated_at": "2019-08-20 12:09:05.446414+02:00",
                "created_at": "2018-04-22 15:00:42.129490+02:00",
                "confidence": 80,
                "families": ['testfamily2'],
                "actors": ['testactor2'],
                "severity": 0,
                "id": "ee77f2ac-ec5a-4f27-b53e-1f27b506abf5",
                "categories": [
                    "whitelist"
                ],
                "event": {
                    "id": "2f76d2e1-8f86-4df7-b781-cf70c751256a",
                    "memo": "test_memo1"
                },
                "last_seen": "2019-08-20 10:39:44.252599+02:00",
                "value": "*.testval.ue",
                "data_type": "DomainName",
                "first_seen": "2018-04-22 14:55:47.365489+02:00",
                "source": {
                    "pseudonym": "testpseudo1",
                    "name": "testname1"
                }
            }
        ]

        deduplicated = dict()
        TIELoader.deduplicate_observations(test_response_observations, deduplicated)
        hashed_value = hashlib.md5("*.testval.ue".encode())
        deduplicated_ioc = deduplicated[hashed_value.hexdigest()]
        assert deduplicated_ioc['value'] == '*.testval.ue'
        assert deduplicated_ioc['categories'] == ['whitelist']
        assert deduplicated_ioc['actors'] == ['testactor1', 'testactor2']
        assert deduplicated_ioc['families'] == ['testfamily1', 'testfamily2']
        assert deduplicated_ioc['sources'] == [{
            "pseudonym": "testpseudo1",
            "name": "testname1"
        }]
        assert deduplicated_ioc['max_severity'] == 0
        assert deduplicated_ioc['min_severity'] == 0
        assert deduplicated_ioc['max_confidence'] == 80
        assert deduplicated_ioc['min_confidence'] == 80
        assert deduplicated_ioc['n_occurrences'] == 2
        assert deduplicated_ioc['first_seen'] == "2018-04-22 13:55:47.365489+02:00"
        assert deduplicated_ioc['last_seen'] == "2019-08-20 10:39:44.252599+02:00"
        assert deduplicated_ioc['created_at'] == "2018-04-22 14:00:42.129490+02:00"
        assert deduplicated_ioc['updated_at'] == "2019-08-20 12:09:05.446414+02:00"

    @pytest.mark.it('Should not deduplicate two Observations with different values into the same ioc')
    def test_deduplicate_observations_diff_values(self):
        test_response_observations = [{
            "seq": 6211635542,
            "updated_at": "2019-08-20 10:09:05.446414+02:00",
            "created_at": "2018-04-22 14:00:42.129490+02:00",
            "confidence": 80,
            "families": ['testfamily1'],
            "actors": ['testactor1'],
            "severity": 0,
            "id": "46fa290b-8fa7-4fd9-9c81-0943164bf6b9",
            "categories": [
                "whitelist"
            ],
            "event": {
                "id": "2f76d2e1-8f86-4df7-b781-cf70c751256a",
                "memo": "test_memo1"
            },
            "last_seen": "2019-08-20 09:39:44.252599+02:00",
            "value": "*.testval.ue2",
            "data_type": "DomainName",
            "first_seen": "2018-04-22 13:55:47.365489+02:00",
            "source": {
                "pseudonym": "testpseudo1",
                "name": "testname1"
            }
        },
            {
                "seq": 6211635545,
                "updated_at": "2019-08-20 12:09:05.446414+02:00",
                "created_at": "2018-04-22 15:00:42.129490+02:00",
                "confidence": 80,
                "families": ['testfamily2'],
                "actors": ['testactor2'],
                "severity": 0,
                "id": "ee77f2ac-ec5a-4f27-b53e-1f27b506abf5",
                "categories": [
                    "whitelist"
                ],
                "event": {
                    "id": "2f76d2e1-8f86-4df7-b781-cf70c751256a",
                    "memo": "test_memo1"
                },
                "last_seen": "2019-08-20 10:39:44.252599+02:00",
                "value": "*.testval.ue",
                "data_type": "DomainName",
                "first_seen": "2018-04-22 14:55:47.365489+02:00",
                "source": {
                    "pseudonym": "testpseudo1",
                    "name": "testname1"
                }
            }
        ]

        deduplicated = dict()
        TIELoader.deduplicate_observations(test_response_observations, deduplicated)
        assert len(deduplicated) == 2
