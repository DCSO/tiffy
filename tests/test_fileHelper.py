import hashlib
import json

import pytest
from helpers import fileHelper
from pathlib import Path

from contextlib import contextmanager
import os

@contextmanager
def cd(newdir):
    prevdir = os.getcwd()
    os.chdir(os.path.expanduser(newdir))
    try:
        yield
    finally:
        os.chdir(prevdir)


@pytest.mark.describe('FileHelper')
class TestFileHelper:
    @pytest.mark.it('Should write json content to a file named after the event uuid')
    def test_save_events_to_file(self):
        with cd('tests'):
            uuid = '6e3fc308-dc09-4bb2-b120-e0b94bbaa976'
            content = '{"Event" : "TESTEVENT"}'
            path = Path("feed")
            if not path.exists():
                path.mkdir()
            filename = uuid + ".json"
            fileHelper.save_events_to_file(uuid, content)
            outfile = path / filename
            with outfile.open("r") as file:
                read_content = file.read()
                assert read_content == content
            outfile.unlink()
            path.rmdir()

    @pytest.mark.it('Should append manifest json content to an existing manifest file')
    def test_save_manifest_to_file(self):
        with cd('tests'):
            uuid = '6e3fc308-dc09-4bb2-b120-e0b94bbaa976'
            content = {uuid: {"name": "test"}}
            path = Path("feed")
            if not path.exists():
                path.mkdir()
            filename = "manifest.json"
            outfile = path / filename
            existing_content = '{"3324d447-dcb7-4c96-92c2-b0eb0640ef39" : {"name": "ExEvent"}}'
            with outfile.open("w") as file:
                file.write(existing_content)
            fileHelper.save_manifest_to_file(content)
            with outfile.open("r") as file:
                read_content = file.read()
                manifest_json = json.loads(existing_content)
                manifest_json.update(content)
                assert read_content == json.dumps(manifest_json)
            outfile.unlink()
            path.rmdir()

    @pytest.mark.it('Should append attribute hashes to an existing hases.csv file')
    def test_save_hashes(self):
        with cd('tests'):
            uuid = '6e3fc308-dc09-4bb2-b120-e0b94bbaa976'
            existing_hash = [hashlib.md5('testvalueEx'.encode("utf-8")).hexdigest(), 'd640f672-0935-42c8-b710-92bafc5362e5']
            hashes = [[hashlib.md5('testvalue'.encode("utf-8")).hexdigest(), uuid]]
            path = Path("feed")
            if not path.exists():
                path.mkdir()
            filename = "hashes.csv"
            outfile = path / filename
            with outfile.open("w") as file:
                file.write('{},{}\n'.format(existing_hash[0], existing_hash[1]))
            fileHelper.save_hashes(hashes)

            with outfile.open("r") as file:
                read_content = file.read()
                result = '{},{}\n'.format(existing_hash[0], existing_hash[1]) + '{},{}\n'.format(hashes[0][0], hashes[0][1])
                assert read_content == result
            outfile.unlink()
            path.rmdir()
