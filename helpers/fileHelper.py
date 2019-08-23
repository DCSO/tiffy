import json
import logging
import os
from pathlib import Path


def save_events_to_file(uuid, json_output):
    out_path = Path("feed")
    if not out_path.exists():
        out_path.mkdir()
    filename = str(uuid) + ".json"
    outfile = out_path / filename
    logging.info("Saved attributes as JSON-File: " + str(outfile))
    with outfile.open("w") as text_file:
        text_file.write(json_output)


def save_manifest_to_file(manifest_output):
    out_path = Path("feed")
    if not out_path.exists():
        out_path.mkdir()
    manifest_file = out_path / 'manifest.json'
    manifest_content = ''
    if manifest_file.exists():
        with manifest_file.open("r") as manifest:
            manifest.seek(0)
            manifest_content = manifest.read()
    with manifest_file.open("w") as manifest:
        if manifest_content != '':
            manifest_json = json.loads(manifest_content)
            manifest_json.update(manifest_output)
        else:
            manifest_json = manifest_output
        manifest.write(json.dumps(manifest_json))


def save_hashes(attr_hashes):
    out_path = Path("feed")
    if not out_path.exists():
        out_path.mkdir()
    if not attr_hashes:
        return False
    try:
        hashFile = open(os.path.join(out_path, 'hashes.csv'), 'a')
        for element in attr_hashes:
            hashFile.write('{},{}\n'.format(element[0], element[1]))
        hashFile.close()
    except Exception as e:
        print(e)
