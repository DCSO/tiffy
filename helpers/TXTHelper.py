import copy
from datetime import datetime
import hashlib
import json
import uuid


def generate_TXT_File_plain(deduplicated_observations):
    txtdict = list()

    for key, attr in deduplicated_observations.items():
        txtdict.append(attr['value'])

    return txtdict
