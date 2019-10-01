"""
DCSO TIE2MISP Parser
Copyright (c) 2017, DCSO GmbH
"""
import yaml
import warnings


class Tags:
    def __init__(self):
        self.__c2tags = list()
        self.__malwaretags = list()


    @property
    def c2tags(self):
        return self.__c2tags

    @property
    def malwaretags(self):
        return self.__malwaretags

    @c2tags.setter
    def c2tags(self, value):
        self.__c2tags = value

    @malwaretags.setter
    def malwaretags(self, value):
        self.__malwaretags = value

    @staticmethod
    def parse(tagfile):

        tags = Tags()

        # Load Config
        tag_file = open(tagfile, "r", encoding="utf-8")
        raw_tags = yaml.load(tag_file, Loader=yaml.FullLoader)

        if "c2_tags" in raw_tags:
            c2tags = raw_tags["c2_tags"]
            for tag in c2tags:
                tags.c2tags.append(tag)

        if "malware_tags" in raw_tags:
            malwaretags = raw_tags["malware_tags"]
            for tag in malwaretags:
                tags.malwaretags.append(tag)

        return tags


