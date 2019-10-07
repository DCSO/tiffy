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
        self.__espionagetags = list()
        self.__bottags = list()
        self.__whitelisttags = list()
        self.__cybercrimetags = list()
        self.__phishingtags = list()

    @property
    def c2tags(self):
        return self.__c2tags

    @property
    def malwaretags(self):
        return self.__malwaretags

    @property
    def espionagetags(self):
        return self.__espionagetags

    @property
    def bottags(self):
        return self.__bottags

    @property
    def whitelisttags(self):
        return self.__whitelisttags

    @property
    def cybercrimetags(self):
        return self.__cybercrimetags

    @property
    def phishingtags(self):
        return self.__phishingtags

    @c2tags.setter
    def c2tags(self, value):
        self.__c2tags = value

    @malwaretags.setter
    def malwaretags(self, value):
        self.__malwaretags = value

    @espionagetags.setter
    def espionagetags(self, value):
        self.__espionagetags = value

    @bottags.setter
    def bottags(self, value):
        self.__bottags = value

    @whitelisttags.setter
    def whitelisttags(self, value):
        self.__whitelisttags = value

    @cybercrimetags.setter
    def cybercrimetags(self, value):
        self.__cybercrimetags = value

    @phishingtags.setter
    def phishingtags(self, value):
        self.__phishingtags = value

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

        if "espionage_tags" in raw_tags:
            espionagetags = raw_tags["espionage_tags"]
            for tag in espionagetags:
                tags.espionagetags.append(tag)

        if "bot_tags" in raw_tags:
            bottags = raw_tags["bot_tags"]
            for tag in bottags:
                tags.bottags.append(tag)

        if "whitelist_tags" in raw_tags:
            whitelisttags = raw_tags["whitelist_tags"]
            for tag in whitelisttags:
                tags.whitelisttags.append(tag)

        if "cybercrime_tags" in raw_tags:
            cybercrimetags = raw_tags["cybercrime_tags"]
            for tag in cybercrimetags:
                tags.cybercrimetags.append(tag)

        if "phishing_tags" in raw_tags:
            phishingtags = raw_tags["phishing_tags"]
            for tag in phishingtags:
                tags.phishingtags.append(tag)

        return tags
