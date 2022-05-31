from PyQt5.QtCore import *

import requests
from OTXv2 import OTXv2
import IndicatorTypes


class ScanWorker(QThread):
    update = pyqtSignal(dict)
    complete = pyqtSignal(int)

    def __init__(self, value, settings):
            super().__init__()
            self.value = value
            self.settings = settings

    def run(self):
        try:
            whois = requests.get('https://ipinfo.io/{}/json?token={}'.format(self.value, self.settings['whois_token']))
            self.update.emit(whois.json())
        except Exception as ex:
            print("Exception with Whois", ex)

        self.complete.emit(1)


class ScanVTWorker(QThread):
    update = pyqtSignal(dict)
    complete = pyqtSignal(int)

    def __init__(self, value, settings):
            super().__init__()
            self.value = value
            self.settings = settings

    def run(self):
        try:
            url = f'https://www.virustotal.com/api/v3/search?query={self.value}'
            headers = {"Accept": "application/json", "X-Apikey": self.settings['vt_token']}
            self.update.emit(requests.get(url, headers=headers).json())
        except Exception as ex:
            print("Exception with Whois", ex)
        self.complete.emit(1)


class ScanOTXWorker(QThread):
    update = pyqtSignal(dict)
    complete = pyqtSignal(int)

    def __init__(self, value, settings):
            super().__init__()
            self.value = value
            self.settings = settings

    def run(self):
        try:
            otx = OTXv2(self.settings['otx'])
            out = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, self.value, "general")
            self.update.emit(out)
        except Exception as ex:
            print("Exception with Whois", ex)
        self.complete.emit(1)


class ScanIPDBWorker(QThread):
    update = pyqtSignal(dict)
    complete = pyqtSignal(int)

    def __init__(self, value, settings):
            super().__init__()
            self.value = value
            self.settings = settings

    def run(self):
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            querystring = {
                'ipAddress': '{}'.format(self.value),
                'maxAgeInDays': '90'
            }

            headers = {
                'Accept': 'application/json',
                'Key': '{}'.format(self.settings['abuse_ip_db'])
            }

            response = requests.request(method='GET', url=url, headers=headers, params=querystring)

            self.update.emit(response.json())
        except Exception as ex:
            print("Exception with Whois", ex)

        self.complete.emit(1)


class ScanMetaWorker(QThread):
    update = pyqtSignal(dict)
    complete = pyqtSignal(int)

    def __init__(self, value, settings):
            super().__init__()
            self.value = value
            self.settings = settings

    def run(self):
        try:
            url = "https://api.metadefender.com/v4/ip/{}".format(self.value)
            headers = {
                'apikey': "{}".format(self.settings['meta_scan'])
            }
            response = requests.request("GET", url, headers=headers)
            self.update.emit(response.json())
        except Exception as ex:
            print("Exception with Whois", ex)

        self.complete.emit(1)


class ScanCVEWorker(QThread):
    update = pyqtSignal(list)
    complete = pyqtSignal(int)

    def run(self):
        try:
            response = requests.request(method='GET', url='https://cve.circl.lu/api/last')
            self.update.emit(response.json())
        except Exception as ex:
            print("Exception with CVE scan", ex)
        self.complete.emit(1)
