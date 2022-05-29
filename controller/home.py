# -*- coding: utf-8 -*-
import json
import threading
from PyQt5.QtWidgets import QWidget, QListWidgetItem, QLabel, QMessageBox
from PyQt5.QtGui import *
from PyQt5.QtCore import *

import requests
from OTXv2 import OTXv2
import IndicatorTypes

from view.home import Ui_HomeForm


class Home_Page(QWidget, Ui_HomeForm):
    def __init__(self):
        QWidget.__init__(self)
        self.setupUi(self)
        self.searhc_btn.clicked.connect(self.search)
        self.search_edt.returnPressed.connect(self.search)
        self.scanner_w.hide()
        self.red_alert = "background:#e63946;border-radius: 15px;"
        self.green_alert = "background:#4f772d;border-radius: 15px;"
        self.configurations()
        self.search_edt.setFocus()

    def configurations(self):
        try:
            with open("tokens.conf", "r") as tf:
                lines = tf.read()
                self.settings = dict(json.loads(lines))
                self.settings = dict(json.loads(lines))
        except:
            self.dialoge_only("Configuration Error",
                              "Configuration file should be filled with the keys in a JSON format with those keys (vt_token, whois_token, otx, abuse_ip_db, and meta_scan)")

    def dialoge_only(self, x, y):
        msgBox = QMessageBox()
        msgBox.setFixedSize(150, 100)
        msgBox.setWindowTitle('Warning Message')
        msgBox.setText(x)
        msgBox.setInformativeText(y)
        msgBox.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
        return msgBox.exec_()

    def search(self):
        ip_domain = self.search_edt.text()

        self.pre_run(ip_domain)

        scan = ScanWorker(ip_domain, self.settings)
        scan.start()
        scan.update.connect(self.whois_scan)
        scan.complete.connect(scan.exit)

        scanvt = ScanVTWorker(ip_domain, self.settings)
        scanvt.start()
        scanvt.update.connect(self.virus_total)
        scanvt.complete.connect(scanvt.exit)

        scanotx = ScanOTXWorker(ip_domain, self.settings)
        scanotx.start()
        scanotx.update.connect(self.otx_scan)
        scanotx.complete.connect(scanotx.exit)

        scanipdb = ScanIPDBWorker(ip_domain, self.settings)
        scanipdb.start()
        scanipdb.update.connect(self.abuse_ip_db)
        scanipdb.complete.connect(scanipdb.exit)

        scanmeta = ScanMetaWorker(ip_domain, self.settings)
        scanmeta.start()
        scanmeta.update.connect(self.meta_scan)
        scanmeta.complete.connect(scanmeta.exit)


    def whois_scan(self, value):
        self.whois_country.setText(dict(value).get('country') + " - " + dict(value).get('city'))
        self.whois_company.setText(dict(value).get('org'))
        self.whois_hostname.setText(dict(value).get('hostname'))

    def virus_total(self, value):
        stats = value['data'][0]['attributes']['last_analysis_stats']
        if stats:
            if stats['malicious'] > 2:
                self.vt_sts.setText("Not Safe")
                self.vt_w.setStyleSheet(self.red_alert)
            else:
                self.vt_sts.setText("Safe")
                self.vt_w.setStyleSheet(self.green_alert)
            self.vt_count.setText(str(stats['malicious']))
            self.vt_relations.setText(str(stats['suspicious']))
            self.vt_clean.setText(str(stats['undetected'] + stats['harmless']))

    def otx_scan(self, out):
        try:
            if out['pulse_info']['count'] > 0:
                self.otx_sts.setText("Not Safe")
                self.otx_w.setStyleSheet(self.red_alert)
            else:
                self.otx_sts.setText("Safe")
                self.otx_w.setStyleSheet(self.green_alert)
            self.otx_count.setText(str(out['pulse_info']['count']))
            self.otx_iocs.setText(str(out['reputation']))
        except Exception as ex:
            print('Exception with OTX', ex)

    def abuse_ip_db(self, value):

        try:
            reports = value['data']['totalReports']
            last = value['data']['lastReportedAt']
            if reports > 0:
                self.ipdb_sts.setText("Not Safe")
                self.ipdb_w.setStyleSheet(self.red_alert)
            else:
                self.ipdb_sts.setText("Safe")
                self.ipdb_w.setStyleSheet(self.green_alert)
            self.ipdb_count.setText(str(reports))
            self.ipdb_date.setText(last)

        except Exception as ex:
            print('Exception With Abuse IPDB', ex)

    def meta_scan(self, value):
        try:

            reports = value["lookup_results"]['detected_by']
            if reports > 0:
                self.falcon_sts.setText("Not Safe")
                self.falcon_w.setStyleSheet(self.red_alert)
            else:
                self.falcon_w.setStyleSheet(self.green_alert)
                self.falcon_sts.setText("Safe")
            self.falcon_count.setText(str(reports))
            self.falcon_date.setText(value["lookup_results"]["start_time"])
        except Exception as ex:
            print('Exception with MetaDefender', ex)

    def pre_run(self,value):
        self.scanner_w.show()
        #whois
        self.whois_lbl.setText(
            f"<a href=\"https://ipinfo.io/products/whois-api\"><font face=verdana color=black>Whois </font></a>")
        self.whois_country.setText("")
        self.whois_company.setText("")
        self.whois_hostname.setText("")

        #vt
        self.vt_lbl.setText(
            f"<a href=\"https://www.virustotal.com/gui/search/{value}\"><font face=verdana color=black>Virus Total </font></a>")
        self.vt_sts.setText("")
        self.vt_count.setText("")
        self.vt_relations.setText("")
        self.vt_clean.setText("")

        #otx
        self.otx_lbl.setText(
            f"<a href=\"https://otx.alienvault.com/indicator/ip/{value}\"><font face=verdana color=black> OTX </font></a>")
        self.otx_sts.setText("")
        self.otx_count.setText("")
        self.otx_iocs.setText("")

        #IPDB
        self.ipdb_lbl.setText(
            f"<a href=\"https://www.abuseipdb.com/check/{value}\"><font face=verdana color=black> Abuse IPDB </font></a>")
        self.ipdb_sts.setText("")
        self.ipdb_count.setText("")
        self.ipdb_date.setText("")

        #mrta
        self.falcon_lbl.setText(
            f"<a href=\"https://metadefender.opswat.com/\"><font face=verdana color=black> Meta Defender </font></a>")
        self.falcon_sts.setText("")
        self.falcon_count.setText("")
        self.falcon_date.setText("")

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
