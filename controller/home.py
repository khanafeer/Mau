# -*- coding: utf-8 -*-
import json

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5 import QtCore
from PyQt5 import QtGui
from PyQt5.QtWidgets import QWidget, QListWidgetItem, QLabel, QMessageBox

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
        ip_domain = self.search_edt.text().strip()
        self.whois_scan(ip_domain)
        self.virus_total(ip_domain)
        self.otx_scan(ip_domain)
        self.abuse_ip_db(ip_domain)
        self.meta_scan(ip_domain)
        self.scanner_w.show()

    def whois_scan(self, value):
        self.whois_lbl.setText(
            f"<a href=\"https://ipinfo.io/products/whois-api\"><font face=verdana color=black>Whois </font></a>")
        self.whois_country.setText("")
        self.whois_company.setText("")
        self.whois_hostname.setText("")
        try:
            g = requests.get('https://ipinfo.io/{}/json?token={}'.format(value,self.settings['whois_token']))
            print(g.json())
            self.whois_country.setText(dict(g.json()).get('country') + " - "+ dict(g.json()).get('city'))
            self.whois_company.setText(dict(g.json()).get('org'))
            self.whois_hostname.setText(dict(g.json()).get('hostname'))
        except Exception as ex:
            print("Exception with Whois", ex)

    def virus_total(self, value):
        self.vt_lbl.setText(
            f"<a href=\"https://www.virustotal.com/gui/search/{value}\"><font face=verdana color=black>Virus Total </font></a>")
        self.vt_sts.setText("")
        self.vt_count.setText("")
        self.vt_relations.setText("")
        self.vt_clean.setText("")
        try:
            api_key = self.settings['vt_token']

            url = f'https://www.virustotal.com/api/v3/search?query={value}'
            headers = {"Accept": "application/json", "X-Apikey": api_key}
            vtresponse_dict = requests.get(url,headers=headers).json()
            stats = vtresponse_dict['data'][0]['attributes']['last_analysis_stats']
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

        except Exception as ex:
            print("Exceptio with VT", ex)

    def otx_scan(self, value):
        self.otx_lbl.setText(
            f"<a href=\"https://otx.alienvault.com/indicator/ip/{value}\"><font face=verdana color=black> OTX </font></a>")
        self.otx_sts.setText("")
        self.otx_count.setText("")
        self.otx_iocs.setText("")
        try:
            otx = OTXv2(self.settings['otx'])
            out = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, value, "general")
            if out['pulse_info']['count'] > 0:
                self.otx_sts.setText("Not Safe")
                self.otx_w.setStyleSheet(self.red_alert)
            else:
                self.otx_sts.setText("Safe")
                self.otx_w.setStyleSheet(self.green_alert)
            self.otx_count.setText(str(out['pulse_info']['count']))
            self.otx_iocs.setText(str(out['reputation']))

            print(out)
        except Exception as ex:
            print('Exception with OTX', ex)

    def abuse_ip_db(self, value):
        self.ipdb_lbl.setText(
            f"<a href=\"https://www.abuseipdb.com/check/{value}\"><font face=verdana color=black> Abuse IPDB </font></a>")
        self.ipdb_sts.setText("")
        self.ipdb_count.setText("")
        self.ipdb_date.setText("")
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            querystring = {
                'ipAddress': '{}'.format(value),
                'maxAgeInDays': '90'
            }

            headers = {
                'Accept': 'application/json',
                'Key': '{}'.format(self.settings['abuse_ip_db'])
            }

            response = requests.request(method='GET', url=url, headers=headers, params=querystring)

            # Formatted output
            reports = response.json()['data']['totalReports']
            last = response.json()['data']['lastReportedAt']
            if reports > 0:
                self.ipdb_sts.setText("Not Safe")
                self.ipdb_w.setStyleSheet(self.red_alert)
            else:
                self.ipdb_sts.setText("Safe")
                self.ipdb_w.setStyleSheet(self.green_alert)
            self.ipdb_count.setText(str(reports))
            self.ipdb_date.setText(last)

        except Exception as ex:
            print('Exception With Abuse IPDB',ex)

    def meta_scan(self,value):
        self.falcon_lbl.setText(
            f"<a href=\"https://metadefender.opswat.com/\"><font face=verdana color=black> Meta Defender </font></a>")
        self.falcon_sts.setText("")
        self.falcon_count.setText("")
        self.falcon_date.setText("")

        try:
            url = "https://api.metadefender.com/v4/ip/{}".format(value)
            headers = {
                'apikey': "{}".format(self.settings['meta_scan'])
            }
            response = requests.request("GET", url, headers=headers)
            print(response.json())
            reports = response.json()["lookup_results"]['detected_by']
            if reports > 0:
                self.falcon_sts.setText("Not Safe")
                self.falcon_w.setStyleSheet(self.red_alert)
            else:
                self.falcon_w.setStyleSheet(self.green_alert)
                self.falcon_sts.setText("Safe")
            self.falcon_count.setText(str(reports))
            self.falcon_date.setText(response.json()["lookup_results"]["start_time"])
        except Exception as ex:
            print('Exception with MetaDefender',ex)

