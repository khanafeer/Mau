# -*- coding: utf-8 -*-
import json
import random
from PyQt5.QtWidgets import QWidget, QMessageBox
from PyQt5 import QtCore, QtGui, QtWidgets


from view.home import Ui_HomeForm
from controller.workers import *


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
        self.stackedWidget.setCurrentIndex(0)
        self.search_wbtn.clicked.connect(lambda :self.stackedWidget.setCurrentIndex(0))
        self.cve_wbtn.clicked.connect(lambda: self.stackedWidget.setCurrentIndex(1))
        self.threats_wbtn.clicked.connect(lambda: self.stackedWidget.setCurrentIndex(2))
        self.settings_wbtn.clicked.connect(lambda: self.stackedWidget.setCurrentIndex(3))
        self.searhc_btn_2.clicked.connect(self.CVE_search)


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

    def CVE_search(self):
        scancve = ScanCVEWorker()
        scancve.start()
        scancve.update.connect(self.cve_search)
        scancve.complete.connect(scancve.exit)

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

    def add_cve_item_gui(self,cveid,date,details):
        self.CVE_W = QtWidgets.QWidget()
        self.CVE_W.setObjectName("cvew"+str(random.randint))
        self.CVE_W.setGeometry(QtCore.QRect(60, 40, 808, 65))
        self.CVE_W.setStyleSheet("background:#4f772d;border-radius: 15px;")
        self.CVE_W.setObjectName("CVE_W")
        self.horizontalLayout_9 = QtWidgets.QHBoxLayout(self.CVE_W)
        self.horizontalLayout_9.setContentsMargins(11, 0, 0, 0)
        self.horizontalLayout_9.setSpacing(0)
        self.horizontalLayout_9.setObjectName("horizontalLayout_9")
        self.cve_lbl = QtWidgets.QLabel(self.CVE_W)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.cve_lbl.sizePolicy().hasHeightForWidth())
        self.cve_lbl.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        self.cve_lbl.setFont(font)
        self.cve_lbl.setOpenExternalLinks(True)
        self.cve_lbl.setObjectName("cve_lbl")
        self.horizontalLayout_9.addWidget(self.cve_lbl)
        self.widget_7 = QtWidgets.QWidget(self.CVE_W)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.widget_7.sizePolicy().hasHeightForWidth())
        self.widget_7.setSizePolicy(sizePolicy)
        self.widget_7.setObjectName("widget_7")
        self.verticalLayout_14 = QtWidgets.QVBoxLayout(self.widget_7)
        self.verticalLayout_14.setObjectName("verticalLayout_14")
        self.cve_nl = QtWidgets.QLabel(self.widget_7)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.cve_nl.setFont(font)
        self.cve_nl.setObjectName("cve_nl")
        self.verticalLayout_14.addWidget(self.cve_nl)
        self.cveml = QtWidgets.QLabel(self.widget_7)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.cveml.setFont(font)
        self.cveml.setObjectName("cveml")
        self.verticalLayout_14.addWidget(self.cveml)
        self.horizontalLayout_9.addWidget(self.widget_7)
        self.widget_10 = QtWidgets.QWidget(self.CVE_W)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(6)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.widget_10.sizePolicy().hasHeightForWidth())
        self.widget_10.setSizePolicy(sizePolicy)
        self.widget_10.setObjectName("widget_10")
        self.verticalLayout_15 = QtWidgets.QVBoxLayout(self.widget_10)
        self.verticalLayout_15.setObjectName("verticalLayout_15")
        self.cve_date_lbl = QtWidgets.QLabel(self.widget_10)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.cve_date_lbl.setFont(font)
        self.cve_date_lbl.setObjectName("cve_date_lbl")
        self.verticalLayout_15.addWidget(self.cve_date_lbl)
        self.cve_details_lbl = QtWidgets.QLabel(self.widget_10)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.cve_details_lbl.setFont(font)
        self.cve_details_lbl.setObjectName("cve_details_lbl")
        self.verticalLayout_15.addWidget(self.cve_details_lbl)
        self.horizontalLayout_9.addWidget(self.widget_10)

        self.cve_lbl.setText(f'<a href="https://www.cvedetails.com/cve/{cveid}/"><font face=verdana color=black>{cveid}</font></a>')
        self.cve_nl.setText("Last Modified")
        self.cveml.setText("Summary")
        self.cve_date_lbl.setText(date)
        self.cve_details_lbl.setText(details)
        return self.CVE_W

    def cve_search(self,latest_cves ):
        self.empty_cve_layout()
        for item in latest_cves:
            cve_btn = self.add_cve_item_gui(str(item['id']).strip(),str(item['Modified']).strip() ,str(item['summary'])[:125])
            self.cve_area.layout().addWidget(cve_btn)
        self.cve_area.layout().addItem(QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding))


    def empty_cve_layout(self):
        try:
            #remove all items(CVE)
            for bt in self.cve_area.findChildren(QWidget):
                bt.deleteLater()
            #remove the last spacer
            self.cve_area.layout().removeItem(self.cve_area.layout().itemAt(self.cve_area.layout().count()-1))
        except Exception as ex:
                print(ex)


