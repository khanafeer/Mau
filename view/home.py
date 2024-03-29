# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '.\ui\home.ui'
#
# Created by: PyQt5 UI code generator 5.15.6
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_HomeForm(object):
    def setupUi(self, HomeForm):
        HomeForm.setObjectName("HomeForm")
        HomeForm.resize(1207, 820)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(".\\ui\\../img/Mau.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        HomeForm.setWindowIcon(icon)
        HomeForm.setStyleSheet("background: #202940;\n"
"color: #fff;")
        self.verticalLayout = QtWidgets.QVBoxLayout(HomeForm)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setSpacing(5)
        self.verticalLayout.setObjectName("verticalLayout")
        self.widget_2 = QtWidgets.QWidget(HomeForm)
        self.widget_2.setObjectName("widget_2")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.widget_2)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.label = QtWidgets.QLabel(self.widget_2)
        font = QtGui.QFont()
        font.setPointSize(20)
        self.label.setFont(font)
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setObjectName("label")
        self.verticalLayout_2.addWidget(self.label)
        self.label_2 = QtWidgets.QLabel(self.widget_2)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.label_2.setFont(font)
        self.label_2.setAlignment(QtCore.Qt.AlignCenter)
        self.label_2.setObjectName("label_2")
        self.verticalLayout_2.addWidget(self.label_2)
        self.verticalLayout.addWidget(self.widget_2)
        self.line = QtWidgets.QFrame(HomeForm)
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.verticalLayout.addWidget(self.line)
        self.stackedWidget = QtWidgets.QStackedWidget(HomeForm)
        self.stackedWidget.setMouseTracking(True)
        self.stackedWidget.setAcceptDrops(True)
        self.stackedWidget.setAutoFillBackground(False)
        self.stackedWidget.setObjectName("stackedWidget")
        self.scanner_sw = QtWidgets.QWidget()
        self.scanner_sw.setObjectName("scanner_sw")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.scanner_sw)
        self.verticalLayout_3.setContentsMargins(-1, 0, -1, 0)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.widget = QtWidgets.QWidget(self.scanner_sw)
        self.widget.setStyleSheet("")
        self.widget.setObjectName("widget")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.widget)
        self.horizontalLayout.setObjectName("horizontalLayout")
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.search_edt = QtWidgets.QLineEdit(self.widget)
        self.search_edt.setMinimumSize(QtCore.QSize(0, 40))
        self.search_edt.setStyleSheet("border: 1 solid #fff;\n"
"border-radius: 10;")
        self.search_edt.setAlignment(QtCore.Qt.AlignCenter)
        self.search_edt.setObjectName("search_edt")
        self.horizontalLayout.addWidget(self.search_edt)
        self.searhc_btn = QtWidgets.QPushButton(self.widget)
        self.searhc_btn.setMinimumSize(QtCore.QSize(90, 40))
        self.searhc_btn.setStyleSheet("border: 1 solid #fff;\n"
"border-radius: 10;")
        self.searhc_btn.setDefault(False)
        self.searhc_btn.setFlat(False)
        self.searhc_btn.setObjectName("searhc_btn")
        self.horizontalLayout.addWidget(self.searhc_btn)
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem1)
        self.verticalLayout_3.addWidget(self.widget)
        self.widget_13 = QtWidgets.QWidget(self.scanner_sw)
        self.widget_13.setObjectName("widget_13")
        self.horizontalLayout_11 = QtWidgets.QHBoxLayout(self.widget_13)
        self.horizontalLayout_11.setObjectName("horizontalLayout_11")
        spacerItem2 = QtWidgets.QSpacerItem(250, 20, QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_11.addItem(spacerItem2)
        self.scanner_w = QtWidgets.QScrollArea(self.widget_13)
        self.scanner_w.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.scanner_w.setLineWidth(1)
        self.scanner_w.setWidgetResizable(True)
        self.scanner_w.setObjectName("scanner_w")
        self.scrollAreaWidgetContents_3 = QtWidgets.QWidget()
        self.scrollAreaWidgetContents_3.setGeometry(QtCore.QRect(0, 0, 647, 564))
        self.scrollAreaWidgetContents_3.setObjectName("scrollAreaWidgetContents_3")
        self.verticalLayout_19 = QtWidgets.QVBoxLayout(self.scrollAreaWidgetContents_3)
        self.verticalLayout_19.setObjectName("verticalLayout_19")
        self.whois_w = QtWidgets.QWidget(self.scrollAreaWidgetContents_3)
        self.whois_w.setStyleSheet("background:#4f772d;\n"
"border-radius: 15px;")
        self.whois_w.setObjectName("whois_w")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.whois_w)
        self.horizontalLayout_2.setContentsMargins(11, 0, -1, 0)
        self.horizontalLayout_2.setSpacing(0)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.whois_lbl = QtWidgets.QLabel(self.whois_w)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(2)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.whois_lbl.sizePolicy().hasHeightForWidth())
        self.whois_lbl.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        self.whois_lbl.setFont(font)
        self.whois_lbl.setOpenExternalLinks(True)
        self.whois_lbl.setObjectName("whois_lbl")
        self.horizontalLayout_2.addWidget(self.whois_lbl)
        self.widget_5 = QtWidgets.QWidget(self.whois_w)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(2)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.widget_5.sizePolicy().hasHeightForWidth())
        self.widget_5.setSizePolicy(sizePolicy)
        self.widget_5.setObjectName("widget_5")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.widget_5)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.label_4 = QtWidgets.QLabel(self.widget_5)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_4.setFont(font)
        self.label_4.setObjectName("label_4")
        self.verticalLayout_4.addWidget(self.label_4)
        self.label_5 = QtWidgets.QLabel(self.widget_5)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_5.setFont(font)
        self.label_5.setObjectName("label_5")
        self.verticalLayout_4.addWidget(self.label_5)
        self.label_19 = QtWidgets.QLabel(self.widget_5)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_19.setFont(font)
        self.label_19.setObjectName("label_19")
        self.verticalLayout_4.addWidget(self.label_19)
        self.horizontalLayout_2.addWidget(self.widget_5)
        self.widget_6 = QtWidgets.QWidget(self.whois_w)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(6)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.widget_6.sizePolicy().hasHeightForWidth())
        self.widget_6.setSizePolicy(sizePolicy)
        self.widget_6.setObjectName("widget_6")
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self.widget_6)
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.whois_country = QtWidgets.QLabel(self.widget_6)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.whois_country.setFont(font)
        self.whois_country.setObjectName("whois_country")
        self.verticalLayout_5.addWidget(self.whois_country)
        self.whois_company = QtWidgets.QLabel(self.widget_6)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.whois_company.setFont(font)
        self.whois_company.setObjectName("whois_company")
        self.verticalLayout_5.addWidget(self.whois_company)
        self.whois_hostname = QtWidgets.QLabel(self.widget_6)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.whois_hostname.setFont(font)
        self.whois_hostname.setObjectName("whois_hostname")
        self.verticalLayout_5.addWidget(self.whois_hostname)
        self.horizontalLayout_2.addWidget(self.widget_6)
        self.verticalLayout_19.addWidget(self.whois_w)
        self.vt_w = QtWidgets.QWidget(self.scrollAreaWidgetContents_3)
        self.vt_w.setStyleSheet("background:#e63946;\n"
"border-radius: 15px;")
        self.vt_w.setObjectName("vt_w")
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout(self.vt_w)
        self.horizontalLayout_3.setContentsMargins(-1, 0, -1, 0)
        self.horizontalLayout_3.setSpacing(0)
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.vt_lbl = QtWidgets.QLabel(self.vt_w)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(2)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.vt_lbl.sizePolicy().hasHeightForWidth())
        self.vt_lbl.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        self.vt_lbl.setFont(font)
        self.vt_lbl.setOpenExternalLinks(True)
        self.vt_lbl.setObjectName("vt_lbl")
        self.horizontalLayout_3.addWidget(self.vt_lbl)
        self.widget_8 = QtWidgets.QWidget(self.vt_w)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(2)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.widget_8.sizePolicy().hasHeightForWidth())
        self.widget_8.setSizePolicy(sizePolicy)
        self.widget_8.setObjectName("widget_8")
        self.verticalLayout_6 = QtWidgets.QVBoxLayout(self.widget_8)
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.label_8 = QtWidgets.QLabel(self.widget_8)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_8.setFont(font)
        self.label_8.setObjectName("label_8")
        self.verticalLayout_6.addWidget(self.label_8)
        self.label_9 = QtWidgets.QLabel(self.widget_8)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_9.setFont(font)
        self.label_9.setObjectName("label_9")
        self.verticalLayout_6.addWidget(self.label_9)
        self.label_10 = QtWidgets.QLabel(self.widget_8)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_10.setFont(font)
        self.label_10.setObjectName("label_10")
        self.verticalLayout_6.addWidget(self.label_10)
        self.label_3 = QtWidgets.QLabel(self.widget_8)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_3.setFont(font)
        self.label_3.setObjectName("label_3")
        self.verticalLayout_6.addWidget(self.label_3)
        self.horizontalLayout_3.addWidget(self.widget_8)
        self.widget_9 = QtWidgets.QWidget(self.vt_w)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(6)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.widget_9.sizePolicy().hasHeightForWidth())
        self.widget_9.setSizePolicy(sizePolicy)
        self.widget_9.setObjectName("widget_9")
        self.verticalLayout_7 = QtWidgets.QVBoxLayout(self.widget_9)
        self.verticalLayout_7.setObjectName("verticalLayout_7")
        self.vt_sts = QtWidgets.QLabel(self.widget_9)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.vt_sts.setFont(font)
        self.vt_sts.setObjectName("vt_sts")
        self.verticalLayout_7.addWidget(self.vt_sts)
        self.vt_count = QtWidgets.QLabel(self.widget_9)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.vt_count.setFont(font)
        self.vt_count.setObjectName("vt_count")
        self.verticalLayout_7.addWidget(self.vt_count)
        self.vt_relations = QtWidgets.QLabel(self.widget_9)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.vt_relations.setFont(font)
        self.vt_relations.setObjectName("vt_relations")
        self.verticalLayout_7.addWidget(self.vt_relations)
        self.vt_clean = QtWidgets.QLabel(self.widget_9)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.vt_clean.setFont(font)
        self.vt_clean.setObjectName("vt_clean")
        self.verticalLayout_7.addWidget(self.vt_clean)
        self.horizontalLayout_3.addWidget(self.widget_9)
        self.verticalLayout_19.addWidget(self.vt_w)
        self.otx_w = QtWidgets.QWidget(self.scrollAreaWidgetContents_3)
        self.otx_w.setStyleSheet("background:#e63946;\n"
"border-radius: 15px;")
        self.otx_w.setObjectName("otx_w")
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout(self.otx_w)
        self.horizontalLayout_4.setContentsMargins(-1, 0, -1, 0)
        self.horizontalLayout_4.setSpacing(0)
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.otx_lbl = QtWidgets.QLabel(self.otx_w)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(2)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.otx_lbl.sizePolicy().hasHeightForWidth())
        self.otx_lbl.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        self.otx_lbl.setFont(font)
        self.otx_lbl.setOpenExternalLinks(True)
        self.otx_lbl.setObjectName("otx_lbl")
        self.horizontalLayout_4.addWidget(self.otx_lbl)
        self.widget_11 = QtWidgets.QWidget(self.otx_w)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(2)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.widget_11.sizePolicy().hasHeightForWidth())
        self.widget_11.setSizePolicy(sizePolicy)
        self.widget_11.setObjectName("widget_11")
        self.verticalLayout_8 = QtWidgets.QVBoxLayout(self.widget_11)
        self.verticalLayout_8.setObjectName("verticalLayout_8")
        self.label_12 = QtWidgets.QLabel(self.widget_11)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_12.setFont(font)
        self.label_12.setObjectName("label_12")
        self.verticalLayout_8.addWidget(self.label_12)
        self.label_13 = QtWidgets.QLabel(self.widget_11)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_13.setFont(font)
        self.label_13.setObjectName("label_13")
        self.verticalLayout_8.addWidget(self.label_13)
        self.label_14 = QtWidgets.QLabel(self.widget_11)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_14.setFont(font)
        self.label_14.setObjectName("label_14")
        self.verticalLayout_8.addWidget(self.label_14)
        self.horizontalLayout_4.addWidget(self.widget_11)
        self.widget_12 = QtWidgets.QWidget(self.otx_w)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(6)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.widget_12.sizePolicy().hasHeightForWidth())
        self.widget_12.setSizePolicy(sizePolicy)
        self.widget_12.setObjectName("widget_12")
        self.verticalLayout_9 = QtWidgets.QVBoxLayout(self.widget_12)
        self.verticalLayout_9.setObjectName("verticalLayout_9")
        self.otx_sts = QtWidgets.QLabel(self.widget_12)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.otx_sts.setFont(font)
        self.otx_sts.setObjectName("otx_sts")
        self.verticalLayout_9.addWidget(self.otx_sts)
        self.otx_count = QtWidgets.QLabel(self.widget_12)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.otx_count.setFont(font)
        self.otx_count.setObjectName("otx_count")
        self.verticalLayout_9.addWidget(self.otx_count)
        self.otx_iocs = QtWidgets.QLabel(self.widget_12)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.otx_iocs.setFont(font)
        self.otx_iocs.setObjectName("otx_iocs")
        self.verticalLayout_9.addWidget(self.otx_iocs)
        self.horizontalLayout_4.addWidget(self.widget_12)
        self.verticalLayout_19.addWidget(self.otx_w)
        self.ipdb_w = QtWidgets.QWidget(self.scrollAreaWidgetContents_3)
        self.ipdb_w.setStyleSheet("background:#e63946;\n"
"border-radius: 15px;")
        self.ipdb_w.setObjectName("ipdb_w")
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout(self.ipdb_w)
        self.horizontalLayout_6.setContentsMargins(-1, 0, -1, 0)
        self.horizontalLayout_6.setSpacing(0)
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        self.ipdb_lbl = QtWidgets.QLabel(self.ipdb_w)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(2)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.ipdb_lbl.sizePolicy().hasHeightForWidth())
        self.ipdb_lbl.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        self.ipdb_lbl.setFont(font)
        self.ipdb_lbl.setOpenExternalLinks(True)
        self.ipdb_lbl.setObjectName("ipdb_lbl")
        self.horizontalLayout_6.addWidget(self.ipdb_lbl)
        self.widget_14 = QtWidgets.QWidget(self.ipdb_w)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(2)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.widget_14.sizePolicy().hasHeightForWidth())
        self.widget_14.setSizePolicy(sizePolicy)
        self.widget_14.setObjectName("widget_14")
        self.verticalLayout_10 = QtWidgets.QVBoxLayout(self.widget_14)
        self.verticalLayout_10.setObjectName("verticalLayout_10")
        self.label_16 = QtWidgets.QLabel(self.widget_14)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_16.setFont(font)
        self.label_16.setObjectName("label_16")
        self.verticalLayout_10.addWidget(self.label_16)
        self.label_17 = QtWidgets.QLabel(self.widget_14)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_17.setFont(font)
        self.label_17.setObjectName("label_17")
        self.verticalLayout_10.addWidget(self.label_17)
        self.label_18 = QtWidgets.QLabel(self.widget_14)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_18.setFont(font)
        self.label_18.setObjectName("label_18")
        self.verticalLayout_10.addWidget(self.label_18)
        self.horizontalLayout_6.addWidget(self.widget_14)
        self.widget_15 = QtWidgets.QWidget(self.ipdb_w)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(6)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.widget_15.sizePolicy().hasHeightForWidth())
        self.widget_15.setSizePolicy(sizePolicy)
        self.widget_15.setObjectName("widget_15")
        self.verticalLayout_11 = QtWidgets.QVBoxLayout(self.widget_15)
        self.verticalLayout_11.setObjectName("verticalLayout_11")
        self.ipdb_sts = QtWidgets.QLabel(self.widget_15)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.ipdb_sts.setFont(font)
        self.ipdb_sts.setObjectName("ipdb_sts")
        self.verticalLayout_11.addWidget(self.ipdb_sts)
        self.ipdb_count = QtWidgets.QLabel(self.widget_15)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.ipdb_count.setFont(font)
        self.ipdb_count.setObjectName("ipdb_count")
        self.verticalLayout_11.addWidget(self.ipdb_count)
        self.ipdb_date = QtWidgets.QLabel(self.widget_15)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.ipdb_date.setFont(font)
        self.ipdb_date.setObjectName("ipdb_date")
        self.verticalLayout_11.addWidget(self.ipdb_date)
        self.horizontalLayout_6.addWidget(self.widget_15)
        self.verticalLayout_19.addWidget(self.ipdb_w)
        self.falcon_w = QtWidgets.QWidget(self.scrollAreaWidgetContents_3)
        self.falcon_w.setStyleSheet("background:#e63946;\n"
"border-radius: 15px;")
        self.falcon_w.setObjectName("falcon_w")
        self.horizontalLayout_7 = QtWidgets.QHBoxLayout(self.falcon_w)
        self.horizontalLayout_7.setContentsMargins(-1, 0, -1, 0)
        self.horizontalLayout_7.setSpacing(0)
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        self.falcon_lbl = QtWidgets.QLabel(self.falcon_w)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(2)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.falcon_lbl.sizePolicy().hasHeightForWidth())
        self.falcon_lbl.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        self.falcon_lbl.setFont(font)
        self.falcon_lbl.setOpenExternalLinks(True)
        self.falcon_lbl.setObjectName("falcon_lbl")
        self.horizontalLayout_7.addWidget(self.falcon_lbl)
        self.widget_17 = QtWidgets.QWidget(self.falcon_w)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(2)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.widget_17.sizePolicy().hasHeightForWidth())
        self.widget_17.setSizePolicy(sizePolicy)
        self.widget_17.setObjectName("widget_17")
        self.verticalLayout_12 = QtWidgets.QVBoxLayout(self.widget_17)
        self.verticalLayout_12.setObjectName("verticalLayout_12")
        self.label_21 = QtWidgets.QLabel(self.widget_17)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_21.setFont(font)
        self.label_21.setObjectName("label_21")
        self.verticalLayout_12.addWidget(self.label_21)
        self.label_22 = QtWidgets.QLabel(self.widget_17)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_22.setFont(font)
        self.label_22.setObjectName("label_22")
        self.verticalLayout_12.addWidget(self.label_22)
        self.label_23 = QtWidgets.QLabel(self.widget_17)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_23.setFont(font)
        self.label_23.setObjectName("label_23")
        self.verticalLayout_12.addWidget(self.label_23)
        self.horizontalLayout_7.addWidget(self.widget_17)
        self.widget_18 = QtWidgets.QWidget(self.falcon_w)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(6)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.widget_18.sizePolicy().hasHeightForWidth())
        self.widget_18.setSizePolicy(sizePolicy)
        self.widget_18.setObjectName("widget_18")
        self.verticalLayout_13 = QtWidgets.QVBoxLayout(self.widget_18)
        self.verticalLayout_13.setObjectName("verticalLayout_13")
        self.falcon_sts = QtWidgets.QLabel(self.widget_18)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.falcon_sts.setFont(font)
        self.falcon_sts.setObjectName("falcon_sts")
        self.verticalLayout_13.addWidget(self.falcon_sts)
        self.falcon_count = QtWidgets.QLabel(self.widget_18)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.falcon_count.setFont(font)
        self.falcon_count.setObjectName("falcon_count")
        self.verticalLayout_13.addWidget(self.falcon_count)
        self.falcon_date = QtWidgets.QLabel(self.widget_18)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.falcon_date.setFont(font)
        self.falcon_date.setObjectName("falcon_date")
        self.verticalLayout_13.addWidget(self.falcon_date)
        self.horizontalLayout_7.addWidget(self.widget_18)
        self.verticalLayout_19.addWidget(self.falcon_w)
        spacerItem3 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout_19.addItem(spacerItem3)
        self.scanner_w.setWidget(self.scrollAreaWidgetContents_3)
        self.horizontalLayout_11.addWidget(self.scanner_w)
        spacerItem4 = QtWidgets.QSpacerItem(250, 20, QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_11.addItem(spacerItem4)
        self.verticalLayout_3.addWidget(self.widget_13)
        self.stackedWidget.addWidget(self.scanner_sw)
        self.cve_sw = QtWidgets.QWidget()
        self.cve_sw.setObjectName("cve_sw")
        self.verticalLayout_26 = QtWidgets.QVBoxLayout(self.cve_sw)
        self.verticalLayout_26.setContentsMargins(-1, 0, -1, 0)
        self.verticalLayout_26.setObjectName("verticalLayout_26")
        self.widget_4 = QtWidgets.QWidget(self.cve_sw)
        self.widget_4.setStyleSheet("")
        self.widget_4.setObjectName("widget_4")
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout(self.widget_4)
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        spacerItem5 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_5.addItem(spacerItem5)
        self.searhc_btn_2 = QtWidgets.QPushButton(self.widget_4)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.searhc_btn_2.sizePolicy().hasHeightForWidth())
        self.searhc_btn_2.setSizePolicy(sizePolicy)
        self.searhc_btn_2.setMinimumSize(QtCore.QSize(90, 40))
        self.searhc_btn_2.setStyleSheet("border: 1 solid #fff;\n"
"border-radius: 10;")
        self.searhc_btn_2.setDefault(False)
        self.searhc_btn_2.setFlat(False)
        self.searhc_btn_2.setObjectName("searhc_btn_2")
        self.horizontalLayout_5.addWidget(self.searhc_btn_2)
        spacerItem6 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_5.addItem(spacerItem6)
        self.verticalLayout_26.addWidget(self.widget_4)
        self.widget_16 = QtWidgets.QWidget(self.cve_sw)
        self.widget_16.setObjectName("widget_16")
        self.horizontalLayout_12 = QtWidgets.QHBoxLayout(self.widget_16)
        self.horizontalLayout_12.setObjectName("horizontalLayout_12")
        spacerItem7 = QtWidgets.QSpacerItem(250, 20, QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_12.addItem(spacerItem7)
        self.scrollArea_4 = QtWidgets.QScrollArea(self.widget_16)
        self.scrollArea_4.setWidgetResizable(True)
        self.scrollArea_4.setObjectName("scrollArea_4")
        self.cve_area = QtWidgets.QWidget()
        self.cve_area.setGeometry(QtCore.QRect(0, 0, 647, 564))
        self.cve_area.setObjectName("cve_area")
        self.verticalLayout_20 = QtWidgets.QVBoxLayout(self.cve_area)
        self.verticalLayout_20.setObjectName("verticalLayout_20")
        self.scrollArea_4.setWidget(self.cve_area)
        self.horizontalLayout_12.addWidget(self.scrollArea_4)
        spacerItem8 = QtWidgets.QSpacerItem(250, 20, QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_12.addItem(spacerItem8)
        self.verticalLayout_26.addWidget(self.widget_16)
        self.stackedWidget.addWidget(self.cve_sw)
        self.threats_sw = QtWidgets.QWidget()
        self.threats_sw.setObjectName("threats_sw")
        self.stackedWidget.addWidget(self.threats_sw)
        self.settings = QtWidgets.QWidget()
        self.settings.setObjectName("settings")
        self.stackedWidget.addWidget(self.settings)
        self.verticalLayout.addWidget(self.stackedWidget)
        self.widget_3 = QtWidgets.QWidget(HomeForm)
        self.widget_3.setStyleSheet("background: #1A1A1A;\n"
"color: #eee;\n"
"border: 0;")
        self.widget_3.setObjectName("widget_3")
        self.horizontalLayout_8 = QtWidgets.QHBoxLayout(self.widget_3)
        self.horizontalLayout_8.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_8.setSpacing(0)
        self.horizontalLayout_8.setObjectName("horizontalLayout_8")
        self.search_wbtn = QtWidgets.QToolButton(self.widget_3)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Ignored)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.search_wbtn.sizePolicy().hasHeightForWidth())
        self.search_wbtn.setSizePolicy(sizePolicy)
        self.search_wbtn.setMinimumSize(QtCore.QSize(0, 55))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.search_wbtn.setFont(font)
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(":/img/icons8-search-24.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.search_wbtn.setIcon(icon1)
        self.search_wbtn.setIconSize(QtCore.QSize(30, 30))
        self.search_wbtn.setToolButtonStyle(QtCore.Qt.ToolButtonTextUnderIcon)
        self.search_wbtn.setObjectName("search_wbtn")
        self.horizontalLayout_8.addWidget(self.search_wbtn)
        self.cve_wbtn = QtWidgets.QToolButton(self.widget_3)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Ignored)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.cve_wbtn.sizePolicy().hasHeightForWidth())
        self.cve_wbtn.setSizePolicy(sizePolicy)
        self.cve_wbtn.setMinimumSize(QtCore.QSize(0, 55))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.cve_wbtn.setFont(font)
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(":/img/icons8-flag-2-24.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.cve_wbtn.setIcon(icon2)
        self.cve_wbtn.setIconSize(QtCore.QSize(30, 30))
        self.cve_wbtn.setToolButtonStyle(QtCore.Qt.ToolButtonTextUnderIcon)
        self.cve_wbtn.setObjectName("cve_wbtn")
        self.horizontalLayout_8.addWidget(self.cve_wbtn)
        self.threats_wbtn = QtWidgets.QToolButton(self.widget_3)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Ignored)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.threats_wbtn.sizePolicy().hasHeightForWidth())
        self.threats_wbtn.setSizePolicy(sizePolicy)
        self.threats_wbtn.setMinimumSize(QtCore.QSize(0, 55))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.threats_wbtn.setFont(font)
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap(":/img/icons8-biohazard-30.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.threats_wbtn.setIcon(icon3)
        self.threats_wbtn.setIconSize(QtCore.QSize(30, 30))
        self.threats_wbtn.setToolButtonStyle(QtCore.Qt.ToolButtonTextUnderIcon)
        self.threats_wbtn.setObjectName("threats_wbtn")
        self.horizontalLayout_8.addWidget(self.threats_wbtn)
        self.settings_wbtn = QtWidgets.QToolButton(self.widget_3)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Ignored)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.settings_wbtn.sizePolicy().hasHeightForWidth())
        self.settings_wbtn.setSizePolicy(sizePolicy)
        self.settings_wbtn.setMinimumSize(QtCore.QSize(0, 55))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.settings_wbtn.setFont(font)
        icon4 = QtGui.QIcon()
        icon4.addPixmap(QtGui.QPixmap(":/img/icons8-settings-64.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.settings_wbtn.setIcon(icon4)
        self.settings_wbtn.setIconSize(QtCore.QSize(30, 30))
        self.settings_wbtn.setToolButtonStyle(QtCore.Qt.ToolButtonTextUnderIcon)
        self.settings_wbtn.setObjectName("settings_wbtn")
        self.horizontalLayout_8.addWidget(self.settings_wbtn)
        self.verticalLayout.addWidget(self.widget_3)

        self.retranslateUi(HomeForm)
        self.stackedWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(HomeForm)

    def retranslateUi(self, HomeForm):
        _translate = QtCore.QCoreApplication.translate
        HomeForm.setWindowTitle(_translate("HomeForm", "Mau | Threat Intelligence"))
        self.label.setText(_translate("HomeForm", "Mau"))
        self.label_2.setText(_translate("HomeForm", "IOCs with context is the key to prioritize your responde"))
        self.search_edt.setPlaceholderText(_translate("HomeForm", "IP, Domain, Hash, URL ..."))
        self.searhc_btn.setText(_translate("HomeForm", "Search"))
        self.whois_lbl.setText(_translate("HomeForm", "Whois"))
        self.label_4.setText(_translate("HomeForm", "Country"))
        self.label_5.setText(_translate("HomeForm", "Company"))
        self.label_19.setText(_translate("HomeForm", "Hostname"))
        self.whois_country.setText(_translate("HomeForm", "Country"))
        self.whois_company.setText(_translate("HomeForm", "Company"))
        self.whois_hostname.setText(_translate("HomeForm", "Hostname"))
        self.vt_lbl.setText(_translate("HomeForm", "Virus Total"))
        self.label_8.setText(_translate("HomeForm", "Status"))
        self.label_9.setText(_translate("HomeForm", "Malicious"))
        self.label_10.setText(_translate("HomeForm", "suspicious"))
        self.label_3.setText(_translate("HomeForm", "clean/no detection"))
        self.vt_sts.setText(_translate("HomeForm", "Malicious"))
        self.vt_count.setText(_translate("HomeForm", "10"))
        self.vt_relations.setText(_translate("HomeForm", "44"))
        self.vt_clean.setText(_translate("HomeForm", "0"))
        self.otx_lbl.setText(_translate("HomeForm", "OTX"))
        self.label_12.setText(_translate("HomeForm", "Status"))
        self.label_13.setText(_translate("HomeForm", "Pulses"))
        self.label_14.setText(_translate("HomeForm", "Reputation"))
        self.otx_sts.setText(_translate("HomeForm", "Malicious"))
        self.otx_count.setText(_translate("HomeForm", "10"))
        self.otx_iocs.setText(_translate("HomeForm", "44"))
        self.ipdb_lbl.setText(_translate("HomeForm", "AbuseIPDB "))
        self.label_16.setText(_translate("HomeForm", "Status"))
        self.label_17.setText(_translate("HomeForm", "Reports"))
        self.label_18.setText(_translate("HomeForm", "Last Report"))
        self.ipdb_sts.setText(_translate("HomeForm", "Malicious"))
        self.ipdb_count.setText(_translate("HomeForm", "10"))
        self.ipdb_date.setText(_translate("HomeForm", "44"))
        self.falcon_lbl.setText(_translate("HomeForm", "Meta Defender"))
        self.label_21.setText(_translate("HomeForm", "Status"))
        self.label_22.setText(_translate("HomeForm", "Detections"))
        self.label_23.setText(_translate("HomeForm", "Last Report"))
        self.falcon_sts.setText(_translate("HomeForm", "Malicious"))
        self.falcon_count.setText(_translate("HomeForm", "10"))
        self.falcon_date.setText(_translate("HomeForm", "44"))
        self.searhc_btn_2.setText(_translate("HomeForm", "Fetch Latest CVEs"))
        self.search_wbtn.setText(_translate("HomeForm", "Search"))
        self.cve_wbtn.setText(_translate("HomeForm", "CVE"))
        self.threats_wbtn.setText(_translate("HomeForm", "Threat"))
        self.settings_wbtn.setText(_translate("HomeForm", "Settings"))
import view.images_rc
