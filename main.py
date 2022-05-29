# -*- coding: utf-8 -*-
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import QApplication

from controller.home import Home_Page
if __name__ == '__main__':
    import sys
    app = QApplication(sys.argv)
    s = Home_Page()
    s.show()
    app.exec_()