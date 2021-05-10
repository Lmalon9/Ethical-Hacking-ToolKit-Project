import sys
from PyQt5.QtWidgets import *
from Ui_Project1 import *


class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.spoofClickMe.clicked.connect(self.dispmessage)
        self.show()

    def dispmessage(self):
        self.ui.label_5.setText("Hello "+self.ui.addressEdit.text())


if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())