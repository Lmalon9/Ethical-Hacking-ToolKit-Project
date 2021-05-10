#!/usr/bin/env python

import subprocess
# Sub process module allows to execute system/terminal commands
import re
# Regular
from MainWindow import *
# from Ui_Project1 import Ui_MainWindow

def change_address(interface, new_mac):

    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])
    # Here the subprocess call will execute it the contents as one command
    return new_mac


def get_mac(interface):
    # Here ifconfig is set to be the output of subprocess command that returns the ifconfig of the device
    try:
        ifconfig = subprocess.check_output(["ifconfig", interface])
    # To handle errors like th user entering an invalid interface, an exception is made and is used to inform the user
    except Exception:
        # The message is returned to be displayed on the application
        error = " Error! invalid interface"
        return error

    # executes ifconfig command in terminal, returning the output too the ifconfig variable,ensuring change is made
    mac_address_search = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig))
    # Using regular expression, it finds a match with 6 alphanumeric values followed by ':' within ifconfig
    if mac_address_search:
        # Returns if a value found by the regular expression, group(0) allows us too only see the first result
        return mac_address_search.group(0)
    else:
        return
