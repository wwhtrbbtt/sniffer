# https://www.thepythoncode.com/article/building-wifi-scanner-in-python-scapy

from scapy.all import *
from threading import Thread
#import pandas
import time
import os

interface = "en0"
if len(sys.argv) == 2:
    interface = sys.argv[1]

# initialize the networks dataframe that will contain all access points nearby
# networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# set the index BSSID (MAC address of the AP)
# networks.set_index("BSSID", inplace=True)

def callback(packet):
    print(packet.summary())
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        # get the name of it
        ssid = packet[Dot11Elt].info.decode()
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # extract network stats
        stats = packet[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        # get the crypto
        crypto = stats.get("crypto")
        print(ssid, dbm_signal, channel, crypto)
  # networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)

def print_all():
    while True:
        os.system("clear")
        # print(networks)
        time.sleep(0.5)

if __name__ == "__main__":
    print("Using wifi interface", interface)

    # start the thread that prints all the networks
#    printer = Thread(target=print_all)
#    printer.daemon = True
#    printer.start()
    # start sniffing
    sniff(prn=callback, iface=interface)
