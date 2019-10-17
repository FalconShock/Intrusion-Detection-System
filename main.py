from scapy.all import *
from config import *

sniff(prn = lambda x: wrpcap("captured_pkts.pcap", x, append = True),\
lfilter = filter_to_apply, count = packets_to_capture)


print "-" * 40
print "Possibly Dangerous Packets"
print "-" * 40

for packet in rdpcap("captured_pkts.pcap"):
    for protocol in protocols:
        try:
            temp = packet.summary().split()
            #print temp
            try:
                for x in temp: print x.split(":")[1]
            except: continue
            #if protocol in packet.summary().split(":"): print packet.summary()
        except Exception, e:
            print "Exception:" + str(e)
            continue
