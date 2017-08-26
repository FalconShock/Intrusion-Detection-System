from scapy.all import *

sniff(prn = lambda x: wrpcap("whatever.pcap", x, append = True),\
 lfilter = None, count = 2)

for packet in rdpcap("whatever.pcap"):
    try:
        if packet.summary().split()[5].split(":")[1] == "https"\
        or packet.summary().split()[7].split(":")[1] == "https":
            print packet.summary()
    except Exception, e:
        print "Exception:" + str(e)
        continue
