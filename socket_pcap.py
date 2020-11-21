from scapy.all import *
from scapy.layers.dot15d4 import *
from scapy.layers.zigbee import *

conf.dot15d4_protocol = "zigbee"

filereader = PcapReader("./captures/norftap2.pcap")
count = 1
for newpkt in filereader:
    valid = False
    src = ext_src = dest = panid = None

    if newpkt.haslayer(UDP) and newpkt[UDP].dport == 52001:
        pkt = Dot15d4FCS(newpkt.load)

        if pkt.haslayer(Dot15d4Data):
            src = "{0:#06x}".format(pkt.src_addr)
            dest = "{0:#06x}".format(pkt.dest_addr)
            panid = "{0:#06x}".format(pkt.dest_panid)
            valid = True

        elif pkt.haslayer(Dot15d4Cmd) and hasattr(pkt, 'cmd_id') and pkt.cmd_id == 4:
            src = "{0:#06x}".format(pkt.src_addr)
            dest = "{0:#06x}".format(pkt.dest_addr)
            panid = "{0:#06x}".format(pkt.dest_panid)
            valid = True

        if pkt.haslayer(ZigbeeSecurityHeader):
            es_field = pkt[ZigbeeSecurityHeader].get_field('source')
            ext_src = es_field.i2repr(pkt, pkt[ZigbeeSecurityHeader].source)

        if valid:
            if ext_src is None:
                print("%i \t source: %s, extended source: %s,\t\t\t\t\t\t dest: %s, PAN ID: %s" % (count, src, ext_src, dest, panid))
            else:
                print("%i \t source: %s, extended source: %s,\t dest: %s, PAN ID: %s" % (count, src, ext_src, dest, panid))

        count += 1
