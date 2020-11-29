from scapy.all import *
from scapy.layers.dot15d4 import *
from scapy.layers.zigbee import *
from datetime import datetime
import db


session = db.createDBSession()


def parse_packet(newpkt):
    rectime = datetime.now()

    valid = False
    src = ext_src = dest = panid = nwk_src = nwk_ext = None
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

        # Pull from security header instead of NWK because its consistently available and corresponds
        # to the short addr in the MAC layer, NWK corresponds to short NWK addr, which may not be the same
        if pkt.haslayer(ZigbeeSecurityHeader):
            es_field = pkt[ZigbeeSecurityHeader].get_field('source')
            ext_src = es_field.i2repr(pkt, pkt[ZigbeeSecurityHeader].source)

        if pkt.haslayer(ZigbeeNWK) and pkt[ZigbeeNWK].ext_src is not None and pkt.src_addr != pkt[ZigbeeNWK].source:
            nwk_src = "{0:#06x}".format(pkt[ZigbeeNWK].source)

            nes_field = pkt[ZigbeeNWK].get_field('ext_src')
            nwk_ext = nes_field.i2repr(pkt, pkt[ZigbeeNWK].ext_src)

        if valid:
            db.createPacket(session, rectime, panid, src, dest, ext_src, nwk_src, nwk_ext)


def main():
    conf.dot15d4_protocol = "zigbee"
    sniff(iface="lo", prn=parse_packet)


if __name__ == '__main__':
    main()
