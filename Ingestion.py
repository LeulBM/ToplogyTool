from scapy.all import *
from scapy.layers.dot15d4 import *
from scapy.layers.zigbee import *


def analyze_print_pkt(newpkt):
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

        # Pull from security header instead of NWK because its consistently available and corresponds
        # to the short addr in the MAC layer, NWK corresponds to short NWK addr, which may not be the same
        if pkt.haslayer(ZigbeeSecurityHeader):
            es_field = pkt[ZigbeeSecurityHeader].get_field('source')
            ext_src = es_field.i2repr(pkt, pkt[ZigbeeSecurityHeader].source)

        if valid:
            return src, ext_src, dest, panid

        return None


def main():
    conf.dot15d4_protocol = "zigbee"

    while True:
        parsed = sniff(1, iface="lo", prn=analyze_print_pkt)

        # Ensure a valid packet was parsed
        if parsed is not None:
            source, ext_source, destination, panID = parsed
            # TODO: Save above to sql db using sqlalchemy
