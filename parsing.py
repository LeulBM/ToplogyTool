import db
import time
import threading
from scapy.all import *


BROADCAST = ['0xffff', '0xfffe', '0xfffd', '0xfffc', '0xfffb', '0xfffa', '0xfff9', '0xfff8']
CONFIDENCE = 3
LAST_TRANSACTION = ''


def invalidate_all_map_entries(session, device):
    for entry in device.source_map_entries:
        db.invalidateMapEntry(session, entry)
    for entry in device.destination_map_entries:
        db.invalidateMapEntry(session, entry)


#  If return True, confidence value was high enough, if False, make change
def check_confidence(session, device):
    if device.confidence < CONFIDENCE:
        db.increaseConfidence(session=session, db_object=device)
        return True
    else:
        return False


def parse_device(session, packet):
    alerts = []

    pan_exist = db.queryPANDevices(session, packet.pan_id)
    if not pan_exist:
        alerts.append("New network created. PAN ID: %s" % packet.pan_id)

    device = db.queryDevice(session=session, pan_id=packet.pan_id, source_id=packet.source_id)

    if device is not None:  # Device with said pan id and source exists
        if packet.extended_source_id is not None:

            if device.extended_source_id is None:  # Packet has ext src and device does not
                ext_check = db.queryDevice(session=session, extended_source_id=packet.extended_source_id)

                if ext_check is None:  # No other devices with this ext src exist
                    db.modifyDevice(session, device, extended_source_id=packet.extended_source_id)

                else:  # This ext src exists elsewhere, remove old entry and add this ext src to found entry
                    if not check_confidence(session, ext_check):
                        alerts.append('Device %s(%s) moved to network %s from network %s' %
                                      (packet.source_id, packet.extended_source_id, packet.pan_id, ext_check.pan_id))
                        # invalidate_all_map_entries(session, ext_check)
                        db.deleteDevice(session, ext_check)
                        db.modifyDevice(session=session, device=device, extended_source_id=packet.extended_source_id)

            elif device.extended_source_id != packet.extended_source_id:  # Packet has ext src, does not match device
                if not check_confidence(session, device):
                    alerts.append('New Device %s has replaced old device %s in network %s' %
                                  (packet.extended_source_id, device.extended_source_id, device.pan_id))
                    invalidate_all_map_entries(session, device)
                    db.modifyDevice(session=session, device=device, extended_source_id=packet.extended_source_id)
            else:
                db.decreaseConfidence(session, device)
        # No else here to increase confidence as we don't have an extended source to compare against

    else:  # Device couldn't be found by pan_id and src
        if packet.extended_source_id is not None:
            device_ext = db.queryDevice(session=session, extended_source_id=packet.extended_source_id)

            if device_ext is None:  # Source+Pan_ID combo nor extended source could be found, brand new device
                alerts.append('New device %s added to network %s' % (packet.extended_source_id, packet.pan_id))
                db.createDevice(session=session, pan_id=packet.pan_id, source_id=packet.source_id,
                                extended_source_id=packet.extended_source_id)

            elif device_ext.pan_id != packet.pan_id:  # Ext Source found in new PAN
                if not check_confidence(session, device_ext):
                    alerts.append('Device %s(%s) moved to network %s from network %s' %
                                  (packet.source_id, packet.extended_source_id, packet.pan_id, device_ext.pan_id))
                    invalidate_all_map_entries(session, device_ext)
                    db.modifyDevice(session=session, device=device_ext, pan_id=packet.pan_id, source_id=packet.source_id)

            else:  # PanID and ext match, source don't so device somehow got readdressed
                if not check_confidence(session, device_ext):
                    alerts.append('Device %s(%s) has been readdressed from previous short address %s' %
                                  (packet.source_id, device_ext.extended_source_id, device_ext.source_id))
                    invalidate_all_map_entries(session, device_ext)
                    db.modifyDevice(session=session, device=device_ext, source_id=packet.source_id)
        else:
            alerts.append('New device %s added to network %s' % (packet.source_id, packet.pan_id))
            db.createDevice(session=session, pan_id=packet.pan_id, source_id=packet.source_id)

    if packet.destination_id not in BROADCAST:
        dest_device = db.queryDevice(session=session, pan_id=packet.pan_id, source_id=packet.destination_id)
        if dest_device is None:
            alerts.append('New device %s added to network %s' % (packet.destination_id, packet.pan_id))
            db.createDevice(session=session, pan_id=packet.pan_id, source_id=packet.destination_id)

    if packet.network_source_id is not None:
        nwk_device = db.queryDevice(session=session, pan_id=packet.pan_id, source_id=packet.network_source_id)
        if nwk_device is not None and nwk_device.extended_source_id is None:
            db.modifyDevice(session=session, device=nwk_device, extended_source_id=packet.network_extended_source_id)
        elif nwk_device is None:
            alerts.append('New device %s added to network %s' % (packet.network_source_id, packet.pan_id))
            db.createDevice(session=session, pan_id=packet.pan_id, source_id=packet.network_source_id,
                            extended_source_id=packet.network_extended_source_id)

    return alerts


def parse_conns(session, packet):
    alerts = []
    if packet.destination_id not in BROADCAST:

        device_source = db.queryDevice(session=session, pan_id=packet.pan_id, source_id=packet.source_id)
        device_destination = db.queryDevice(session=session, pan_id=packet.pan_id, source_id=packet.destination_id)

        forward_link = db.queryMapEntry(session=session, pan_id=packet.pan_id, source_device=device_source,
                                        destination_device=device_destination)
        back_link = db.queryMapEntry(session=session, pan_id=packet.pan_id, source_device=device_destination,
                                     destination_device=device_source)

        if forward_link is None and back_link is None:
            alerts.append('New connection between %s and %s established in network %s' %
                          (packet.source_id, packet.destination_id, packet.pan_id))
            db.createMapEntry(session=session, pan_id=packet.pan_id, source_device=device_source,
                              destination_device=device_destination)
    return alerts


def raise_alerts(session, alerts):
    for alert in alerts:
        db.createAlert(session=session, message=alert)

def get_valid_zll():
    valid = []
    try:
        with open("./auth_ZLL.txt") as f:
            valid = f.read().splitlines()

    except FileNotFoundError:
        print("No authorized ZLL List Found")

    finally:
        return valid

def get_scan_id(pkt):
    return pkt[ZLLScanRequest].get_field('inter_pan_transaction_id')\
            .i2repr(pkt, pkt.inter_pan_transaction_id)

def parse_zll(session, pkt, spkt, auth_zll):
    global LAST_TRANSACTION

    alerts =[]
    source = pkt.source_id;

    target_device = db.queryDevice(session, extended_source_id=pkt.destination_id)

    if source not in auth_zll:  # Unauthorized source, ID attack
        if spkt.haslayer(ZLLScanRequest):  # SCAN 
            t_id = get_scan_id(spkt)

            if t_id != LAST_TRANSACTION:
                LAST_TRANSACTION = t_id
                alerts.append('TOUCHLINK: Scan Attempted by unauthorized user %s' %
                        (pkt.source_id))

        elif spkt.haslayer(ZLLScanResponse):    #SCAN RESPONSE
            target_device = db.queryDevice(session, extended_source_id=pkt.source_id)

            victim_pan = spkt[Dot15d4Data].get_field('src_panid').i2repr(spkt, spkt.src_panid)

            if target_device is not None:
                if not target_device.pan_id == victim_pan:  # Device is on new PAN, possibly Reset
                    invalidate_all_map_entries(session, target_device)
                    db.modifyDevice(session=session, device=target_device, pan_id=victim_pan)
                    alerts.append('TOUCHLINK: Scan Response shows device %s moved to PAN %s, possible Reset' % (pkt.source_id, victim_pan))


        elif spkt.haslayer(ZLLResetToFactoryNewRequest):  #RESET
            if target_device is not None:
                alerts.append('TOUCHLINK: Attempt to Factory Reset device %s(%s)' %
                        (target_device.source_id, pkt.destination_id))
            else:
                alerts.append('TOUCHLINK: Attempt to Factory Reset device %s' %
                        (pkt.destination_id))

        elif spkt.haslayer(ZLLIdentifyRequest): #IDENTIFY
            if target_device is not None:
                alerts.append('TOUCHLINK: Attempt to Identify Device %s(%s) for %i seconds' %
                        (target_device.source_id, pkt.destination_id, spkt[ZLLIdentifyRequest].identify_duration))
            else:
                alerts.append('TOUCHLINK: Attempt to Identify Device device %s for %i seconds' %
                        (pkt.destination_id, spkt[ZLLIdentifyRequest].identify_duration))

        elif spkt.haslayer(ZLLNetworkUpdateRequest): #UPDATE
            if target_device is not None:
                alerts.append('TOUCHLINK: Attempt to Update Device %s(%s) to channel %i' %
                        (target_device.source_id, pkt.destination_id, 
                            spkt[ZLLNetworkUpdateRequest].channel))
            else:
                alerts.append('TOUCHLINK: Attempt to Update Device %s to channel %i' %
                        (pkt.destination_id, spkt[ZLLNetworkUpdateRequest].channel))

        elif spkt.haslayer(ZLLNetworkJoinRouterRequest): #JOIN
            new_pan = spkt[ZLLNetworkJoinRouterRequest].get_field('pan_id').i2repr(spkt, 
                    spkt[ZLLNetworkJoinRouterRequest].pan_id)

            if target_device is not None:
                alerts.append('TOUCHLINK: Attempt to Join device %s(%s) to Network %s on channel %i' %
                        (target_device.source_id, pkt.destination_id, new_pan,
                            spkt[ZLLNetworkJoinRouterRequest].channel))
            else:
                alerts.append('TOUCHLINK: Attempt to Join device %s to Network %s on channel %i' %
                        (pkt.destination_id, new_pan, spkt[ZLLNetworkJoinRouterRequest].channel))
    return alerts


def parse(e):
    session = db.createDBSession()
    auth_zll = get_valid_zll()
    conf.dot15d4_protocol = "zigbee"


    while True and not e.is_set():
        pkt = db.queryPacket(session)

        if pkt is None:
            time.sleep(0.5)

        else:
            alerts = []
            map_alerts = []

            spkt = Dot15d4FCS(pkt.packet_raw)
            if spkt.haslayer(ZigbeeZLLCommissioningCluster):
                # Touchlink Attack Detection
                alerts = parse_zll(session, pkt, spkt, auth_zll)

            else:
                # Regular Attack Detection
                alerts = parse_device(session, pkt)
                map_alerts = parse_conns(session, pkt)

            alerts.extend(map_alerts)
            raise_alerts(session, alerts)

            db.parsedPacket(session, pkt)


if __name__ == '__main__':
    event = threading.Event()
    parse(event)
