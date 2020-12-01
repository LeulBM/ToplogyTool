import db
import time
import threading

BROADCAST = ['0xffff', '0xfffe', '0xfffd', '0xfffc', '0xfffb', '0xfffa', '0xfff9', '0xfff8']
CONFIDENCE = 3


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


def parse(e):
    session = db.createDBSession()

    while True and not e.is_set():
        pkt = db.queryPacket(session)

        if pkt is None:
            time.sleep(0.5)

        else:
            alerts = parse_device(session, pkt)
            map_alerts = parse_conns(session, pkt)

            alerts.extend(map_alerts)
            raise_alerts(session, alerts)

            db.parsedPacket(session, pkt)


if __name__ == '__main__':
    event = threading.Event()
    parse(event)
