import db
import time


def remove_all_map_entries(session, device):
    for entry in device.source_map_entries:
        db.invalidateMapEntry(session, entry)
    for entry in device.destination_map_entries:
        db.invalidateMapEntry(session, entry)


def parse_device(session, packet):
    broadcast = ['0xffff', '0xfffe', '0xfffd', '0xfffc', '0xfffb', '0xfffa', '0xfff9', '0xfff8']
    alerts = []
    device = db.queryDevice(session=session, pan_id=packet.pan_id, source_id=packet.source_id)

    if device is not None:  # Device with said pan id and source exists
        if packet.extended_source_id is not None:

            if device.extended_source_id is None:  # Packet has ext src and device does not
                ext_check = db.queryDevice(session=session, extended_source_id=packet.extended_source_id)

                if ext_check is None:  # No other devices with this ext src exist
                    db.modifyDevice(session, device, extended_source_id=packet.extended_source_id)

                else:  # This ext src exists elsewhere, remove old entry and add this ext src to found entry
                    alerts.append('Device %s moved to network %s' % (packet.extended_source_id, packet.pan_id))
                    remove_all_map_entries(session, ext_check)
                    db.deleteDevice(session, ext_check)
                    db.modifyDevice(session=session, device=device, extended_source_id=packet.extended_source_id)

            elif device.extended_source_id != packet.extended_source_id:  # Packet has ext src, does not match device
                alerts.append('New Device %s has replaced %s in network %s' %
                              (packet.extended_source_id, device.extended_source_id, device.pan_id))
                remove_all_map_entries(session, device)
                db.modifyDevice(session=session, device=device, extended_source_id=packet.extended_source_id)
        # If entry is found and packet has no ext src, nothing else we can do here

    else:  # Device couldn't be found by panid and src
        if packet.extended_source_id is not None:
            device_ext = db.queryDevice(session=session, extended_source_id=packet.extended_source_id)
            if device_ext is None:
                alerts.append('New device %s added to network %s' % (packet.extended_source_id, packet.pan_id))
                db.createDevice(session=session, pan_id=packet.pan_id, source_id=packet.source_id,
                                extended_source_id=packet.extended_source)
            elif device_ext.pan_id != packet.pan_id:
                alerts.append('Device %s moved to network %s' % (packet.extended_source_id, packet.pan_id))
                remove_all_map_entries(session, device_ext)
                db.modifyDevice(session=session, device=device_ext, pan_id=packet.pan_id)
            else:  # PanID and ext match, source dont so device somehow got readdressed
                alerts.append('Device %s has been readdressed from %s to %s' % (device_ext.extended_source_id,
                                                                                device_ext.source_id, packet.source_id))
                db.modifyDevice(session=session, device=device_ext, source_id=packet.source_id)

    if packet.destination_id not in broadcast:
        dest_device = db.queryDevice(session=session, pan_id=packet.pan_id, source_id=packet.destination_id)
        if dest_device is None:
            alerts.append('New device %s added to network %s' % (packet.destination_id, packet.pan_id))
            db.createDevice(session=session, pan_id=packet.pan_id, source_id=packet.destination_id)

    if packet.network_source_id is not None:
        nwk_device = db.queryDevice(session=session, pan_id=packet.pan_id, source_id=packet.network_source_id)
        if nwk_device is not None and nwk_device[0].extended_source_id is None:
            db.modifyDevice(session=session, device=nwk_device[0], extended_source_id=packet.network_extended_source_id)
        elif nwk_device is None:
            alerts.append('New Device %s added to network %s' % (packet.network_source_id, packet.pan_id))

    return alerts


def parse_conns(session, packet):
    alert = []
    forward_link = db.queryMapEntry(session=session, pan_id=packet.pan_id, source_device=packet.source_id,
                                    destination_device=packet.destination_id)
    back_link = db.queryMapEntry(session=session, pan_id=packet.pan_id, source_device=packet.destination_id,
                                 destination_device=packet.source_id)
    if forward_link is None and back_link is None:
        alert.append('New connection between %s and %s established in network %s' %
                     (packet.source_id, packet.destination_id, packet.pan_id))
        db.createMapEntry(session=session, pan_id=packet.pan_id, source_device=packet.source_id,
                          destination_device=packet.destination_id)
    return alert


def raise_alerts(session, alerts):
    for alert in alerts:
        db.createAlert(session=session, message=alert)


def parse():
    session = db.createDBSession()

    while True:
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
    parse()
