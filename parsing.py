import db
import time

def remove_all_map_entries(session, device):
    for entry in device.source_map_entries:
        db.invalidateMapEntry(session, entry)
    for entry in device.destination_map_entries:
        db.invalidateMapEntry(session, entry)

def parse_device(packet, session):
    broadcast = ['0xffff', '0xfffe', '0xfffd', '0xfffc', '0xfffb', '0xfffa', '0xfff9', '0xfff8']
    alerts = []
    ###
    device = db.queryDevice(session=session, pan_id=packet.pan_id, source_id=packet.source_id)

    if len(device) == 1: # Device with said pan id and source exists
        if packet.extended_source_id is not None:
            if device.extended_source_id is None:
                ext_check = db.queryDevice(session=session, extended_source_id=packet.extended_source_id)
                if ext_check is None: # No devices with this ext src exist
                    db.modifyDevice(session, device, extended_source_id=packet.extended_source_id)
                else: # This ext src exists elsewhere, remove old entry and add this ext src to found entry
                    alerts.append('Device %s moved to network %s' % (packet.extended_source_id, packet.pan_id))
                    remove_all_map_entries(session, ext_check)
                    #TODO DELETE EXT CHECK ENTRY
                    db.modifyDevice(sesion=session, device=device, extended_source_id=packet.extended_source_id)

            elif device.extended_source_id != packet.extended_source_id:
                alerts.append('New Device %s has replaced %s in network %s' % (packet.extended_source_id, device.extended_source_id, device.pan_id))
                remove_all_map_entries(session, device)
                db.modifyDevice(session = session, device = device, extended_source_id=packet.extended_source_id)
        # If entry is found and packet has no ext src, nothing else we can do here

    elif len(device) > 1:
        # TODO MULTIPLE DEVICES WITH THE SAME PANID AND SRC

    else: # Device couldn't be found by panid and src
        if packet.extended_source_id is not None:
            device_ext = db.queryDevice(session=session, extended_source_id=packet.extended_source_id)
            if device_ext is None:
                alerts.append('New device %s added to network %s' % (packet.extended_source_id, packet.pan_id))
                db.createDevice(session=session, pan_id=apacket.pan_id, source_id=packet.source_id,
                                extended_source_id=packet.extended_source)
            elif device_ext.pan_id != packet.pan_id:
                alerts.append('Device %s moved to network %s' % (packet.extended_source_id, packet.pan_id))
                remove_all_map_entries(session, device_ext)
                db.modifyDevice(session=session, device = device_ext, pan_id=packet.pan_id)
            else: #PanID and ext match, source dont so device somehow got readdressed
                alerts.append('Device %s has been readdressed from %s to %s' % (device_ext.extended_source_id,
                                                                         device_ext.source_id, packet.source_id))
                db.modifyDevice(session=session, device=device_ext, source_id=packet.source_id)

    if packet.destination_id not in broadcast:
        dest_device = db.queryDevice(session=session, pan_id=packet.pan_id, source_id=packet.destination_id)
        if not dest_device:
            alerts.append('New device %s added to network %s' % (packet.destination_id, packet.pan_id))
            db.createDevice(session=session, pan_id=packet.pan_id, source_id=packet.destination_id)
        elif len(dest_device) > 1:
            #TODO MULTIPLE DEVICES WITH SAME PANID AND SRC

    if packet.network_source_id is not None:
        nwk_device = db.queryDevice(session=session, pan_id=packet.pan_id, source_id=packet.network_source_id)
        if len(nwk_device) == 1 and nwk_device[0].extended_source_id is None:
            db.modifyDevice(session=session, device=nwk_device[0], extended_source_id=packet.network_extended_source_id)
        elif not nwk_device:
            alerts.append('New Device %s added to network %s' % (packet.network_source_id, packet.pan_id))

    return alerts

def parse_conns(source, destination, panID):
    alert = []
    #if conSrc = source and connDest = destination and panId = panID
    #       or
    #   connSrc = destination and connDest= dource and panId = panID:
    #       already exists
    #else
    #   add source, dest, panID
    #   ALERT
    #
    #return alert
    #

def raise_alerts(device, connection):
    #for x in device
    #   store x in alerts
    #for x in connections
    #    store x in alerts

def parse():
    session = db.createDBSession()

    while True:
        pkt = db.queryPacket(session)

        if pkt is None:
            time.sleep(1)

        else:
            device_alerts = parse_device(pkt, session)


            db.parsedPacket(session, pkt)

        # device_alerts = parse_device
        # connection_alerts = parse_conns
        # raise alerts






