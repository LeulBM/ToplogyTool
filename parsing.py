

def parse_device(source, ext_source, destination, panID, nwk_src, nwk_ext, time_received ):

    broadcast = ['0xFFFF', '0xFFFE', '0xFFFD', '0xFFFC', '0xFFFB', '0xFFFA', '0xFFF9', '0xFFF8']
    alerts = []
    ###
    #if source + panid exists
    #   found basc
    #   if extSrc = None
    #       save extSrc
    #   if not none and not ext_source
    #       ALERT extended source mismatch, new device has been assigned old source
    #       update ext
    #
    #else if extsource exists NOTE THAT THIS MEANS THE DEVICE EXISTS BUT HAS MOVED
    #   ALERT device has moved
    #   save source and panid
    #
    #else
    #   alert   new device found, added to table
    #   add device
    #
    #if dest not in broadcast
    #   if dest + panid doesn't exist
    #       add entry with null ext    new device found
    #
    #if nwk_src is not None:
    #   if nwk_src + panid exists
    #       if extSrc = None
    #           extSrc = nwk_ext
    #       elseif extSrc != nwk_ext
    #           ALERT extended source mismatch,
    #           update ext
    #
    #return alerts

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

    while True:
        # TODO GET FIELDS FROM DB
        # device_alerts = parse_device
        # connection_alerts = parse_conns
        # raise alerts






