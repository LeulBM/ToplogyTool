import datetime
from sqlalchemy import Column, Integer, String, ForeignKey, Table, DateTime, Boolean, create_engine
from sqlalchemy.orm import relationship, backref, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class Packets(Base):
    __tablename__ = "packets"
    packet_id = Column(Integer, primary_key=True)
    packet_time = Column(DateTime)
    pan_id = Column(String)
    source_id = Column(String)
    destination_id = Column(String)
    extended_source_id = Column(String)
    network_source_id = Column(String)
    network_extended_source_id = Column(String)
    packet_raw = Column(String)
    parsed = Column(Boolean, default=False)

    def __str__(self):
        return f"Packet ID: {self.packet_id}, Packet Time: {self.packet_time}, PAN ID: {self.pan_id}, Source ID: {self.source_id}, Destination ID: {self.destination_id}, Extended Source ID: {self.extended_source_id}, Network Source ID: {self.network_source_id},Network Extended Source ID {self.network_extended_source_id}, Parsed: {self.parsed}"


class MapEntries(Base):
    __tablename__ = "map_entries"
    entry_id = Column(Integer, primary_key=True)
    pan_id = Column(String)
    source_device_id = Column(Integer, ForeignKey("devices.device_id"))
    destination_device_id = Column(Integer, ForeignKey("devices.device_id"))
    created = Column(DateTime, default=datetime.datetime.utcnow)
    valid = Column(Boolean, default=True)
    confidence = Column(Integer, default=0)

    def __str__(self):
        return f"Entry ID: {self.entry_id}, PAN ID: {self.pan_id}, Source Device ID: {self.source_device_id}, Destination Device ID: {self.destination_device_id}, Created: {self.created}, Valid: {self.valid}"


class Devices(Base):
    __tablename__ = "devices"
    device_id = Column(Integer, primary_key=True)
    pan_id = Column(String)
    source_id = Column(String)
    extended_source_id = Column(String, unique=True)
    confidence = Column(Integer, default=0)
    source_map_entries = relationship("MapEntries", order_by="MapEntries.entry_id",
                                      foreign_keys=[MapEntries.source_device_id], cascade="all, delete")
    destination_map_entries = relationship("MapEntries", order_by="MapEntries.entry_id",
                                           foreign_keys=[MapEntries.destination_device_id], cascade="all, delete")

    def __str__(self):
        return f"Device ID: {self.device_id}, PAN ID: {self.pan_id}, Source ID: {self.source_id},Extended Source ID: {self.extended_source_id}"


class Alerts(Base):
    __tablename__ = "alerts"
    alerts_id = Column(Integer, primary_key=True)
    message = Column(String)
    read = Column(Boolean, default=False)

    def __str__(self):
        return f"Alert ID: {self.alerts_id}, Message: {self.message}, Read: {self.read}"

    def __resp__(self):
        return f"Alert ID: {self.alerts_id}, Message: {self.message}, Read: {self.read}"


def createDBSession():
    sqlite_filepath = "test.db"
    engine = create_engine(f"sqlite:///{sqlite_filepath}")
    Base.metadata.create_all(engine)
    Session = sessionmaker()
    Session.configure(bind=engine)
    session = Session()
    return session


def createPacket(session, packet_time, pan_id, source_id, destination_id, pkt_raw, extended_source_id=None,
                 network_source_id=None, network_extended_source_id=None):
    packet = Packets(packet_time=packet_time, pan_id=pan_id, source_id=source_id, destination_id=destination_id,
                     extended_source_id=extended_source_id, network_source_id=network_source_id,
                     network_extended_source_id=network_extended_source_id, packet_raw=pkt_raw)
    session.add(packet)
    session.commit()
    return packet


def queryPacket(session):
    packet = session.query(Packets).filter_by(parsed=False).order_by(Packets.packet_id.asc()).first()
    return packet


def parsedPacket(session, packet):
    packet.parsed = True
    session.commit()


def createMapEntry(session, pan_id, source_device, destination_device):
    existing_device = queryMapEntry(session, pan_id, source_device, destination_device)
    if existing_device is not None:
        return existing_device
    map_entry = MapEntries(pan_id=pan_id, source_device_id=source_device.device_id,
                           destination_device_id=destination_device.device_id)
    session.add(map_entry)
    session.commit()
    return map_entry


def queryMapEntry(session, pan_id, source_device, destination_device):
    map_entry = session.query(MapEntries).filter_by(pan_id=pan_id, source_device_id=source_device.device_id,
                                                    destination_device_id=destination_device.device_id).first()
    return map_entry


def queryMapEntries(session):
    map_entries = session.query(MapEntries).filter_by(valid=True).all()
    return map_entries


def invalidateMapEntry(session, entry):
    entry.valid = False
    session.commit()


def createAlert(session, message):
    alert = Alerts(message=message)
    session.add(alert)
    session.commit()
    return alert


def queryAlerts(session):
    alerts = session.query(Alerts).filter_by(read=False).all()
    return alerts


def queryAlert(session, alert_id):
    alert = session.query(Alerts).filter_by(alerts_id=alert_id).first()
    return alert


def readAlert(session, alert):
    alert.read = True
    session.commit()


def createDevice(session, pan_id, source_id, extended_source_id=None):
    existing_device = queryDevice(session, pan_id, source_id, extended_source_id)
    if existing_device is not None:
        return existing_device
    if extended_source_id is None:
        device = Devices(pan_id=pan_id, source_id=source_id)
    else:
        device = Devices(pan_id=pan_id, source_id=source_id, extended_source_id=extended_source_id)
    session.add(device)
    session.commit()
    return device


def queryDevice(session, pan_id=None, source_id=None, extended_source_id=None):
    if extended_source_id is None and pan_id is not None and source_id is not None:
        device = session.query(Devices).filter_by(pan_id=pan_id, source_id=source_id).first()
    else:
        device = session.query(Devices).filter_by(extended_source_id=extended_source_id).first()
    return device


def queryDevices(session):
    devices = session.query(Devices).all()
    return devices


def queryPANDevices(session, pan_id):
    devices = session.query(Devices).filter_by(pan_id=pan_id).all()
    return devices


def modifyDevice(session, device, pan_id=None, source_id=None, extended_source_id=None):
    if extended_source_id is not None:
        check_device = queryDevice(session=session, extended_source_id=extended_source_id)
        if check_device is None:
            device.extended_source_id = extended_source_id
    if pan_id is not None:
        device.pan_id = pan_id
    if source_id is not None:
        device.source_id = source_id
    session.commit()


def deleteDevice(session, device):
    session.delete(device)
    session.commit()


def increaseConfidence(session, db_object):
    if isinstance(db_object, (Devices, MapEntries)):
        db_object.confidence += 1
        session.commit()


def decreaseConfidence(session, db_object):
    if isinstance(db_object, (Devices, MapEntries)) and db_object.confidence > 0:
        db_object.confidence -= 1
        session.commit()


def resetConfidence(session, db_object):
    if isinstance(db_object, (Devices, MapEntries)):
        db_object.confidence = 0
        session.commit()


def main():
    session = createDBSession()
    test_device_1 = createDevice(session=session, pan_id="test1", source_id="short_test_1",
                                 extended_source_id="long_test_1")
    test_device_2 = createDevice(session=session, pan_id="test1", source_id="short_test_2",
                                 extended_source_id="long_test_2")
    map_entry = createMapEntry(session=session, pan_id="test1", source_device=test_device_1,
                               destination_device=test_device_2)
    print(test_device_1)
    print(test_device_2)

    deleteDevice(session, test_device_1)

    device1 = queryDevice(session=session, extended_source_id='long_test_1')
    device2 = queryDevice(session=session, extended_source_id='long_test_2')
    print(device1)
    print(device2)

    modifyDevice(session=session, device=device1, extended_source_id="nahFam")
    print(device1)
    modifyDevice(session=session, device=device1, source_id="22")
    print(device1)
    modifyDevice(session=session, device=device1, pan_id="33")
    print(device1)

    packet = createPacket(session, datetime.datetime.now(), "test", "test1", "test2")
    test = queryPacket(session)
    print(test)
    parsedPacket(session, test)
    print(queryPacket(session))

    alert1 = createAlert(session, "Test Massage One")
    createAlert(session, "Test Massage Two")
    alerts = queryAlerts(session)
    for alert in alerts:
        print(alert)
    readAlert(session, alert1)
    alerts = queryAlerts(session)
    for alert in alerts:
        print(alert)


if __name__ == "__main__":
    main()
