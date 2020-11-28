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
    network_extended_source_id = Column(String)
    parsed = Column(Boolean,default=False)

class MapEntries(Base):
    __tablename__ = "map_entries"
    entry_id = Column(Integer, primary_key=True)
    pan_id = Column(String)
    source_device_id = Column(Integer, ForeignKey("devices.device_id"))
    destination_device_id = Column(Integer, ForeignKey("devices.device_id"))
    last_modified = Column(DateTime,default=datetime.datetime.utcnow)

class Devices(Base):
    __tablename__ = "devices"
    device_id = Column(Integer, primary_key=True)
    pan_id = Column(String)
    source_id = Column(String)
    extended_source_id = Column(String, unique=True)
    source_map_entries = relationship("MapEntries",order_by="MapEntries.entry_id", foreign_keys=[MapEntries.source_device_id])
    destination_map_entries = relationship("MapEntries",order_by="MapEntries.entry_id", foreign_keys=[MapEntries.destination_device_id])

class Alerts(Base):
    __tablename__ = "alerts"
    alerts_id = Column(Integer, primary_key=True)
    message = Column(String)
    read = Column(Boolean,default=False)

def main():
    """Main entry point of program"""
    # Connect to the database using SQLAlchemy
    sqlite_filepath = "test.db"
    engine = create_engine(f"sqlite:///{sqlite_filepath}")
    Base.metadata.create_all(engine)
    Session = sessionmaker()
    Session.configure(bind=engine)
    session = Session()
    
    test_device_1 = Devices(pan_id="test1",source_id="short_test_1",extended_source_id="long_test_1")
    test_device_2 = Devices(pan_id="test1",source_id="short_test_2",extended_source_id="long_test_2")
    session.add_all([test_device_1,test_device_2])
    session.commit()

    device1= session.query(Devices).filter_by(extended_source_id='long_test_1').first()
    device2= session.query(Devices).filter_by(extended_source_id='long_test_2').first()
    map_entry = MapEntries(pan_id="test1",source_device_id=device1.device_id,destination_device_id=device2.device_id)
    session.add(map_entry)
    session.commit()

    device1= session.query(Devices).filter_by(extended_source_id='long_test_1').first()
    device2= session.query(Devices).filter_by(extended_source_id='long_test_2').first()
    print(device1.source_map_entries)
    print(device1.destination_map_entries)
    print(device2.source_map_entries)
    print(device2.destination_map_entries)

if __name__ == "__main__":
    main()