from sqlalchemy import Column, Integer, String, ForeignKey, Table, DateTime, Boolean, create_engine
from sqlalchemy.orm import relationship, backref
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

class Devices(Base):
    __tablename__ = "devices"
    device_id = Column(Integer, primary_key=True)
    pan_id = Column(String)
    source_id = Column(String)
    extended_source_id = Column(String)

class MapEntries(Base):
    __tablename__ = "map_entries"
    entry_id = Column(Integer, primary_key=True)
    pan_id = Column(String)
    source_device_id = Column(Integer, ForeignKey("devices.device_id"))
    destination__device_id = Column(Integer, ForeignKey("devices.device_id"))
    last_modified = Column(DateTime)

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
    # Session = sessionmaker()
    # Session.configure(bind=engine)
    # session = Session()
    
if __name__ == "__main__":
    main()