# ToplogyTool

Requirements for installation
  Install packages listed in requirements.txt
  Once installed, locate the layers folder in your Scapy installation and replace dot15d4.py and zigbee.py with those supplied in the patch folder of this project
  Install GNURadio 3.7, and the compatible branches of gr-foo and gr-ieee802-15-4

Usage
  To sniff traffic run the zig_tranciever.grc flowgraph in Gnuradio. It is initially configured for use with a USRP B210, but the source can be modified to accomodate any SDR source GNURadio supports provided you supply the right branches
  The IDS consists of the 3 files you must run. 
    ingestion.py handles reading traffic GNURadio passes to localhost and pulls out relevant info, storing it in a database
    parsing.py handles taking the stored packet data and correlating it to attacks and network state changes
    ui.py handles the User Interface of the IDS
    
  All 3 must be running concurrently in order to have the IDS function. Note that because ingestion sniffs traffic, as written it must be run using sudo. If this is your first time running the IDS, do NOT run ingestion first, as the first file run generate the DB and if a sudo file does so the other two scripsts will be unable to edit the database
  Additi0onally GNURadio needs to be running to handle sniffing traffic and passing it to localhost.
  Once all scripts and GNURadio are running, the UI can be viewed at localhost port 5000.
