# This program is published under a GPLv2 license
# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Ryan Speers <ryan@rmspeers.com> 2011-2012
# Copyright (C) Roger Meyer <roger.meyer@csus.edu>: 2012-03-10 Added frames
# Copyright (C) Gabriel Potter <gabriel@potter.fr>: 2018
# Copyright (C) 2020 Dimitrios-Georgios Akestoridis <akestoridis@cmu.edu>
# This program is published under a GPLv2 license

"""
ZigBee bindings for IEEE 802.15.4.
"""

import re, struct

from scapy.compat import orb
from scapy.packet import *
from scapy.fields import *
"""	#NOTE simplified imports to match z3, maybe not necessary
from scapy.packet import bind_layers, bind_bottom_up, Packet
from scapy.fields import BitField, ByteField, XLEIntField, ConditionalField, \
    ByteEnumField, EnumField, BitEnumField, FieldListField, FlagsField, \
    IntField, PacketListField, ShortField, StrField, StrFixedLenField, \
    StrLenField, XLEShortField, XStrField
"""

from scapy.layers.dot15d4 import dot15d4AddressField, Dot15d4Beacon, Dot15d4, \
    Dot15d4FCS
from scapy.layers.inet import UDP
from scapy.layers.ntp import TimeStampField

# ZigBee Cluster Library Identifiers, Table 2.2 ZCL
_zcl_cluster_identifier = {
    # Functional Domain: General
    0x0000: "basic",
    0x0001: "power_configuration",
    0x0002: "device_temperature_configuration",
    0x0003: "identify",
    0x0004: "groups",
    0x0005: "scenes",
    0x0006: "on_off",
    0x0007: "on_off_switch_configuration",
    0x0008: "level_control",
    0x0009: "alarms",
    0x000a: "time",
    0x000b: "rssi_location",
    0x000c: "analog_input",
    0x000d: "analog_output",
    0x000e: "analog_value",
    0x000f: "binary_input",
    0x0010: "binary_output",
    0x0011: "binary_value",
    0x0012: "multistate_input",
    0x0013: "multistate_output",
    0x0014: "multistate_value",
    0x0015: "commissioning",
    # 0x0016 - 0x00ff reserved
    # Functional Domain: Closures
    0x0100: "shade_configuration",
    # 0x0101 - 0x01ff reserved
    # Functional Domain: HVAC
    0x0200: "pump_configuration_and_control",
    0x0201: "thermostat",
    0x0202: "fan_control",
    0x0203: "dehumidification_control",
    0x0204: "thermostat_user_interface_configuration",
    # 0x0205 - 0x02ff reserved
    # Functional Domain: Lighting
    0x0300: "color_control",
    0x0301: "ballast_configuration",
    # Functional Domain: Measurement and sensing
    0x0400: "illuminance_measurement",
    0x0401: "illuminance_level_sensing",
    0x0402: "temperature_measurement",
    0x0403: "pressure_measurement",
    0x0404: "flow_measurement",
    0x0405: "relative_humidity_measurement",
    0x0406: "occupancy_sensing",
    # Functional Domain: Security and safethy
    0x0500: "ias_zone",
    0x0501: "ias_ace",
    0x0502: "ias_wd",
    # Functional Domain: Protocol Interfaces
    0x0600: "generic_tunnel",
    0x0601: "bacnet_protocol_tunnel",
    0x0602: "analog_input_regular",
    0x0603: "analog_input_extended",
    0x0604: "analog_output_regular",
    0x0605: "analog_output_extended",
    0x0606: "analog_value_regular",
    0x0607: "analog_value_extended",
    0x0608: "binary_input_regular",
    0x0609: "binary_input_extended",
    0x060a: "binary_output_regular",
    0x060b: "binary_output_extended",
    0x060c: "binary_value_regular",
    0x060d: "binary_value_extended",
    0x060e: "multistate_input_regular",
    0x060f: "multistate_input_extended",
    0x0610: "multistate_output_regular",
    0x0611: "multistate_output_extended",
    0x0612: "multistate_value_regular",
    0x0613: "multistate_value",
    # Smart Energy Profile Clusters
    0x0700: "price",
    0x0701: "demand_response_and_load_control",
    0x0702: "metering",
    0x0703: "messaging",
    0x0704: "smart_energy_tunneling",
    0x0705: "prepayment",
    # Functional Domain: General
    # Key Establishment
    0x0800: "key_establishment",
    0x1000: "ZLL_commissioning",
}

# ZigBee stack profiles
_zcl_profile_identifier = {
    0x0000: "ZigBee_Stack_Profile_1",
    0x0101: "IPM_Industrial_Plant_Monitoring",
    0x0104: "HA_Home_Automation",
    0x0105: "CBA_Commercial_Building_Automation",
    0x0107: "TA_Telecom_Applications",
    0x0108: "HC_Health_Care",
    0x0109: "SE_Smart_Energy_Profile",
    0xc05e: "ZLL_Light_Link",
}

# ZigBee Cluster Library, Table 2.8 ZCL Command Frames
_zcl_command_frames = {
    0x00: "read_attributes",
    0x01: "read_attributes_response",
    0x02: "write_attributes_response",
    0x03: "write_attributes_undivided",
    0x04: "write_attributes_response",
    0x05: "write_attributes_no_response",
    0x06: "configure_reporting",
    0x07: "configure_reporting_response",
    0x08: "read_reporting_configuration",
    0x09: "read_reporting_configuration_response",
    0x0a: "report_attributes",
    0x0b: "default_response",
    0x0c: "discover_attributes",
    0x0d: "discover_attributes_response",
    # 0x0e - 0xff Reserved
}

# ZigBee LightLink Command Frames
_zll_command_frames = {
    0x00: "scan_request",
    0x01: "scan_response",
    0x02: "device_information_request",
    0x03: "device_information_response",
    0x06: "identify_request",
    0x07: "reset_to_factory_new_request",
    0x10: "network_start_request",
    0x11: "network_start_response",
    0x12: "network_join_router_request",
    0x13: "network_join_router_response",
    0x14: "network_join_end_device_request",
    0x15: "network_join_end_device_response",
    0x16: "network_update_request",
    0x40: "endpoint_information",
    0x41: "get_group_identifiers_request",
    0x42: "get_endpoint_list_request",
}

# ZigBee Cluster Library, Table 2.16 Enumerated Status Values
_zcl_enumerated_status_values = {
    0x00: "SUCCESS",
    0x02: "FAILURE",
    # 0x02 - 0x7f Reserved
    0x80: "MALFORMED_COMMAND",
    0x81: "UNSUP_CLUSTER_COMMAND",
    0x82: "UNSUP_GENERAL_COMMAND",
    0x83: "UNSUP_MANUF_CLUSTER_COMMAND",
    0x84: "UNSUP_MANUF_GENERAL_COMMAND",
    0x85: "INVALID_FIELD",
    0x86: "UNSUPPORTED_ATTRIBUTE",
    0x87: "INVALID_VALUE",
    0x88: "READ_ONLY",
    0x89: "INSUFFICIENT_SPACE",
    0x8a: "DUPLICATE_EXISTS",
    0x8b: "NOT_FOUND",
    0x8c: "UNREPORTABLE_ATTRIBUTE",
    0x8d: "INVALID_DATA_TYPE",
    # 0x8e - 0xbf Reserved
    0xc0: "HARDWARE_FAILURE",
    0xc1: "SOFTWARE_FAILURE",
    0xc2: "CALIBRATION_ERROR",
    # 0xc3 - 0xff Reserved
}

# ZigBee Device Profile Status Values
# ZigBee Specification: Table 2.138 ZDP Enumerations Description
_zdp_enumerated_stauts_values = {
    0x00: "SUCCESS",
    # 0X01 - 0X7f Reserved
    0x80: "INV_REQUESTTYPE",
    0X81: "DEVICE_NOT_FOUND",
    0X82: "INVALID_EP",
    0X83: "NOT_ACTIVE",
    0X84: "NOT_SUPPORTED",
    0X85: "TIMEOUT",
    0X86: "NO_MATCH",
    # 0X87 Reserved
    0x88: "NO_ENTRY",
    0x89: "NO_DESCRIPTOR",
    0X8a: "INSUFFICIENT_SPACE",
    0x8b: "NOT_PERMITTED",
    0X8c: "TABLE_FULL",
    0x8d: "NOT_AUTHORIZED",
    0X8e: "DEVICE_BINDING_TABLE_FULL",
    # 0x8f - 0xff Reserved
}

# ZigBee Cluster Library, Table 2.15 Data Types
_zcl_attribute_data_types = {
    0x00: "no_data",
    # General data
    0x08: "8-bit_data",
    0x09: "16-bit_data",
    0x0a: "24-bit_data",
    0x0b: "32-bit_data",
    0x0c: "40-bit_data",
    0x0d: "48-bit_data",
    0x0e: "56-bit_data",
    0x0f: "64-bit_data",
    # Logical
    0x10: "boolean",
    # Bitmap
    0x18: "8-bit_bitmap",
    0x19: "16-bit_bitmap",
    0x1a: "24-bit_bitmap",
    0x1b: "32-bit_bitmap",
    0x1c: "40-bit_bitmap",
    0x1d: "48-bit_bitmap",
    0x1e: "56-bit_bitmap",
    0x1f: "64-bit_bitmap",
    # Unsigned integer
    0x20: "Unsigned_8-bit_integer",
    0x21: "Unsigned_16-bit_integer",
    0x22: "Unsigned_24-bit_integer",
    0x23: "Unsigned_32-bit_integer",
    0x24: "Unsigned_40-bit_integer",
    0x25: "Unsigned_48-bit_integer",
    0x26: "Unsigned_56-bit_integer",
    0x27: "Unsigned_64-bit_integer",
    # Signed integer
    0x28: "Signed_8-bit_integer",
    0x29: "Signed_16-bit_integer",
    0x2a: "Signed_24-bit_integer",
    0x2b: "Signed_32-bit_integer",
    0x2c: "Signed_40-bit_integer",
    0x2d: "Signed_48-bit_integer",
    0x2e: "Signed_56-bit_integer",
    0x2f: "Signed_64-bit_integer",
    # Enumeration
    0x30: "8-bit_enumeration",
    0x31: "16-bit_enumeration",
    # Floating point
    0x38: "semi_precision",
    0x39: "single_precision",
    0x3a: "double_precision",
    # String
    0x41: "octet-string",
    0x42: "character_string",
    0x43: "long_octet_string",
    0x44: "long_character_string",
    # Ordered sequence
    0x48: "array",
    0x4c: "structure",
    # Collection
    0x50: "set",
    0x51: "bag",
    # Time
    0xe0: "time_of_day",
    0xe1: "date",
    0xe2: "utc_time",
    # Identifier
    0xe8: "cluster_id",
    0xe9: "attribute_id",
    0xea: "bacnet_oid",
    # Miscellaneous
    0xf0: "ieee_address",
    0xf1: "128-bit_security_key",
    # Unknown
    0xff: "unknown",
}


# ZigBee #

class ZigbeeNWK(Packet):
    name = "Zigbee Network Layer"
    fields_desc = [
        BitField("discover_route", 0, 2),
        BitField("proto_version", 2, 4),
        BitEnumField("frametype", 0, 2,
                     {0: 'data', 1: 'command', 3: 'Inter-PAN'}),
        FlagsField("flags", 0, 8, ['multicast', 'security', 'source_route', 'extended_dst', 'extended_src', 'reserved1', 'reserved2', 'reserved3']),  # noqa: E501
        XLEShortField("destination", 0),
        XLEShortField("source", 0),
        ByteField("radius", 0),
        ByteField("seqnum", 1),

        # ConditionalField(XLongField("ext_dst", 0), lambda pkt:pkt.flags & 8),

        ConditionalField(dot15d4AddressField("ext_dst", 0, adjust=lambda pkt, x: 8), lambda pkt:pkt.flags & 8),  # noqa: E501
        ConditionalField(dot15d4AddressField("ext_src", 0, adjust=lambda pkt, x: 8), lambda pkt:pkt.flags & 16),  # noqa: E501

        ConditionalField(ByteField("relay_count", 1), lambda pkt:pkt.flags & 0x04),  # noqa: E501
        ConditionalField(ByteField("relay_index", 0), lambda pkt:pkt.flags & 0x04),  # noqa: E501
        ConditionalField(FieldListField("relays", [], XLEShortField("", 0x0000), count_from=lambda pkt:pkt.relay_count), lambda pkt:pkt.flags & 0x04),  # noqa: E501
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            frametype = ord(_pkt[:1]) & 3
            if frametype == 3:
                return ZigbeeNWKStub
        return cls

    def guess_payload_class(self, payload):
        if self.flags.security:
            return ZigbeeSecurityHeader
        elif self.frametype == 0:
            return ZigbeeAppDataPayload
        elif self.frametype == 1:
            return ZigbeeNWKCommandPayload
        elif self.frametype == 3:
            return ZigbeeAppDataPayloadStub
        else:
            return Packet.guess_payload_class(self, payload)


class LinkStatusEntry(Packet):
    name = "ZigBee Link Status Entry"

    fields_desc = [
        # Neighbor network address (2 octets)
        XLEShortField("neighbor_network_address", 0x0000),
        # Link status (1 octet)
        BitField("reserved1", 0, 1),
        BitField("outgoing_cost", 0, 3),
        BitField("reserved2", 0, 1),
        BitField("incoming_cost", 0, 3),
    ]

    def extract_padding(self, p):
        return b"", p


class ZigbeeNWKCommandPayload(Packet):
    name = "Zigbee Network Layer Command Payload"
    fields_desc = [
        ByteEnumField("cmd_identifier", 1, {
            1: "route request",
            2: "route reply",
            3: "network status",
            4: "leave",
            5: "route record",
            6: "rejoin request",
            7: "rejoin response",
            8: "link status",
            9: "network report",
            10: "network update",
            11: "end device timeout request",
            12: "end device timeout response"
            # 0x0d - 0xff reserved
        }),

        # - Route Request Command - #
        # Command options (1 octet)
        ConditionalField(BitField("res1", 0, 1),
                         lambda pkt: pkt.cmd_identifier in [1, 2]),
        ConditionalField(BitField("multicast", 0, 1),
                         lambda pkt: pkt.cmd_identifier in [1, 2]),
        ConditionalField(BitField("dest_addr_bit", 0, 1), lambda pkt: pkt.cmd_identifier == 1),  # noqa: E501
        ConditionalField(
            BitEnumField("many_to_one", 0, 2, {
                0: "not_m2one", 1: "m2one_support_rrt", 2: "m2one_no_support_rrt", 3: "reserved"}  # noqa: E501
            ), lambda pkt: pkt.cmd_identifier == 1),
        ConditionalField(BitField("res2", 0, 3), lambda pkt: pkt.cmd_identifier == 1),  # noqa: E501

        # - Route Reply Command - #
        # Command options (1 octet)
        ConditionalField(BitField("responder_addr_bit", 0, 1), lambda pkt: pkt.cmd_identifier == 2),  # noqa: E501
        ConditionalField(BitField("originator_addr_bit", 0, 1), lambda pkt: pkt.cmd_identifier == 2),  # noqa: E501
        ConditionalField(BitField("res3", 0, 4), lambda pkt: pkt.cmd_identifier == 2),  # noqa: E501
        # Route request identifier (1 octet)
        ConditionalField(ByteField("route_request_identifier", 0),
                         lambda pkt: pkt.cmd_identifier in [1, 2]),  # noqa: E501
        # Originator address (2 octets)
        ConditionalField(XLEShortField("originator_address", 0x0000), lambda pkt: pkt.cmd_identifier == 2),  # noqa: E501
        # Responder address (2 octets)
        ConditionalField(XLEShortField("responder_address", 0x0000), lambda pkt: pkt.cmd_identifier == 2),  # noqa: E501

        # - Network Status Command - #
        # Status code (1 octet)
        ConditionalField(ByteEnumField("status_code", 0, {
            0x00: "No route available",
            0x01: "Tree link failure",
            0x02: "Non-tree link failure",
            0x03: "Low battery level",
            0x04: "No routing capacity",
            0x05: "No indirect capacity",
            0x06: "Indirect transaction expiry",
            0x07: "Target device unavailable",
            0x08: "Target address unallocated",
            0x09: "Parent link failure",
            0x0a: "Validate route",
            0x0b: "Source route failure",
            0x0c: "Many-to-one route failure",
            0x0d: "Address conflict",
            0x0e: "Verify addresses",
            0x0f: "PAN identifier update",
            0x10: "Network address update",
            0x11: "Bad frame counter",
            0x12: "Bad key sequence number",
            # 0x13 - 0xff Reserved
        }), lambda pkt: pkt.cmd_identifier == 3),
        # Destination address (2 octets)
        ConditionalField(XLEShortField("destination_address", 0x0000),
                         lambda pkt: pkt.cmd_identifier in [1, 3]),
        # Path cost (1 octet)
        ConditionalField(ByteField("path_cost", 0),
                         lambda pkt: pkt.cmd_identifier in [1, 2]),  # noqa: E501
        # Destination IEEE Address (0/8 octets), only present when dest_addr_bit has a value of 1  # noqa: E501
        ConditionalField(dot15d4AddressField("ext_dst", 0, adjust=lambda pkt, x: 8),  # noqa: E501
                         lambda pkt: (pkt.cmd_identifier == 1 and pkt.dest_addr_bit == 1)),  # noqa: E501
        # Originator IEEE address (0/8 octets)
        ConditionalField(dot15d4AddressField("originator_addr", 0, adjust=lambda pkt, x: 8),  # noqa: E501
                         lambda pkt: (pkt.cmd_identifier == 2 and pkt.originator_addr_bit == 1)),  # noqa: E501
        # Responder IEEE address (0/8 octets)
        ConditionalField(dot15d4AddressField("responder_addr", 0, adjust=lambda pkt, x: 8),  # noqa: E501
                         lambda pkt: (pkt.cmd_identifier == 2 and pkt.responder_addr_bit == 1)),  # noqa: E501

        # - Leave Command - #
        # Command options (1 octet)
        # Bit 7: Remove children
        ConditionalField(BitField("remove_children", 0, 1), lambda pkt: pkt.cmd_identifier == 4),  # noqa: E501
        # Bit 6: Request
        ConditionalField(BitField("request", 0, 1), lambda pkt: pkt.cmd_identifier == 4),  # noqa: E501
        # Bit 5: Rejoin
        ConditionalField(BitField("rejoin", 0, 1), lambda pkt: pkt.cmd_identifier == 4),  # noqa: E501
        # Bit 0 - 4: Reserved
        ConditionalField(BitField("res4", 0, 5), lambda pkt: pkt.cmd_identifier == 4),  # noqa: E501

        # - Route Record Command - #
        # Relay count (1 octet)
        ConditionalField(ByteField("rr_relay_count", 0), lambda pkt: pkt.cmd_identifier == 5),  # noqa: E501
        # Relay list (variable in length)
        ConditionalField(
            FieldListField("rr_relay_list", [], XLEShortField("", 0x0000), count_from=lambda pkt:pkt.rr_relay_count),  # noqa: E501
            lambda pkt:pkt.cmd_identifier == 5),

        # - Rejoin Request Command - #
        # Capability Information (1 octet)
        ConditionalField(BitField("allocate_address", 0, 1), lambda pkt:pkt.cmd_identifier == 6),  # Allocate Address  # noqa: E501
        ConditionalField(BitField("security_capability", 0, 1), lambda pkt:pkt.cmd_identifier == 6),  # Security Capability  # noqa: E501
        ConditionalField(BitField("reserved2", 0, 1), lambda pkt:pkt.cmd_identifier == 6),  # bit 5 is reserved  # noqa: E501
        ConditionalField(BitField("reserved1", 0, 1), lambda pkt:pkt.cmd_identifier == 6),  # bit 4 is reserved  # noqa: E501
        ConditionalField(BitField("receiver_on_when_idle", 0, 1), lambda pkt:pkt.cmd_identifier == 6),  # Receiver On When Idle  # noqa: E501
        ConditionalField(BitField("power_source", 0, 1), lambda pkt:pkt.cmd_identifier == 6),  # Power Source  # noqa: E501
        ConditionalField(BitField("device_type", 0, 1), lambda pkt:pkt.cmd_identifier == 6),  # Device Type  # noqa: E501
        ConditionalField(BitField("alternate_pan_coordinator", 0, 1), lambda pkt:pkt.cmd_identifier == 6),  # Alternate PAN Coordinator  # noqa: E501

        # - Rejoin Response Command - #
        # Network address (2 octets)
        ConditionalField(XLEShortField("network_address", 0xFFFF), lambda pkt:pkt.cmd_identifier == 7),  # noqa: E501
        # Rejoin status (1 octet)
        ConditionalField(ByteField("rejoin_status", 0), lambda pkt:pkt.cmd_identifier == 7),  # noqa: E501

        # - Link Status Command - #
        # Command options (1 octet)
        ConditionalField(BitField("res5", 0, 1), lambda pkt:pkt.cmd_identifier == 8),  # Reserved  # noqa: E501
        ConditionalField(BitField("last_frame", 0, 1), lambda pkt:pkt.cmd_identifier == 8),  # Last frame  # noqa: E501
        ConditionalField(BitField("first_frame", 0, 1), lambda pkt:pkt.cmd_identifier == 8),  # First frame  # noqa: E501
        ConditionalField(BitField("entry_count", 0, 5), lambda pkt:pkt.cmd_identifier == 8),  # Entry count  # noqa: E501
        # Link status list (variable size)
        ConditionalField(
            PacketListField("link_status_list", [], LinkStatusEntry, count_from=lambda pkt:pkt.entry_count),  # noqa: E501
            lambda pkt:pkt.cmd_identifier == 8),

        # - Network Report Command - #
        # Command options (1 octet)
        ConditionalField(
            BitEnumField("report_command_identifier", 0, 3, {0: "PAN identifier conflict"}),  # 0x01 - 0x07 Reserved  # noqa: E501
            lambda pkt: pkt.cmd_identifier == 9),
        ConditionalField(BitField("report_information_count", 0, 5), lambda pkt: pkt.cmd_identifier == 9),  # noqa: E501

        # - Network Update Command - #
        # Command options (1 octet)
        ConditionalField(
            BitEnumField("update_command_identifier", 0, 3, {0: "PAN Identifier Update"}),  # 0x01 - 0x07 Reserved  # noqa: E501
            lambda pkt: pkt.cmd_identifier == 10),
        ConditionalField(BitField("update_information_count", 0, 5), lambda pkt: pkt.cmd_identifier == 10),  # noqa: E501
        # EPID: Extended PAN ID (8 octets)
        ConditionalField(
            dot15d4AddressField("epid", 0, adjust=lambda pkt, x: 8),
            lambda pkt: pkt.cmd_identifier in [9, 10]
        ),
        # Report information (variable length)
        # Only present if we have a PAN Identifier Conflict Report
        ConditionalField(
            FieldListField("PAN_ID_conflict_report", [], XLEShortField("", 0x0000),  # noqa: E501
                           count_from=lambda pkt:pkt.report_information_count),
            lambda pkt:(pkt.cmd_identifier == 9 and pkt.report_command_identifier == 0)  # noqa: E501
        ),
        # Update Id (1 octet)
        ConditionalField(ByteField("update_id", 0), lambda pkt: pkt.cmd_identifier == 10),  # noqa: E501
        # Update Information (Variable)
        # Only present if we have a PAN Identifier Update
        # New PAN ID (2 octets)
        ConditionalField(XLEShortField("new_PAN_ID", 0x0000),
                         lambda pkt: (pkt.cmd_identifier == 10 and pkt.update_command_identifier == 0)),  # noqa: E501

        # - End Device Timeout Request Command - #
        # Requested Timeout (1 octet)
        ConditionalField(
            ByteEnumField("req_timeout", 3, {
                0: "10 seconds",
                1: "2 minutes",
                2: "4 minutes",
                3: "8 minutes",
                4: "16 minutes",
                5: "32 minutes",
                6: "64 minutes",
                7: "128 minutes",
                8: "256 minutes",
                9: "512 minutes",
                10: "1024 minutes",
                11: "2048 minutes",
                12: "4096 minutes",
                13: "8192 minutes",
                14: "16384 minutes"
            }),
            lambda pkt: pkt.cmd_identifier == 11),
        # End Device Configuration (1 octet)
        ConditionalField(
            ByteField("ed_conf", 0),
            lambda pkt: pkt.cmd_identifier == 11),

        # - End Device Timeout Response Command - #
        # Status (1 octet)
        ConditionalField(
            ByteEnumField("status", 0, {
                0: "Success",
                1: "Incorrect Value"
            }),
            lambda pkt: pkt.cmd_identifier == 12),
        # Parent Information (1 octet)
        ConditionalField(
            BitField("res6", 0, 6),
            lambda pkt: pkt.cmd_identifier == 12),
        ConditionalField(
            BitField("ed_timeout_req_keepalive", 0, 1),
            lambda pkt: pkt.cmd_identifier == 12),
        ConditionalField(
            BitField("mac_data_poll_keepalive", 0, 1),
            lambda pkt: pkt.cmd_identifier == 12)

        # StrField("data", ""),
    ]


def util_mic_len(pkt):
    ''' Calculate the length of the attribute value field '''
    if (pkt.nwk_seclevel == 0):  # no encryption, no mic
        return 0
    elif (pkt.nwk_seclevel == 1):  # MIC-32
        return 4
    elif (pkt.nwk_seclevel == 2):  # MIC-64
        return 8
    elif (pkt.nwk_seclevel == 3):  # MIC-128
        return 16
    elif (pkt.nwk_seclevel == 4):  # ENC
        return 0
    elif (pkt.nwk_seclevel == 5):  # ENC-MIC-32
        return 4
    elif (pkt.nwk_seclevel == 6):  # ENC-MIC-64
        return 8
    elif (pkt.nwk_seclevel == 7):  # ENC-MIC-128
        return 16
    else:
        return 0


class ZigbeeSecurityHeader(Packet):
    name = "Zigbee Security Header"
    fields_desc = [
        # Security control (1 octet)
        FlagsField("reserved1", 0, 2, ['reserved1', 'reserved2']),
        BitField("extended_nonce", 1, 1),  # set to 1 if the sender address field is present (source)  # noqa: E501
        # Key identifier
        BitEnumField("key_type", 1, 2, {
            0: 'data_key',
            1: 'network_key',
            2: 'key_transport_key',
            3: 'key_load_key'
        }),
        # Security level (3 bits)
        BitEnumField("nwk_seclevel", 0, 3, {
            0: "None",
            1: "MIC-32",
            2: "MIC-64",
            3: "MIC-128",
            4: "ENC",
            5: "ENC-MIC-32",
            6: "ENC-MIC-64",
            7: "ENC-MIC-128"
        }),
        # Frame counter (4 octets)
        XLEIntField("fc", 0),  # provide frame freshness and prevent duplicate frames  # noqa: E501
        # Source address (0/8 octets)
        ConditionalField(dot15d4AddressField("source", 0, adjust=lambda pkt, x: 8), lambda pkt: pkt.extended_nonce),  # noqa: E501
        # Key sequence number (0/1 octet): only present when key identifier is 1 (network key)  # noqa: E501
        ConditionalField(ByteField("key_seqnum", 0), lambda pkt: pkt.getfieldval("key_type") == 1),  # noqa: E501
        # Payload
        # the length of the encrypted data is the payload length minus the MIC
        StrField("data", ""),  # noqa: E501
        # Message Integrity Code (0/variable in size), length depends on nwk_seclevel  # noqa: E501
        XStrField("mic", ""),
    ]

    def post_dissect(self, s):
        # Get the mic dissected correctly
        mic_length = util_mic_len(self)
        if mic_length > 0:  # Slice "data" into "data + mic"
            _data, _mic = self.data[:-mic_length], self.data[-mic_length:]
            self.data, self.mic = _data, _mic
        return s


class ZigbeeAppDataPayload(Packet):
    name = "Zigbee Application Layer Data Payload (General APS Frame Format)"
    fields_desc = [
        # Frame control (1 octet)
        FlagsField("frame_control", 2, 4,
                   ['ack_format', 'security', 'ack_req', 'extended_hdr']),
        BitEnumField("delivery_mode", 0, 2,
                     {0: 'unicast', 1: 'indirect',
                      2: 'broadcast', 3: 'group_addressing'}),
        BitEnumField("aps_frametype", 0, 2,
                     {0: 'data', 1: 'command', 2: 'ack'}),
        # Destination endpoint (0/1 octet)
        ConditionalField(
            ByteField("dst_endpoint", 10),
            lambda pkt: ((pkt.aps_frametype == 0 and
                          pkt.delivery_mode in [0, 2]) or
                         (pkt.aps_frametype == 2 and not
                          pkt.frame_control.ack_format))
        ),
        # Group address (0/2 octets)
        ConditionalField(
            XLEShortField("group_addr", 0x0000),
            lambda pkt: (pkt.aps_frametype == 0 and pkt.delivery_mode == 3)
        ),
        # Cluster identifier (0/2 octets)
        ConditionalField(
            # unsigned short (little-endian)
            EnumField("cluster", 0, _zcl_cluster_identifier, fmt="<H"),
            lambda pkt: ((pkt.aps_frametype == 0) or
                         (pkt.aps_frametype == 2 and not
                          pkt.frame_control.ack_format))
        ),
        # Profile identifier (0/2 octets)
        ConditionalField(
            EnumField("profile", 0, _zcl_profile_identifier, fmt="<H"),
            lambda pkt: ((pkt.aps_frametype == 0) or
                         (pkt.aps_frametype == 2 and not
                          pkt.frame_control.ack_format))
        ),
        # Source endpoint (0/1 octets)
        ConditionalField(
            ByteField("src_endpoint", 10),
            lambda pkt: ((pkt.aps_frametype == 0) or
                         (pkt.aps_frametype == 2 and not
                          pkt.frame_control.ack_format))
        ),
        # APS counter (1 octet)
        ByteField("counter", 0),
        # Extended header (0/1/2 octets)
        # cribbed from https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-zbee-aps.c  # noqa: E501
        ConditionalField(
            ByteEnumField(
                "fragmentation", 0,
                {0: "none", 1: "first_block", 2: "middle_block"}),
            lambda pkt: (pkt.aps_frametype in [0, 2] and
                         pkt.frame_control.extended_hdr)
        ),
        ConditionalField(
            ByteField("block_number", 0),
            lambda pkt: (pkt.aps_frametype in [0, 2] and
                         pkt.fragmentation in [1, 2])
        ),
        ConditionalField(
            ByteField("ack_bitfield", 0),
            lambda pkt: (pkt.aps_frametype == 2 and
                         pkt.fragmentation in [1, 2])
        ),
        # variable length frame payload:
        # 3 frame types: data, APS command, and acknowledgement
        # ConditionalField(StrField("data", ""), lambda pkt:pkt.aps_frametype == 0),  # noqa: E501
    ]

    def guess_payload_class(self, payload):
        if self.frame_control & 0x02:  # we have a security header
            return ZigbeeSecurityHeader
        elif self.aps_frametype == 0:  # data
            if self.profile == 0x0000:
                if self.cluster == 0x0031:
                    return ZDPLqiRequest
                if self.cluster == 0x8031:
                    return ZDPLqiResponse
                if self.cluster == 0x0032:
                    return ZDPRoutingTableRequest
                if self.cluster == 0x8032:
                    return ZDPRoutingTableResponse
                if self.cluster == 0x0033:
                    return ZDPBindingTableRequest
                if self.cluster == 0x8033:
                    return ZDPBindingTableResponse
                if self.cluster == 0x0034:
                    return ZDPLeaveRequest
                if self.cluster == 0x8034:
                    return ZDPLeaveResponse

                return ZigbeeDeviceProfile
            else:
                return ZigbeeClusterLibrary
        elif self.aps_frametype == 1:  # command
            return ZigbeeAppCommandPayload
        else:
            return Packet.guess_payload_class(self, payload)


_TransportKeyKeyTypes = {
    0x00: "Trust Center Master Key",
    0x01: "Standard Network Key",
    0x02: "Application Master Key",
    0x03: "Application Link Key",
    0x04: "Trust Center Link Key",
    0x05: "High-Security Network Key",
    0x06: "Unknown Network Key?"
}


_RequestKeyKeyTypes = {
    0x02: "Application Link Key",
    0x04: "Trust Center Link Key",
}


_ApsStatusValues = {
    0x00: "SUCCESS",
    0xa0: "ASDU_TOO_LONG",
    0xa1: "DEFRAG_DEFERRED",
    0xa2: "DEFRAG_UNSUPPORTED",
    0xa3: "ILLEGAL_REQUEST",
    0xa4: "INVALID_BINDING",
    0xa5: "INVALID_GROUP",
    0xa6: "INVALID_PARAMETER",
    0xa7: "NO_ACK",
    0xa8: "NO_BOUND_DEVICE",
    0xa9: "NO_SHORT_ADDRESS",
    0xaa: "NOT_SUPPORTED",
    0xab: "SECURED_LINK_KEY",
    0xac: "SECURED_NWK_KEY",
    0xad: "SECURITY_FAIL",
    0xae: "TABLE_FULL",
    0xaf: "UNSECURED",
    0xb0: "UNSUPPORTED_ATTRIBUTE"
}


class ZigbeeAppCommandPayload(Packet):
    name = "Zigbee Application Layer Command Payload"
    fields_desc = [
        ByteEnumField("cmd_identifier", 1, {
            1: "APS_CMD_SKKE_1",
            2: "APS_CMD_SKKE_2",
            3: "APS_CMD_SKKE_3",
            4: "APS_CMD_SKKE_4",
            5: "APS_CMD_TRANSPORT_KEY",
            6: "APS_CMD_UPDATE_DEVICE",
            7: "APS_CMD_REMOVE_DEVICE",
            8: "APS_CMD_REQUEST_KEY",
            9: "APS_CMD_SWITCH_KEY",
            # TODO: implement 10 to 13
            10: "APS_CMD_EA_INIT_CHLNG",
            11: "APS_CMD_EA_RSP_CHLNG",
            12: "APS_CMD_EA_INIT_MAC_DATA",
            13: "APS_CMD_EA_RSP_MAC_DATA",
            14: "APS_CMD_TUNNEL",
            15: "APS_CMD_VERIFY_KEY",
            16: "APS_CMD_CONFIRM_KEY"
        }),
        # SKKE Commands
        ConditionalField(dot15d4AddressField("initiator", 0,
                                             adjust=lambda pkt, x: 8),
                         lambda pkt: pkt.cmd_identifier in [1, 2, 3, 4]),
        ConditionalField(dot15d4AddressField("responder", 0,
                                             adjust=lambda pkt, x: 8),
                         lambda pkt: pkt.cmd_identifier in [1, 2, 3, 4]),
        ConditionalField(StrFixedLenField("data", 0, length=16),
                         lambda pkt: pkt.cmd_identifier in [1, 2, 3, 4]),
        # Confirm-key command
        ConditionalField(
            ByteEnumField("status", 0, _ApsStatusValues),
            lambda pkt: pkt.cmd_identifier == 16),
        # Common fields
        ConditionalField(
            ByteEnumField("key_type", 0, _TransportKeyKeyTypes),
            lambda pkt: pkt.cmd_identifier in [5, 8, 15, 16]),
        ConditionalField(dot15d4AddressField("address", 0,
                                             adjust=lambda pkt, x: 8),
                         lambda pkt: pkt.cmd_identifier in [6, 7, 15, 16]),
        # Transport-key Command
        ConditionalField(
            StrFixedLenField("key", None, 16),	#NOTE uses XBitField of size 128 instead of StrFixedLenField
            lambda pkt: pkt.cmd_identifier == 5),
        ConditionalField(
            ByteField("key_seqnum", 0),	#NOTE called network_key_sqn and did not include 6 in lambda
            lambda pkt: (pkt.cmd_identifier == 5 and
                         pkt.key_type in [0x01, 0x05, 0x06])),
        ConditionalField(
            dot15d4AddressField("dest_addr", 0, adjust=lambda pkt, x: 8), #NOTE called key_dest_addr
            lambda pkt: ((pkt.cmd_identifier == 5 and
                         pkt.key_type not in [0x02, 0x03]) or
                         pkt.cmd_identifier == 14)),
        ConditionalField(
            dot15d4AddressField("src_addr", 0, adjust=lambda pkt, x: 8), #NOTE called key_src_addr in z3
            lambda pkt: (pkt.cmd_identifier == 5 and
                         pkt.key_type not in [0x02, 0x03])),
        ConditionalField(
            dot15d4AddressField("partner_addr", 0, adjust=lambda pkt, x: 8), #NOTE same as z3, used
            lambda pkt: ((pkt.cmd_identifier == 5 and
                         pkt.key_type in [0x02, 0x03]) or
                         (pkt.cmd_identifier == 8 and pkt.key_type == 0x02))),
        ConditionalField(
            ByteField("initiator_flag", 0),	#NOTE same as z3, used
            lambda pkt: (pkt.cmd_identifier == 5 and
                         pkt.key_type in [0x02, 0x03])),
        # Update-Device Command
        ConditionalField(XLEShortField("short_address", 0),
                         lambda pkt: pkt.cmd_identifier == 6),
        ConditionalField(ByteField("update_status", 0),
                         lambda pkt: pkt.cmd_identifier == 6),
        # Switch-Key Command
        ConditionalField(StrFixedLenField("seqnum", None, 8),
                         lambda pkt: pkt.cmd_identifier == 9),
        # Un-implemented: 10-13 (+?)
        ConditionalField(StrField("unimplemented", ""),
                         lambda pkt: (pkt.cmd_identifier >= 10 and
                                      pkt.cmd_identifier <= 13)),
        # Tunnel Command
        ConditionalField(
            FlagsField("frame_control", 2, 4, [
                "ack_format",
                "security",
                "ack_req",
                "extended_hdr"
            ]),
            lambda pkt: pkt.cmd_identifier == 14),
        ConditionalField(
            BitEnumField("delivery_mode", 0, 2, {
                0: "unicast",
                1: "indirect",
                2: "broadcast",
                3: "group_addressing"
            }),
            lambda pkt: pkt.cmd_identifier == 14),
        ConditionalField(
            BitEnumField("aps_frametype", 1, 2, {
                0: "data",
                1: "command",
                2: "ack"
            }),
            lambda pkt: pkt.cmd_identifier == 14),
        ConditionalField(
            ByteField("counter", 0),
            lambda pkt: pkt.cmd_identifier == 14),
        # Verify-Key Command
        ConditionalField(
            StrFixedLenField("key_hash", None, 16),
            lambda pkt: pkt.cmd_identifier == 15),
    ]

    def guess_payload_class(self, payload):
        if self.cmd_identifier == 14:
            # Tunneled APS Auxiliary Header
            return ZigbeeSecurityHeader
        else:
            return Packet.guess_payload_class(self, payload)


class ZigBeeBeacon(Packet):
    name = "ZigBee Beacon Payload"
    fields_desc = [
        # Protocol ID (1 octet)
        ByteField("proto_id", 0),
        # nwkcProtocolVersion (4 bits)
        BitField("nwkc_protocol_version", 0, 4),
        # Stack profile (4 bits)
        BitField("stack_profile", 0, 4),
        # End device capacity (1 bit)
        BitField("end_device_capacity", 0, 1),
        # Device depth (4 bits)
        BitField("device_depth", 0, 4),
        # Router capacity (1 bit)
        BitField("router_capacity", 0, 1),
        # Reserved (2 bits)
        BitField("reserved", 0, 2),
        # Extended PAN ID (8 octets)
        dot15d4AddressField("extended_pan_id", 0, adjust=lambda pkt, x: 8),
        # Tx offset (3 bytes)
        # In ZigBee 2006 the Tx-Offset is optional, while in the 2007 and later versions, the Tx-Offset is a required value.  # noqa: E501
        BitField("tx_offset", 0, 24),
        # Update ID (1 octet)
        ByteField("update_id", 0),
    ]


# Inter-PAN Transmission #
class ZigbeeNWKStub(Packet):
    name = "Zigbee Network Layer for Inter-PAN Transmission"
    fields_desc = [
        # NWK frame control
        BitField("res1", 0, 2),  # remaining subfields shall have a value of 0  # noqa: E501
        BitField("proto_version", 2, 4),
        BitField("frametype", 0b11, 2),  # 0b11 (3) is a reserved frame type
        BitField("res2", 0, 8),  # remaining subfields shall have a value of 0  # noqa: E501
    ]

    def guess_payload_class(self, payload):
        if self.frametype == 0b11:
            return ZigbeeAppDataPayloadStub
        else:
            return Packet.guess_payload_class(self, payload)


class ZigbeeAppDataPayloadStub(Packet):
    name = "Zigbee Application Layer Data Payload for Inter-PAN Transmission"
    fields_desc = [
        FlagsField("frame_control", 0, 4, ['reserved1', 'security', 'ack_req', 'extended_hdr']),  # noqa: E501
        BitEnumField("delivery_mode", 0, 2, {0: 'unicast', 2: 'broadcast', 3: 'group'}),  # noqa: E501
        BitField("frametype", 3, 2),  # value 0b11 (3) is a reserved frame type
        # Group Address present only when delivery mode field has a value of 0b11 (group delivery mode)  # noqa: E501
        ConditionalField(
            XLEShortField("group_addr", 0x0),  # 16-bit identifier of the group
            lambda pkt: pkt.getfieldval("delivery_mode") == 0b11
        ),
        # Cluster identifier
        EnumField("cluster", 0, _zcl_cluster_identifier, fmt="<H"),  # unsigned short (little-endian)  # noqa: E501
        # Profile identifier
        EnumField("profile", 0, _zcl_profile_identifier, fmt="<H"),
        # ZigBee Payload
        #ConditionalField(
#            StrField("data", ""),
#            lambda pkt: pkt.frametype == 3
#        ),	#NOTE COMMENTED OUT TO MATCH Z3, MAYBE NOT NECESSARY
    ]

    def guess_payload_class(self, payload):
        if self.frametype == 3 and self.profile == 0xc05e and self.cluster == 0x1000:
            return ZigbeeZLLCommissioningCluster
        else:
            return Packet.guess_payload_class(self, payload)

class ZigbeeZLLCommissioningCluster(Packet):
    name = "Zigbee LightLink Commissioning Cluster Frame"
    fields_desc = [
        # Frame control (8 bits)
        BitField("reserved", 0, 3),
        BitField("disable_default_response", 1, 1), # 1 not default response command will be returned
        BitEnumField("direction", 0, 1, ['client2server', 'server2client']),
        BitField("manufacturer_specific", 0, 1), # 0 manufacturer code shall not be included in the ZCL frame
        # Frame Type
        # 0b00 command acts across the entire profile
        # 0b01 command is specific to a cluster
        # 0b10 - 0b11 reserved
        BitField("zcl_frametype", 1, 2),
        # Manufacturer code (0/16 bits) only present then manufacturer_specific field is set to 1
        ConditionalField(XLEShortField("manufacturer_code", 0x0),
            lambda pkt:pkt.getfieldval("manufacturer_specific") == 1
        ),
        # Transaction sequence number (8 bits)
        ByteField("transaction_sequence", 0),
        # Command identifier (8 bits): the cluster command
        ByteEnumField("command_identifier", 0x00, _zll_command_frames),
    ]

    def guess_payload_class(self, payload):
        if self.command_identifier == 0x00:# and pkt.cluster == 0x1000:
            return ZLLScanRequest
        elif self.command_identifier == 0x01:# and pkt.cluster == 0x1000:
            return ZLLScanResponse
        else:
            return Packet.guess_payload_class(self, payload)

class ZLLScanRequest(Packet):
    name = "ZLL: Scan Request"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666), # Unsigned 32-bit Integer (4 octets)
	# ZigBee information (1 octet)
        #HiddenField(BitField("reserved", 0, 5)), #Removed Hidden
        BitField("reserved", 0, 5),
        BitEnumField("rx_on_when_idle", 1, 1, [False, True]),
        BitEnumField("logical_type", 1, 2, {
            0:"coordinator", 1:"router", 2:"end device", 3:"reserved"}
        ),
	# ZLL information (1 octet)
        #FlagsField("ZLL information", 0, 8, [ 'factory_new', 'address_assignment', 'reserved1', 'reserved2', 'link_initiator', 'undefined', 'reserved3', 'reserved4' ]),
        #HiddenField(BitField("reserved1", 0, 2)),  #Removed Hidden
        #HiddenField(BitField("undefined", 0, 1)),  #Removed Hidden
        BitField("reserved1", 0, 2),
        BitField("undefined", 0, 1),
        BitEnumField("link_initiator", 0, 1, [False, True]),
        #HiddenField(BitField("reserved2", 0, 2)),
        BitField("reserved2", 0, 2),                #Removed Hidden
        BitEnumField("address_assignment", 0, 1, [False, True]),
        BitEnumField("factory_new", 0, 1, [False, True]),
    ]
    def answers(self, other):
        if isinstance(other, ZLLScanResponse):
            return self.inter_pan_transaction_id == other.inter_pan_transaction_id
        return 0

class ZLLScanResponse(Packet):
    name = "ZLL: Scan Response"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
        ByteField("rssi_correction", 0x00), # range 0x00 - 0x20 (1 octet)
	# ZigBee information (1 octet)
        # HiddenField(BitField("reserved", 0, 5)),
        BitField("reserved", 0, 5),
        BitEnumField("rx_on_when_idle", 1, 1, [False, True]),
        BitEnumField("logical_type", 1, 2, {
            0:"coordinator", 1:"router", 2:"end device", 3:"reserved"}
        ),
	# ZLL information (1 octet)
        # HiddenField(BitField("reserved1", 0, 2)),
        BitField("reserved1", 0, 2),
        BitEnumField("touchlink_priority_request", 0, 1, [False, True]),
        BitEnumField("touchlink_initiator", 0, 1, [False, True]),
        # HiddenField(BitField("reserved2", 0, 2)),
        BitField("reserved2", 0, 2),
        BitEnumField("address_assignment", 0, 1, [False, True]),
        BitEnumField("factory_new", 0, 1, [False, True]),
        # Key bitmask (2 octets)
        FlagsField("key_bitmask", 0, 16, ["reserved_key_8", "reserved_key_9",
            "reserved_key_10", "reserved_key_11", "reserved_key_12",
            "reserved_key_13", "reserved_key_14", "certification_key",
            "development_key", "reserved_key_1", "reserved_key_2", "reserved_key_3",
            "master_key", "reserved_key_5", "reserved_key_6",
            "reserved_key_7"]),
        # BitField("reserved3", 0, 3),
        # BitEnumField("master_key", 0, 1, [False, True]),
        # BitField("reserved4", 0, 3),
        # BitEnumField("development_key", 0, 1, [False, True]),
        # BitEnumField("certification_key", 0, 1, [False, True]),
        # BitField("reserved5", 0, 3),
        # BitField("reserved6", 0, 4),

        # Response identifier (4 octets)
        XLEIntField("response_id", 0x66666666),
        # Extended PAN identifier (8 octets)
        dot15d4AddressField("pan_id_ext", 0, adjust=lambda pkt,x: 8),
        # Network update identifier (1 octet)
        ByteField("network_update_id", 0),
        # Logical channel (1 octet)
        ByteField("channel", 11),
        # PAN identifier (2 octets)
        XLEShortField("pan_id", 0x0000),
        # Network address (2 octets)
        XLEShortField("network_address", 0xffff),
        # Number of sub-devices (1 octet)
        ByteField("number_of_sub_devices", 1),
        # Total group identifiers (1 octet)
        ByteField("number_of_group_ids", 0),
        # Endpoint identifier (0/1 octets)
        ConditionalField(ByteField("endpoint_id", 0x00), lambda pkt:(pkt.getfieldval("number_of_sub_devices") == 1)),
        # Profile identifier (0/2 octets)
        #ConditionalField(XShortField("profile_id", 0x0000)
        ConditionalField(EnumField("profile_id", 0, _zcl_profile_identifier, fmt = "<H"), lambda pkt:(pkt.getfieldval("number_of_sub_devices") == 1)),
        # Device identifier (0/2 octets)
        ConditionalField(XShortField("device_id", 0x0000), lambda pkt:(pkt.getfieldval("number_of_sub_devices") == 1)),
        # Version (0/1 octets)
        # HiddenField(ConditionalField(BitField("0x0", 0, 4), lambda pkt:(pkt.getfieldval("number_of_sub_devices") == 1))),
        ConditionalField(BitField("0x0", 0, 4), lambda pkt:(pkt.getfieldval("number_of_sub_devices") == 1)),
        ConditionalField(BitField("application_device_version", 2, 4), lambda pkt:(pkt.getfieldval("number_of_sub_devices") == 1)),
        # Group identifier count (0/1 octets)
        ConditionalField(ByteField("group_id_count", 0x00), lambda pkt:(pkt.getfieldval("number_of_sub_devices") == 1)),
    ]

class ZLLDeviceInformationRequest(Packet):
    name = "ZLL: Device Information Request"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
	# Start index of device table (1 octet)
        ByteField("start_index", 0),
    ]

class ZLLIdentifyRequest(Packet):
    name = "ZLL: Identify Request"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
        # Identify duration (1 octet):
        #   0x0000: Exit identify mode
        #   0x0001 - 0xfffe: Number of seconds to remain in identify mode
        #   0xffff: Remain in identify mode for a default time known by the receiver
        XLEShortField("identify_duration", 0xffff),
    ]

class ZLLResetToFactoryNewRequest(Packet):
    name = "ZLL: Reset to Factory New Request"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
    ]

class ZLLNetworkStartRequest(Packet):
    name = "ZLL: Network Start Request"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
        # Extended PAN identifier (8 octets)
        dot15d4AddressField("pan_id_ext", 0, adjust=lambda pkt,x: 8),
        # Key index (1 octets)
        ByteField("key_index", 4),  # default: Master key
        # Encrypted network key (16 octets)
        XBitField("encrypted_network_key", 0, 128),
        # Logical channel (1 octet)
        ByteField("channel", 0),
        # PAN identifier (2 octets)
        XLEShortField("pan_id", 0x0000),
        # Network address (2 octets)
        XLEShortField("network_address", 0x0001),
        # Group identifiers begin (2 octets)
        XLEShortField("group_id_begin", 0),
        # Group identifiers end (2 octets)
        XLEShortField("group_id_end", 0),
        # Free network address range begin (2 octets)
        XLEShortField("free_network_address_range_begin", 0),
        # Free network address range end (2 octets)
        XLEShortField("free_network_address_range_end", 0),
        # Free group address range begin (2 octets)
        XLEShortField("free_group_address_range_begin", 0),
        # Free group address range end (2 octets)
        XLEShortField("free_group_address_range_end", 0),
        # Initiator IEEE address (8 octet)
        XBitField("initiator_ieee_address", 0, 64),
        # Initiator network address (2 octets)
        XLEShortField("initiator_network_address", 0),
    ]

class ZLLNetworkStartResponse(Packet):
    name = "ZLL: Network Start Response"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
        # Status (1 octet)
        ByteEnumField("status", 0, {0: "success", 1: "failure",
            2: "reserved_status_2", 3: "reserved_status_3",
            4: "reserved_status_4", 5: "reserved_status_5",
            6: "reserved_status_6", 7: "reserved_status_7",
            8: "reserved_status_8", 9: "reserved_status_9",
            10: "reserved_status_10", 11: "reserved_status_11",
            12: "reserved_status_12", 13: "reserved_status_13",
            14: "reserved_status_14", 15: "reserved_status_15"}),
        # Extended PAN identifier (8 octets)
        dot15d4AddressField("pan_id_ext", 0, adjust=lambda pkt,x: 8),
        # Network update identifier (1 octet)
        ByteField("network_update_id", 0x00),
        # Logical channel (1 octet)
        ByteField("channel", 11),
        # PAN identifier (2 octets)
        XLEShortField("pan_id", 0x0000),
    ]

class ZLLNetworkJoinRouterRequest(Packet):
    name = "ZLL: Network Join Router Request"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
        # Extended PAN identifier (8 octets)
        dot15d4AddressField("pan_id_ext", 0, adjust=lambda pkt,x: 8),
        # Key index (1 octets)
        ByteField("key_index", 4),  # default: Master key
        # Encrypted network key (16 octets)
        XBitField("encrypted_network_key", 0, 128),
        # Network update identifier (1 octet)
        ByteField("network_update_id", 0x00),
        # Logical channel (1 octet)
        ByteField("channel", 0),
        # PAN identifier (2 octets)
        XLEShortField("pan_id", 0x0000),
        # Network address (2 octets)
        XLEShortField("network_address", 0x0001),
        # Group identifiers begin (2 octets)
        XLEShortField("group_id_begin", 0),
        # Group identifiers end (2 octets)
        XLEShortField("group_id_end", 0),
        # Free network address range begin (2 octets)
        XLEShortField("free_network_address_range_begin", 0),
        # Free network address range end (2 octets)
        XLEShortField("free_network_address_range_end", 0),
        # Free group address range begin (2 octets)
        XLEShortField("free_group_address_range_begin", 0),
        # Free group address range end (2 octets)
        XLEShortField("free_group_address_range_end", 0),
    ]

class ZLLNetworkJoinRouterResponse(Packet):
    name = "ZLL: Network Join Router Response"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
        # Status (1 octet)
        ByteEnumField("status", 0, {0: "success", 1: "failure",
            2: "reserved_status_2", 3: "reserved_status_3",
            4: "reserved_status_4", 5: "reserved_status_5",
            6: "reserved_status_6", 7: "reserved_status_7",
            8: "reserved_status_8", 9: "reserved_status_9",
            10: "reserved_status_10", 11: "reserved_status_11",
            12: "reserved_status_12", 13: "reserved_status_13",
            14: "reserved_status_14", 15: "reserved_status_15"}),
    ]

class ZLLNetworkUpdateRequest(Packet):
    name = "ZLL: Network Update Request"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
        # Extended PAN identifier (8 octets)
        dot15d4AddressField("pan_id_ext", 0, adjust=lambda pkt,x: 8),
        # Network update identifier (1 octet)
        ByteField("network_update_id", 0x00),
        # Logical Channel (1 octet)
        ByteField("channel", 11),
        # PAN identifier (2 octets)
        XLEShortField("pan_id", 0x0000),
        # Network address (2 octets)
        XLEShortField("network_address", 0xffff),
    ]


# Zigbee Device Profile #


class ZigbeeDeviceProfile(Packet):
    name = "Zigbee Device Profile (ZDP) Frame"
    fields_desc = [
        # Transaction Sequence Number (1 octet)
        ByteField("trans_seqnum", 0),  #NOTE called transaction_sequence in z3

        # TODO: Transaction Data (variable)
    ]

    def guess_payload_class(self, payload):
    	return Packet.guess_payload_class(self, payload)


# ZigBee Specification: Table 2.129
class ZDPRoutingTableListRecord(Packet):  # rename to RoutingDescriptor?
    name = "ZDP Routing Table List Record / Routing Descriptor"
    fields_desc = [
        # Destinatin Address (16 bits)
        dot15d4AddressField("route_dst_addr", 0, adjust=lambda pkt,x: 2),
        # Route Status (3 bits)
        BitEnumField("route_status", 0, 3, {
            0x0: "ACTIVE",
            0X1: "DISCOVERY_UNDERWAY",
            0X2: "DISCOVERY_FAILED",
            0X3: "INACTIVE",
            0X4: "VALIDATION_UNDERWAY",
            # 0x5 - 0x7 Reserved
        }),
        # Reserved (2 bits)
        BitField("reserved", 0 , 2),
        # Route record required (1 bit)
        BitField("route_record_required", 0, 1),
        # Many-to-one (1 bit)
        BitField("many_to_one", 0, 1),
        # Memory constrained (1 bit)
        BitField("memory_constrained", 0, 1),
        # Next-hop Address (16 bits)
        dot15d4AddressField("next_hop_addr", 0, adjust=lambda pkt,x: 2),
    ]

# ZigBee Specification: Table 2.131
class ZDPBindingTableListRecord(Packet):  # rename to BindingDescriptor?
    name = "ZDP Binding Table List Record / Binding Descriptor"
    fields_desc = [
        # Bind Source Address (8 octets)
        dot15d4AddressField("bind_src_addr", 0, adjust=lambda pkt,x: 8),
        # Bind Source Endpoint (1 octet)
        XByteField("bind_src_endpoint", 1),  # valid range: 0x01 - 0xfe
        # Bind Cluster id (2 octets)
        XLEShortField("bind_cluster", 0),
        # Destination Addr Mode (1 octet)
        #   0x00: reserved
        #   0x01: 16-bit group address for DstAddr and DstEndpoint not present
        #   0x02: reserved
        #   0x03: 64-bit extended address for DstAddr and DstEndp present
        #   0x04 - 0xff: reserved
        ByteField("bind_dst_addr_mode", 0x01),
        # Bind Destination Address (2/8 octets)
        dot15d4AddressField("bind_dst_addr", 0,
            adjust=lambda pkt,x:(8 if pkt.bind_dst_addr_mode == 0x03 else 2)),
        # Bind Destination Endpoint (0/1 octet)
        ConditionalField(
            XByteField("bind_dst_endpoint", 1),
            lambda pkt:(pkt.bind_dst_addr_mode == 0x03)),
    ]

# ZigBee Specification: Table 2.127
class ZDPNeighborTableListRecord(Packet):  # rename to NeighborDescriptor?
    name = "ZDP Neighbor Table List Record / Neighbor Descriptor"
    fields_desc = [
        # Neighbor extended PAN Id (8 octets)
        dot15d4AddressField("nb_ext_panid", 0, adjust=lambda pkt,x: 8),
        # Neighbor long Address (8 octets)
        dot15d4AddressField("nb_ext_addr", 0, adjust=lambda pkt,x: 8),
        # Neighbor short Address (2 octets)
        dot15d4AddressField("nb_addr", 0, adjust=lambda pkt,x: 2),
        # Reserved (1 bit)
        BitField("reserved_0", 0, 1),
        # Relationship (3 bits)
        BitEnumField("relationship", 0, 3, {
            0x0: "parent",
            0x1: "child",
            0x2: "sibling",
            0x3: "none",
            0x4: "previous_child",
        }),
        # Rx On When Idle (2 bits)
        BitEnumField("rx_on_when_idle", 1, 2, {
            0x0: "true",
            0x1: "false",
            0x2: "unknown",
        }),
        # Device Type (2 bits)
        BitEnumField("device_type", 0, 2, {
            0x0: "coordinator",
            0x1: "router",
            0x2: "end_device",
            0x3: "unknown",
        }),
        # Reserved (6 bits)
        BitField("reserved_1", 0, 6),
        # Permit Joining (2 bits)
        BitEnumField("permit_joining", 0, 2, {
            0x0: "true",
            0x1: "false",
            0x2: "unknown",
        }),
        # Depth (1 octet)
        ByteField("depth", 0),
        # LQI [Link Quality Indicator] (1 octet)
        ByteField("lqi", 0),
    ]

### ZDP Mgmt_Lqi_req Command (2.4.3.3.2) cluster 0x0031 ###
class ZDPLqiRequest(Packet):
    name = "Zigbee ZDP Mgmt_Lqi_req"
    fields_desc = [
        # sequence number (1 octet)
        ByteField("transaction_sequence", 0),
        # StartIndex (1 octet)
        ByteField("start_index", 0),
    ]
    def answers(self, other):
        if isinstance(other, ZDPLqiResponse):
            return (self.start_index == other.start_index \
                    and self.transaction_sequence == other.transaction_sequence)
        return 0

### ZDP Mgmt_Lqi_rsp Command (2.4.4.3.2) cluster 0x8031 ###
class ZDPLqiResponse(Packet):
    name = "Zigbee ZDP Mgmt_Lqi_rsp"
    fields_desc = [
        # sequence number (1 octet)
        ByteField("transaction_sequence", 0),
        # Status (1 octet)
        ByteEnumField("zdp_status", 0, _zdp_enumerated_stauts_values),
        # Neighbor Table Entries (1 octet)
        ByteField("neighbor_table_entries", 0, ),
        # StartIndex (1 octet)
        ByteField("start_index", 0),
        # Neighbor Table List Count (1 octet)
        FieldLenField("neighbor_table_list_count", None,
                count_of="neighbor_table_list", fmt="B"),
        # Neighbor Table List (22 octets * neighbor_table_list_count)
        PacketListField("neighbor_table_list", [], ZDPNeighborTableListRecord,
            count_from=lambda pkt:pkt.neighbor_table_list_count),
    ]


### ZDP Mgmt_Rtg_req Command (2.4.3.3.3) cluster 0x0032 ###
class ZDPRoutingTableRequest(Packet):
    name = "Zigbee ZDP Mgmt_Rtg_req"
    fields_desc = [
        # sequence number (1 octet)
        ByteField("transaction_sequence", 0),
        # StartIndex (1 octet)
        ByteField("start_index", 0),
    ]
    def answers(self, other):
        if isinstance(other, ZDPRoutingTableResponse):
            return (self.start_index == other.start_index \
                    and self.transaction_sequence == other.transaction_sequence)
        return 0

### Mgmt_Rtg_rsp Command (2.4.4.3.3) cluster 0x8032 ###
class ZDPRoutingTableResponse(Packet):
    name = "Zigbee ZDP Mgmt_Rtg_rsp"
    fields_desc = [
        # sequence number (1 octet)
        ByteField("transaction_sequence", 0),
        # Status (1 octet)
        ByteEnumField("zdp_status", 0, _zdp_enumerated_stauts_values),
        # Routing Table Entries (1 octet)
        ByteField("routing_table_entries", 0),
        # StartIndex (1 octet)
        ByteField("start_index", 0),
        # Routing Table List Count (1 octet)
        FieldLenField("routing_table_list_count", None,
            count_of="routing_table_list", fmt="B"),
        # Routing Table List (5 octets * routing_table_list_count)
        PacketListField("routing_table_list", [], ZDPRoutingTableListRecord,
            count_from=lambda pkt:pkt.routing_table_list_count),
    ]

### Mgmt_Bind_req (2.4.3.3.4) cluster 0x0033 ###
class ZDPBindingTableRequest(Packet):
    name = "Zigbee ZDP Mgmt_Bind_req"
    fields_desc = [
        # sequence number (1 octet)
        ByteField("transaction_sequence", 0),
        # StartIndex (1 octet)
        ByteField("start_index", 0),
    ]
    def answers(self, other):
        if isinstance(other, ZDPBindingTableResponse):
            return (self.start_index == other.start_index \
                    and self.transaction_sequence == other.transaction_sequence)
        return 0

### Mgmt_Bind_rsp (2.4.4.3.4) cluster 0x8033 ###
class ZDPBindingTableResponse(Packet):
    name = "Zigbee ZDP Mgmt_Bind_rsp"
    fields_desc = [
        # sequence number (1 octet)
        ByteField("transaction_sequence", 0),
        # Status (1 octet)
        ByteEnumField("zdp_status", 0, _zdp_enumerated_stauts_values),
        # Binding Table Entries (1 octet)
        ByteField("binding_table_entries", 0),
        # StartIndex (1 octet)
        ByteField("start_index", 0),
        # Binding Table List Count (1 octet)
        FieldLenField("binding_table_list_count", None,
            count_of="binding_table_list", fmt="B"),
        # Binding Table List (variable octets * binding_table_list_count)
        PacketListField("binding_table_list", [], ZDPBindingTableListRecord,
            count_from=lambda pkt:pkt.binding_table_list_count),
    ]

### Mgmt_Leave_req (2.4.3.3.5) cluster 0x0034 ###
class ZDPLeaveRequest(Packet):
    name = "Zigbee ZDP Mgmt_Leave_req"
    fields_desc = [
        # sequence number (1 octet)
        ByteField("transaction_sequence", 0),
        # Device Address (8 octets)
        dot15d4AddressField("device_addr", 0, adjust=lambda pkt,x: 8),
        # Rejoin (1 Bit)
        BitField("rejoin", 0, 1),
        # Remove Children (1 bit)
        BitField("remove_children", 0, 1),
        # Reserved (6 bits)
        BitField("reserved", 0, 6),
    ]
    def answers(self, other):
        if isinstance(other, ZDPLeaveRequest):
            return self.transaction_sequence == other.transaction_sequence
        return 0

### Mgmt_Leave_rsp (2.4.4.3.5) cluster 0x8034 ###
class ZDPLeaveResponse(Packet):
    name = "Zigbee ZDP Mgmt_Leave_rsp"
    fields_desc = [
        # sequence number (1 octet)
        ByteField("transaction_sequence", 0),
        # Status (1 octet)
        ByteEnumField("zdp_status", 0, _zdp_enumerated_stauts_values),
    ]




# ZigBee Cluster Library #


_ZCL_attr_length = {
    0x00: 0,  # no data
    0x08: 1,  # 8-bit data
    0x09: 2,  # 16-bit data
    0x0a: 3,  # 24-bit data
    0x0b: 4,  # 32-bit data
    0x0c: 5,  # 40-bit data
    0x0d: 6,  # 48-bit data
    0x0e: 7,  # 56-bit data
    0x0f: 8,  # 64-bit data
    0x10: 1,  # boolean
    0x18: 1,  # 8-bit bitmap
    0x19: 2,  # 16-bit bitmap
    0x1a: 3,  # 24-bit bitmap
    0x1b: 4,  # 32-bit bitmap
    0x1c: 5,  # 40-bit bitmap
    0x1d: 6,  # 48-bit bitmap
    0x1e: 7,  # 46-bit bitmap
    0x1f: 8,  # 64-bit bitmap
    0x20: 1,  # Unsigned 8-bit integer
    0x21: 2,  # Unsigned 16-bit integer
    0x22: 3,  # Unsigned 24-bit integer
    0x23: 4,  # Unsigned 32-bit integer
    0x24: 5,  # Unsigned 40-bit integer
    0x25: 6,  # Unsigned 48-bit integer
    0x26: 7,  # Unsigned 56-bit integer
    0x27: 8,  # Unsigned 64-bit integer
    0x28: 1,  # Signed 8-bit integer
    0x29: 2,  # Signed 16-bit integer
    0x2a: 3,  # Signed 24-bit integer
    0x2b: 4,  # Signed 32-bit integer
    0x2c: 5,  # Signed 40-bit integer
    0x2d: 6,  # Signed 48-bit integer
    0x2e: 7,  # Signed 56-bit integer
    0x2f: 8,  # Signed 64-bit integer
    0x30: 1,  # 8-bit enumeration
    0x31: 2,  # 16-bit enumeration
    0x38: 2,  # Semi-precision
    0x39: 4,  # Single precision
    0x3a: 8,  # Double precision
    0x41: (1, "!B"),  # Octet string
    0x42: (1, "!B"),  # Character string
    0x43: (2, "!H"),  # Long octet string
    0x44: (2, "!H"),  # Long character string
    # TODO (implement Ordered sequence & collection
    0xe0: 4,  # Time of day
    0xe1: 4,  # Date
    0xe2: 4,  # UTCTime
    0xe8: 2,  # Cluster ID
    0xe9: 2,  # Attribute ID
    0xea: 4,  # BACnet OID
    0xf0: 8,  # IEEE address
    0xf1: 16,  # 128-bit security key
    0xff: 0,  # Unknown
}


class _DiscreteString(StrLenField):
    def getfield(self, pkt, s):
        dtype = pkt.attribute_data_type
        length = _ZCL_attr_length.get(dtype, None)
        if length is None:
            return b"", self.m2i(pkt, s)
        elif isinstance(length, tuple):  # Variable length
            size, fmt = length
            # We add size as we include the length tag in the string
            length = struct.unpack(fmt, s[:size])[0] + size
        if isinstance(length, int):
            self.length_from = lambda x: length
            return StrLenField.getfield(self, pkt, s)
        return s


class ZCLReadAttributeStatusRecord(Packet):
    name = "ZCL Read Attribute Status Record"
    fields_desc = [
        # Attribute Identifier
        XLEShortField("attribute_identifier", 0),
        # Status
        ByteEnumField("status", 0, _zcl_enumerated_status_values),
        # Attribute data type (0/1 octet), and data (0/variable size)
        # are only included if status == 0x00 (SUCCESS)
        ConditionalField(
            ByteEnumField("attribute_data_type", 0, _zcl_attribute_data_types),
            lambda pkt:pkt.status == 0x00
        ),
        ConditionalField(
            _DiscreteString("attribute_value", ""),
            lambda pkt:pkt.status == 0x00
        ),
    ]

    def extract_padding(self, s):
        return "", s


class ZCLGeneralReadAttributes(Packet):
    name = "General Domain: Command Frame Payload: read_attributes"
    fields_desc = [
        FieldListField("attribute_identifiers", [], XLEShortField("", 0x0000)),
    ]


class ZCLGeneralReadAttributesResponse(Packet):
    name = "General Domain: Command Frame Payload: read_attributes_response"
    fields_desc = [
        PacketListField("read_attribute_status_record", [], ZCLReadAttributeStatusRecord),  # noqa: E501
    ]


class ZCLMeteringGetProfile(Packet):
    name = "Metering Cluster: Get Profile Command (Server: Received)"
    fields_desc = [
        # Interval Channel (8-bit Enumeration): 1 octet
        ByteField("Interval_Channel", 0),  # 0 == Consumption Delivered ; 1 == Consumption Received  # noqa: E501
        # End Time (UTCTime): 4 octets
        XLEIntField("End_Time", 0x00000000),
        # NumberOfPeriods (Unsigned 8-bit Integer): 1 octet
        ByteField("NumberOfPeriods", 1),  # Represents the number of intervals being requested.  # noqa: E501
    ]


class ZCLPriceGetCurrentPrice(Packet):
    name = "Price Cluster: Get Current Price Command (Server: Received)"
    fields_desc = [
        BitField("reserved", 0, 7),
        BitField("Requestor_Rx_On_When_Idle", 0, 1),
    ]


class ZCLPriceGetScheduledPrices(Packet):
    name = "Price Cluster: Get Scheduled Prices Command (Server: Received)"
    fields_desc = [
        XLEIntField("start_time", 0x00000000),  # UTCTime (4 octets)
        ByteField("number_of_events", 0),  # Number of Events (1 octet)
    ]


class ZCLPricePublishPrice(Packet):
    name = "Price Cluster: Publish Price Command (Server: Generated)"
    fields_desc = [
        XLEIntField("provider_id", 0x00000000),  # Unsigned 32-bit Integer (4 octets)  # noqa: E501
        # Rate Label is a UTF-8 encoded Octet String (0-12 octets). The first Octet indicates the length.  # noqa: E501
        StrLenField("rate_label", "", length_from=lambda pkt:int(pkt.rate_label[0])),  # TODO verify  # noqa: E501
        XLEIntField("issuer_event_id", 0x00000000),  # Unsigned 32-bit Integer (4 octets)  # noqa: E501
        XLEIntField("current_time", 0x00000000),  # UTCTime (4 octets)
        ByteField("unit_of_measure", 0),  # 8 bits enumeration (1 octet)
        XLEShortField("currency", 0x0000),  # Unsigned 16-bit Integer (2 octets)  # noqa: E501
        ByteField("price_trailing_digit", 0),  # 8-bit BitMap (1 octet)
        ByteField("number_of_price_tiers", 0),  # 8-bit BitMap (1 octet)
        XLEIntField("start_time", 0x00000000),  # UTCTime (4 octets)
        XLEShortField("duration_in_minutes", 0x0000),  # Unsigned 16-bit Integer (2 octets)  # noqa: E501
        XLEIntField("price", 0x00000000),  # Unsigned 32-bit Integer (4 octets)
        ByteField("price_ratio", 0),  # Unsigned 8-bit Integer (1 octet)
        XLEIntField("generation_price", 0x00000000),  # Unsigned 32-bit Integer (4 octets)  # noqa: E501
        ByteField("generation_price_ratio", 0),  # Unsigned 8-bit Integer (1 octet)  # noqa: E501
        XLEIntField("alternate_cost_delivered", 0x00000000),  # Unsigned 32-bit Integer (4 octets)  # noqa: E501
        ByteField("alternate_cost_unit", 0),  # 8-bit enumeration (1 octet)
        ByteField("alternate_cost_trailing_digit", 0),  # 8-bit BitMap (1 octet)  # noqa: E501
        ByteField("number_of_block_thresholds", 0),  # 8-bit BitMap (1 octet)
        ByteField("price_control", 0),  # 8-bit BitMap (1 octet)
    ]


class ZigbeeClusterLibrary(Packet):
    name = "Zigbee Cluster Library (ZCL) Frame"
    deprecated_fields = {
        "direction": ("command_direction", "2.5.0"),
    }
    fields_desc = [
        # Frame control (8 bits)
        BitField("reserved", 0, 3),
        BitField("disable_default_response", 0, 1),  # 0 default response command will be returned  # noqa: E501
        BitField("command_direction", 0, 1),  # 0 command sent from client to server; 1 command sent from server to client  # noqa: E501
        BitField("manufacturer_specific", 0, 1),  # 0 manufacturer code shall not be included in the ZCL frame  # noqa: E501
        # Frame Type
        # 0b00 command acts across the entire profile
        # 0b01 command is specific to a cluster
        # 0b10 - 0b11 reserved
        BitEnumField("zcl_frametype", 0, 2, {0: 'profile-wide', 1: 'cluster-specific', 2: 'reserved2', 3: 'reserved3'}),  # noqa: E501
        # Manufacturer code (0/16 bits) only present then manufacturer_specific field is set to 1  # noqa: E501
        ConditionalField(XLEShortField("manufacturer_code", 0x0),
                         lambda pkt: pkt.getfieldval("manufacturer_specific") == 1  # noqa: E501
                         ),
        # Transaction sequence number (8 bits)
        ByteField("transaction_sequence", 0),
        # Command identifier (8 bits): the cluster command
        ByteEnumField("command_identifier", 0, _zcl_command_frames),
    ]

    def guess_payload_class(self, payload):
        # Profile-wide commands
        if self.zcl_frametype == 0x00 and self.command_identifier == 0x00:
            # done in bind_layers
            pass
        # Cluster-specific commands
        elif self.zcl_frametype == 0x01 and self.command_identifier == 0x00 and self.command_direction == 0 and self.underlayer.cluster == 0x0700:  # "price"  # noqa: E501
            return ZCLPriceGetCurrentPrice
        elif self.zcl_frametype == 0x01 and self.command_identifier == 0x01 and self.command_direction == 0 and self.underlayer.cluster == 0x0700:  # "price"  # noqa: E501
            return ZCLPriceGetScheduledPrices
        elif self.zcl_frametype == 0x01 and self.command_identifier == 0x00 and self.command_direction == 1 and self.underlayer.cluster == 0x0700:  # "price"  # noqa: E501
            return ZCLPricePublishPrice
        return Packet.guess_payload_class(self, payload)


bind_layers(ZigbeeClusterLibrary, ZCLGeneralReadAttributes,
            zcl_frametype=0x00, command_identifier=0x00)
bind_layers(ZigbeeClusterLibrary, ZCLGeneralReadAttributesResponse,
            zcl_frametype=0x00, command_identifier=0x01)

# Zigbee Encapsulation Protocol


class ZEP2(Packet):
    name = "Zigbee Encapsulation Protocol (V2)"
    fields_desc = [
        StrFixedLenField("preamble", "EX", length=2),
        ByteField("ver", 0),
        ByteField("type", 0),
        ByteField("channel", 0),
        ShortField("device", 0),
        ByteField("lqi_mode", 1),
        ByteField("lqi_val", 0),
        TimeStampField("timestamp", 0),
        IntField("seq", 0),
        BitField("res", 0, 80),  # 10 bytes reserved field
        ByteField("length", 0),
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=b"", *args, **kargs):
        if _pkt and len(_pkt) >= 4:
            v = orb(_pkt[2])
            if v == 1:
                return ZEP1
            elif v == 2:
                return ZEP2
        return cls

    def guess_payload_class(self, payload):
        if self.lqi_mode:
            return Dot15d4
        else:
            return Dot15d4FCS


class ZEP1(ZEP2):
    name = "Zigbee Encapsulation Protocol (V1)"
    fields_desc = [
        StrFixedLenField("preamble", "EX", length=2),
        ByteField("ver", 0),
        ByteField("channel", 0),
        ShortField("device", 0),
        ByteField("lqi_mode", 0),
        ByteField("lqi_val", 0),
        BitField("res", 0, 56),  # 7 bytes reserved field
        ByteField("len", 0),
    ]


# Bindings #

# TODO: find a way to chose between ZigbeeNWK and SixLoWPAN (cf. sixlowpan.py)
# Currently: use conf.dot15d4_protocol value
# bind_layers( Dot15d4Data, ZigbeeNWK)

bind_layers(ZigbeeAppDataPayload, ZigbeeAppCommandPayload, frametype=1)
bind_layers(Dot15d4Beacon, ZigBeeBeacon)

# ZLL (Touchlink):
bind_layers( ZigbeeAppDataPayloadStub, ZigbeeZLLCommissioningCluster, profile=0xc05e, cluster=0x1000)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLScanRequest, command_identifier=0x00, direction=0)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLScanResponse, command_identifier=0x01, direction=1)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLDeviceInformationRequest, command_identifier=0x03, direction=0)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLIdentifyRequest, command_identifier=0x06, direction=0)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLResetToFactoryNewRequest, command_identifier=0x07, direction=0)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLNetworkStartRequest, command_identifier=0x10, direction=0)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLNetworkStartResponse, command_identifier=0x11, direction=1)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLNetworkJoinRouterRequest, command_identifier=0x12, direction=0)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLNetworkJoinRouterResponse, command_identifier=0x13, direction=1)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLNetworkUpdateRequest, command_identifier=0x16, direction=0)

bind_bottom_up(UDP, ZEP2, sport=17754)
bind_bottom_up(UDP, ZEP2, sport=17754)
bind_layers(UDP, ZEP2, sport=17754, dport=17754)
