# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: frameworks/proto_logging/stats/enums/stats/connectivity/network_stack.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\nKframeworks/proto_logging/stats/enums/stats/connectivity/network_stack.proto\x12\x1a\x61ndroid.stats.connectivity\"\x17\n\x15NetworkStackEventData*u\n\x0f\x44hcpRenewResult\x12\x0e\n\nRR_UNKNOWN\x10\x00\x12\x0e\n\nRR_SUCCESS\x10\x01\x12\x10\n\x0cRR_ERROR_NAK\x10\x02\x12\x18\n\x14RR_ERROR_IP_MISMATCH\x10\x03\x12\x16\n\x12RR_ERROR_IP_EXPIRE\x10\x04*\x8d\x02\n\x0e\x44isconnectCode\x12\x0b\n\x07\x44\x43_NONE\x10\x00\x12\x19\n\x15\x44\x43_NORMAL_TERMINATION\x10\x01\x12\x18\n\x14\x44\x43_PROVISIONING_FAIL\x10\x02\x12\x1a\n\x16\x44\x43_ERROR_STARTING_IPV4\x10\x04\x12\x1a\n\x16\x44\x43_ERROR_STARTING_IPV6\x10\x05\x12+\n\'DC_ERROR_STARTING_IPREACHABILITYMONITOR\x10\x06\x12\x1b\n\x17\x44\x43_INVALID_PROVISIONING\x10\x07\x12\x1a\n\x16\x44\x43_INTERFACE_NOT_FOUND\x10\x08\x12\x1b\n\x17\x44\x43_PROVISIONING_TIMEOUT\x10\t*\xfa\x01\n\rTransportType\x12\x0e\n\nTT_UNKNOWN\x10\x00\x12\x0f\n\x0bTT_CELLULAR\x10\x01\x12\x0b\n\x07TT_WIFI\x10\x02\x12\x10\n\x0cTT_BLUETOOTH\x10\x03\x12\x0f\n\x0bTT_ETHERNET\x10\x04\x12\x11\n\rTT_WIFI_AWARE\x10\x05\x12\r\n\tTT_LOWPAN\x10\x06\x12\x13\n\x0fTT_CELLULAR_VPN\x10\x07\x12\x0f\n\x0bTT_WIFI_VPN\x10\x08\x12\x14\n\x10TT_BLUETOOTH_VPN\x10\t\x12\x13\n\x0fTT_ETHERNET_VPN\x10\n\x12\x18\n\x14TT_WIFI_CELLULAR_VPN\x10\x0b\x12\x0b\n\x07TT_TEST\x10\x0c*]\n\x0b\x44hcpFeature\x12\x0e\n\nDF_UNKNOWN\x10\x00\x12\x11\n\rDF_INITREBOOT\x10\x01\x12\x12\n\x0e\x44\x46_RAPIDCOMMIT\x10\x02\x12\n\n\x06\x44\x46_DAD\x10\x03\x12\x0b\n\x07\x44\x46_FILS\x10\x04*Y\n\x13HostnameTransResult\x12\x0f\n\x0bHTR_UNKNOWN\x10\x00\x12\x0f\n\x0bHTR_SUCCESS\x10\x01\x12\x0f\n\x0bHTR_FAILURE\x10\x02\x12\x0f\n\x0bHTR_DISABLE\x10\x03*c\n\x0bProbeResult\x12\x0e\n\nPR_UNKNOWN\x10\x00\x12\x0e\n\nPR_SUCCESS\x10\x01\x12\x0e\n\nPR_FAILURE\x10\x02\x12\r\n\tPR_PORTAL\x10\x03\x12\x15\n\x11PR_PRIVATE_IP_DNS\x10\x04*a\n\x10ValidationResult\x12\x0e\n\nVR_UNKNOWN\x10\x00\x12\x0e\n\nVR_SUCCESS\x10\x01\x12\x0e\n\nVR_FAILURE\x10\x02\x12\r\n\tVR_PORTAL\x10\x03\x12\x0e\n\nVR_PARTIAL\x10\x04*\x83\x01\n\tProbeType\x12\x0e\n\nPT_UNKNOWN\x10\x00\x12\n\n\x06PT_DNS\x10\x01\x12\x0b\n\x07PT_HTTP\x10\x02\x12\x0c\n\x08PT_HTTPS\x10\x03\x12\n\n\x06PT_PAC\x10\x04\x12\x0f\n\x0bPT_FALLBACK\x10\x05\x12\x0e\n\nPT_PRIVDNS\x10\x06\x12\x12\n\x0ePT_CAPPORT_API\x10\x07*\xab\x04\n\rDhcpErrorCode\x12\x0e\n\nET_UNKNOWN\x10\x00\x12\x0f\n\x0b\x45T_L2_ERROR\x10\x01\x12\x0f\n\x0b\x45T_L3_ERROR\x10\x02\x12\x0f\n\x0b\x45T_L4_ERROR\x10\x03\x12\x11\n\rET_DHCP_ERROR\x10\x04\x12\x11\n\rET_MISC_ERROR\x10\x05\x12\x16\n\x0f\x45T_L2_TOO_SHORT\x10\x80\x80\x84\x08\x12\x1b\n\x14\x45T_L2_WRONG_ETH_TYPE\x10\x80\x80\x88\x08\x12\x16\n\x0f\x45T_L3_TOO_SHORT\x10\x80\x80\x84\x10\x12\x15\n\x0e\x45T_L3_NOT_IPV4\x10\x80\x80\x88\x10\x12\x17\n\x10\x45T_L3_INVALID_IP\x10\x80\x80\x8c\x10\x12\x14\n\rET_L4_NOT_UDP\x10\x80\x80\x84\x18\x12\x17\n\x10\x45T_L4_WRONG_PORT\x10\x80\x80\x88\x18\x12\x19\n\x12\x45T_BOOTP_TOO_SHORT\x10\x80\x80\x84 \x12\x1f\n\x18\x45T_DHCP_BAD_MAGIC_COOKIE\x10\x80\x80\x88 \x12$\n\x1d\x45T_DHCP_INVALID_OPTION_LENGTH\x10\x80\x80\x8c \x12\x1a\n\x13\x45T_DHCP_NO_MSG_TYPE\x10\x80\x80\x90 \x12\x1f\n\x18\x45T_DHCP_UNKNOWN_MSG_TYPE\x10\x80\x80\x94 \x12\x18\n\x11\x45T_DHCP_NO_COOKIE\x10\x80\x80\x98 \x12\x1a\n\x13\x45T_BUFFER_UNDERFLOW\x10\x80\x80\x84(\x12\x17\n\x10\x45T_RECEIVE_ERROR\x10\x80\x80\x88(\x12\x17\n\x10\x45T_PARSING_ERROR\x10\x80\x80\x8c(*I\n\x11NetworkQuirkEvent\x12\x0e\n\nQE_UNKNOWN\x10\x00\x12$\n QE_IPV6_PROVISIONING_ROUTER_LOST\x10\x01*)\n\x06IpType\x12\x0b\n\x07UNKNOWN\x10\x00\x12\x08\n\x04IPV4\x10\x04\x12\x08\n\x04IPV6\x10\x06*\xf7\x01\n\x0cNudEventType\x12\x15\n\x11NUD_EVENT_UNKNOWN\x10\x00\x12\x1b\n\x17NUD_POST_ROAMING_FAILED\x10\x01\x12$\n NUD_POST_ROAMING_FAILED_CRITICAL\x10\x02\x12\x16\n\x12NUD_CONFIRM_FAILED\x10\x03\x12\x1f\n\x1bNUD_CONFIRM_FAILED_CRITICAL\x10\x04\x12\x16\n\x12NUD_ORGANIC_FAILED\x10\x05\x12\x1f\n\x1bNUD_ORGANIC_FAILED_CRITICAL\x10\x06\x12\x1b\n\x17NUD_MAC_ADDRESS_CHANGED\x10\x07*r\n\x0fNudNeighborType\x12\x18\n\x14NUD_NEIGHBOR_UNKNOWN\x10\x00\x12\x18\n\x14NUD_NEIGHBOR_GATEWAY\x10\x01\x12\x14\n\x10NUD_NEIGHBOR_DNS\x10\x02\x12\x15\n\x11NUD_NEIGHBOR_BOTH\x10\x03\x42\x15\x42\x11NetworkStackProtoP\x01')

_DHCPRENEWRESULT = DESCRIPTOR.enum_types_by_name['DhcpRenewResult']
DhcpRenewResult = enum_type_wrapper.EnumTypeWrapper(_DHCPRENEWRESULT)
_DISCONNECTCODE = DESCRIPTOR.enum_types_by_name['DisconnectCode']
DisconnectCode = enum_type_wrapper.EnumTypeWrapper(_DISCONNECTCODE)
_TRANSPORTTYPE = DESCRIPTOR.enum_types_by_name['TransportType']
TransportType = enum_type_wrapper.EnumTypeWrapper(_TRANSPORTTYPE)
_DHCPFEATURE = DESCRIPTOR.enum_types_by_name['DhcpFeature']
DhcpFeature = enum_type_wrapper.EnumTypeWrapper(_DHCPFEATURE)
_HOSTNAMETRANSRESULT = DESCRIPTOR.enum_types_by_name['HostnameTransResult']
HostnameTransResult = enum_type_wrapper.EnumTypeWrapper(_HOSTNAMETRANSRESULT)
_PROBERESULT = DESCRIPTOR.enum_types_by_name['ProbeResult']
ProbeResult = enum_type_wrapper.EnumTypeWrapper(_PROBERESULT)
_VALIDATIONRESULT = DESCRIPTOR.enum_types_by_name['ValidationResult']
ValidationResult = enum_type_wrapper.EnumTypeWrapper(_VALIDATIONRESULT)
_PROBETYPE = DESCRIPTOR.enum_types_by_name['ProbeType']
ProbeType = enum_type_wrapper.EnumTypeWrapper(_PROBETYPE)
_DHCPERRORCODE = DESCRIPTOR.enum_types_by_name['DhcpErrorCode']
DhcpErrorCode = enum_type_wrapper.EnumTypeWrapper(_DHCPERRORCODE)
_NETWORKQUIRKEVENT = DESCRIPTOR.enum_types_by_name['NetworkQuirkEvent']
NetworkQuirkEvent = enum_type_wrapper.EnumTypeWrapper(_NETWORKQUIRKEVENT)
_IPTYPE = DESCRIPTOR.enum_types_by_name['IpType']
IpType = enum_type_wrapper.EnumTypeWrapper(_IPTYPE)
_NUDEVENTTYPE = DESCRIPTOR.enum_types_by_name['NudEventType']
NudEventType = enum_type_wrapper.EnumTypeWrapper(_NUDEVENTTYPE)
_NUDNEIGHBORTYPE = DESCRIPTOR.enum_types_by_name['NudNeighborType']
NudNeighborType = enum_type_wrapper.EnumTypeWrapper(_NUDNEIGHBORTYPE)
RR_UNKNOWN = 0
RR_SUCCESS = 1
RR_ERROR_NAK = 2
RR_ERROR_IP_MISMATCH = 3
RR_ERROR_IP_EXPIRE = 4
DC_NONE = 0
DC_NORMAL_TERMINATION = 1
DC_PROVISIONING_FAIL = 2
DC_ERROR_STARTING_IPV4 = 4
DC_ERROR_STARTING_IPV6 = 5
DC_ERROR_STARTING_IPREACHABILITYMONITOR = 6
DC_INVALID_PROVISIONING = 7
DC_INTERFACE_NOT_FOUND = 8
DC_PROVISIONING_TIMEOUT = 9
TT_UNKNOWN = 0
TT_CELLULAR = 1
TT_WIFI = 2
TT_BLUETOOTH = 3
TT_ETHERNET = 4
TT_WIFI_AWARE = 5
TT_LOWPAN = 6
TT_CELLULAR_VPN = 7
TT_WIFI_VPN = 8
TT_BLUETOOTH_VPN = 9
TT_ETHERNET_VPN = 10
TT_WIFI_CELLULAR_VPN = 11
TT_TEST = 12
DF_UNKNOWN = 0
DF_INITREBOOT = 1
DF_RAPIDCOMMIT = 2
DF_DAD = 3
DF_FILS = 4
HTR_UNKNOWN = 0
HTR_SUCCESS = 1
HTR_FAILURE = 2
HTR_DISABLE = 3
PR_UNKNOWN = 0
PR_SUCCESS = 1
PR_FAILURE = 2
PR_PORTAL = 3
PR_PRIVATE_IP_DNS = 4
VR_UNKNOWN = 0
VR_SUCCESS = 1
VR_FAILURE = 2
VR_PORTAL = 3
VR_PARTIAL = 4
PT_UNKNOWN = 0
PT_DNS = 1
PT_HTTP = 2
PT_HTTPS = 3
PT_PAC = 4
PT_FALLBACK = 5
PT_PRIVDNS = 6
PT_CAPPORT_API = 7
ET_UNKNOWN = 0
ET_L2_ERROR = 1
ET_L3_ERROR = 2
ET_L4_ERROR = 3
ET_DHCP_ERROR = 4
ET_MISC_ERROR = 5
ET_L2_TOO_SHORT = 16842752
ET_L2_WRONG_ETH_TYPE = 16908288
ET_L3_TOO_SHORT = 33619968
ET_L3_NOT_IPV4 = 33685504
ET_L3_INVALID_IP = 33751040
ET_L4_NOT_UDP = 50397184
ET_L4_WRONG_PORT = 50462720
ET_BOOTP_TOO_SHORT = 67174400
ET_DHCP_BAD_MAGIC_COOKIE = 67239936
ET_DHCP_INVALID_OPTION_LENGTH = 67305472
ET_DHCP_NO_MSG_TYPE = 67371008
ET_DHCP_UNKNOWN_MSG_TYPE = 67436544
ET_DHCP_NO_COOKIE = 67502080
ET_BUFFER_UNDERFLOW = 83951616
ET_RECEIVE_ERROR = 84017152
ET_PARSING_ERROR = 84082688
QE_UNKNOWN = 0
QE_IPV6_PROVISIONING_ROUTER_LOST = 1
UNKNOWN = 0
IPV4 = 4
IPV6 = 6
NUD_EVENT_UNKNOWN = 0
NUD_POST_ROAMING_FAILED = 1
NUD_POST_ROAMING_FAILED_CRITICAL = 2
NUD_CONFIRM_FAILED = 3
NUD_CONFIRM_FAILED_CRITICAL = 4
NUD_ORGANIC_FAILED = 5
NUD_ORGANIC_FAILED_CRITICAL = 6
NUD_MAC_ADDRESS_CHANGED = 7
NUD_NEIGHBOR_UNKNOWN = 0
NUD_NEIGHBOR_GATEWAY = 1
NUD_NEIGHBOR_DNS = 2
NUD_NEIGHBOR_BOTH = 3


_NETWORKSTACKEVENTDATA = DESCRIPTOR.message_types_by_name['NetworkStackEventData']
NetworkStackEventData = _reflection.GeneratedProtocolMessageType('NetworkStackEventData', (_message.Message,), {
  'DESCRIPTOR' : _NETWORKSTACKEVENTDATA,
  '__module__' : 'frameworks.proto_logging.stats.enums.stats.connectivity.network_stack_pb2'
  # @@protoc_insertion_point(class_scope:android.stats.connectivity.NetworkStackEventData)
  })
_sym_db.RegisterMessage(NetworkStackEventData)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'B\021NetworkStackProtoP\001'
  _DHCPRENEWRESULT._serialized_start=132
  _DHCPRENEWRESULT._serialized_end=249
  _DISCONNECTCODE._serialized_start=252
  _DISCONNECTCODE._serialized_end=521
  _TRANSPORTTYPE._serialized_start=524
  _TRANSPORTTYPE._serialized_end=774
  _DHCPFEATURE._serialized_start=776
  _DHCPFEATURE._serialized_end=869
  _HOSTNAMETRANSRESULT._serialized_start=871
  _HOSTNAMETRANSRESULT._serialized_end=960
  _PROBERESULT._serialized_start=962
  _PROBERESULT._serialized_end=1061
  _VALIDATIONRESULT._serialized_start=1063
  _VALIDATIONRESULT._serialized_end=1160
  _PROBETYPE._serialized_start=1163
  _PROBETYPE._serialized_end=1294
  _DHCPERRORCODE._serialized_start=1297
  _DHCPERRORCODE._serialized_end=1852
  _NETWORKQUIRKEVENT._serialized_start=1854
  _NETWORKQUIRKEVENT._serialized_end=1927
  _IPTYPE._serialized_start=1929
  _IPTYPE._serialized_end=1970
  _NUDEVENTTYPE._serialized_start=1973
  _NUDEVENTTYPE._serialized_end=2220
  _NUDNEIGHBORTYPE._serialized_start=2222
  _NUDNEIGHBORTYPE._serialized_end=2336
  _NETWORKSTACKEVENTDATA._serialized_start=107
  _NETWORKSTACKEVENTDATA._serialized_end=130
# @@protoc_insertion_point(module_scope)
