# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: frameworks/proto_logging/stats/enums/stats/hdmi/enums.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n;frameworks/proto_logging/stats/enums/stats/hdmi/enums.proto\x12\x12\x61ndroid.stats.hdmi*\xe2\x02\n\x0eLogicalAddress\x12$\n\x17LOGICAL_ADDRESS_UNKNOWN\x10\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01\x12\x06\n\x02TV\x10\x00\x12\x16\n\x12RECORDING_DEVICE_1\x10\x01\x12\x16\n\x12RECORDING_DEVICE_2\x10\x02\x12\x0b\n\x07TUNER_1\x10\x03\x12\x15\n\x11PLAYBACK_DEVICE_1\x10\x04\x12\x10\n\x0c\x41UDIO_SYSTEM\x10\x05\x12\x0b\n\x07TUNER_2\x10\x06\x12\x0b\n\x07TUNER_3\x10\x07\x12\x15\n\x11PLAYBACK_DEVICE_2\x10\x08\x12\x16\n\x12RECORDING_DEVICE_3\x10\t\x12\x0b\n\x07TUNER_4\x10\n\x12\x15\n\x11PLAYBACK_DEVICE_3\x10\x0b\x12\x0e\n\nRESERVED_1\x10\x0c\x12\x0e\n\nRESERVED_2\x10\r\x12\x10\n\x0cSPECIFIC_USE\x10\x0e\x12\x1d\n\x19UNREGISTERED_OR_BROADCAST\x10\x0f*\x88\x01\n\x10PathRelationship\x12)\n%RELATIONSHIP_TO_ACTIVE_SOURCE_UNKNOWN\x10\x00\x12\x14\n\x10\x44IFFERENT_BRANCH\x10\x01\x12\x0c\n\x08\x41NCESTOR\x10\x02\x12\x0e\n\nDESCENDANT\x10\x03\x12\x0b\n\x07SIBLING\x10\x04\x12\x08\n\x04SAME\x10\x05*_\n\x11SendMessageResult\x12\x1f\n\x1bSEND_MESSAGE_RESULT_UNKNOWN\x10\x00\x12\x0b\n\x07SUCCESS\x10\n\x12\x08\n\x04NACK\x10\x0b\x12\x08\n\x04\x42USY\x10\x0c\x12\x08\n\x04\x46\x41IL\x10\r*w\n\x10MessageDirection\x12\x1d\n\x19MESSAGE_DIRECTION_UNKNOWN\x10\x00\x12\x1b\n\x17MESSAGE_DIRECTION_OTHER\x10\x01\x12\x0c\n\x08OUTGOING\x10\x02\x12\x0c\n\x08INCOMING\x10\x03\x12\x0b\n\x07TO_SELF\x10\x04*\xec\x02\n\x19UserControlPressedCommand\x12(\n$USER_CONTROL_PRESSED_COMMAND_UNKNOWN\x10\x00\x12&\n\"USER_CONTROL_PRESSED_COMMAND_OTHER\x10\x01\x12\n\n\x06NUMBER\x10\x02\x12\x0b\n\x06SELECT\x10\x80\x02\x12\x07\n\x02UP\x10\x81\x02\x12\t\n\x04\x44OWN\x10\x82\x02\x12\t\n\x04LEFT\x10\x83\x02\x12\n\n\x05RIGHT\x10\x84\x02\x12\r\n\x08RIGHT_UP\x10\x85\x02\x12\x0f\n\nRIGHT_DOWN\x10\x86\x02\x12\x0c\n\x07LEFT_UP\x10\x87\x02\x12\x0e\n\tLEFT_DOWN\x10\x88\x02\x12\t\n\x04\x45XIT\x10\x8d\x02\x12\x0e\n\tVOLUME_UP\x10\xc1\x02\x12\x10\n\x0bVOLUME_DOWN\x10\xc2\x02\x12\x10\n\x0bVOLUME_MUTE\x10\xc3\x02\x12\n\n\x05POWER\x10\xc0\x02\x12\x11\n\x0cPOWER_TOGGLE\x10\xeb\x02\x12\x0e\n\tPOWER_OFF\x10\xec\x02\x12\r\n\x08POWER_ON\x10\xed\x02*\xc9\x01\n\x12\x46\x65\x61tureAbortReason\x12 \n\x1c\x46\x45\x41TURE_ABORT_REASON_UNKNOWN\x10\x00\x12\x17\n\x13UNRECOGNIZED_OPCODE\x10\n\x12\"\n\x1eNOT_IN_CORRECT_MODE_TO_RESPOND\x10\x0b\x12\x19\n\x15\x43\x41NNOT_PROVIDE_SOURCE\x10\x0c\x12\x13\n\x0fINVALID_OPERAND\x10\r\x12\x0b\n\x07REFUSED\x10\x0e\x12\x17\n\x13UNABLE_TO_DETERMINE\x10\x0f\x42\x12\x42\x0eHdmiStatsEnumsP\x01')

_LOGICALADDRESS = DESCRIPTOR.enum_types_by_name['LogicalAddress']
LogicalAddress = enum_type_wrapper.EnumTypeWrapper(_LOGICALADDRESS)
_PATHRELATIONSHIP = DESCRIPTOR.enum_types_by_name['PathRelationship']
PathRelationship = enum_type_wrapper.EnumTypeWrapper(_PATHRELATIONSHIP)
_SENDMESSAGERESULT = DESCRIPTOR.enum_types_by_name['SendMessageResult']
SendMessageResult = enum_type_wrapper.EnumTypeWrapper(_SENDMESSAGERESULT)
_MESSAGEDIRECTION = DESCRIPTOR.enum_types_by_name['MessageDirection']
MessageDirection = enum_type_wrapper.EnumTypeWrapper(_MESSAGEDIRECTION)
_USERCONTROLPRESSEDCOMMAND = DESCRIPTOR.enum_types_by_name['UserControlPressedCommand']
UserControlPressedCommand = enum_type_wrapper.EnumTypeWrapper(_USERCONTROLPRESSEDCOMMAND)
_FEATUREABORTREASON = DESCRIPTOR.enum_types_by_name['FeatureAbortReason']
FeatureAbortReason = enum_type_wrapper.EnumTypeWrapper(_FEATUREABORTREASON)
LOGICAL_ADDRESS_UNKNOWN = -1
TV = 0
RECORDING_DEVICE_1 = 1
RECORDING_DEVICE_2 = 2
TUNER_1 = 3
PLAYBACK_DEVICE_1 = 4
AUDIO_SYSTEM = 5
TUNER_2 = 6
TUNER_3 = 7
PLAYBACK_DEVICE_2 = 8
RECORDING_DEVICE_3 = 9
TUNER_4 = 10
PLAYBACK_DEVICE_3 = 11
RESERVED_1 = 12
RESERVED_2 = 13
SPECIFIC_USE = 14
UNREGISTERED_OR_BROADCAST = 15
RELATIONSHIP_TO_ACTIVE_SOURCE_UNKNOWN = 0
DIFFERENT_BRANCH = 1
ANCESTOR = 2
DESCENDANT = 3
SIBLING = 4
SAME = 5
SEND_MESSAGE_RESULT_UNKNOWN = 0
SUCCESS = 10
NACK = 11
BUSY = 12
FAIL = 13
MESSAGE_DIRECTION_UNKNOWN = 0
MESSAGE_DIRECTION_OTHER = 1
OUTGOING = 2
INCOMING = 3
TO_SELF = 4
USER_CONTROL_PRESSED_COMMAND_UNKNOWN = 0
USER_CONTROL_PRESSED_COMMAND_OTHER = 1
NUMBER = 2
SELECT = 256
UP = 257
DOWN = 258
LEFT = 259
RIGHT = 260
RIGHT_UP = 261
RIGHT_DOWN = 262
LEFT_UP = 263
LEFT_DOWN = 264
EXIT = 269
VOLUME_UP = 321
VOLUME_DOWN = 322
VOLUME_MUTE = 323
POWER = 320
POWER_TOGGLE = 363
POWER_OFF = 364
POWER_ON = 365
FEATURE_ABORT_REASON_UNKNOWN = 0
UNRECOGNIZED_OPCODE = 10
NOT_IN_CORRECT_MODE_TO_RESPOND = 11
CANNOT_PROVIDE_SOURCE = 12
INVALID_OPERAND = 13
REFUSED = 14
UNABLE_TO_DETERMINE = 15


if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'B\016HdmiStatsEnumsP\001'
  _LOGICALADDRESS._serialized_start=84
  _LOGICALADDRESS._serialized_end=438
  _PATHRELATIONSHIP._serialized_start=441
  _PATHRELATIONSHIP._serialized_end=577
  _SENDMESSAGERESULT._serialized_start=579
  _SENDMESSAGERESULT._serialized_end=674
  _MESSAGEDIRECTION._serialized_start=676
  _MESSAGEDIRECTION._serialized_end=795
  _USERCONTROLPRESSEDCOMMAND._serialized_start=798
  _USERCONTROLPRESSEDCOMMAND._serialized_end=1162
  _FEATUREABORTREASON._serialized_start=1165
  _FEATUREABORTREASON._serialized_end=1366
# @@protoc_insertion_point(module_scope)