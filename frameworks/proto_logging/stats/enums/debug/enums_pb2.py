# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: frameworks/proto_logging/stats/enums/debug/enums.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n6frameworks/proto_logging/stats/enums/debug/enums.proto\x12\randroid.debug*\xc2\x01\n\x16\x41\x64\x62\x43onnectionStateEnum\x12\x0b\n\x07UNKNOWN\x10\x00\x12\x1a\n\x16\x41WAITING_USER_APPROVAL\x10\x01\x12\x10\n\x0cUSER_ALLOWED\x10\x02\x12\x0f\n\x0bUSER_DENIED\x10\x03\x12\x19\n\x15\x41UTOMATICALLY_ALLOWED\x10\x04\x12\x16\n\x12\x44\x45NIED_INVALID_KEY\x10\x05\x12\x17\n\x13\x44\x45NIED_VOLD_DECRYPT\x10\x06\x12\x10\n\x0c\x44ISCONNECTED\x10\x07\x42\x11\x42\rAdbProtoEnumsP\x01')

_ADBCONNECTIONSTATEENUM = DESCRIPTOR.enum_types_by_name['AdbConnectionStateEnum']
AdbConnectionStateEnum = enum_type_wrapper.EnumTypeWrapper(_ADBCONNECTIONSTATEENUM)
UNKNOWN = 0
AWAITING_USER_APPROVAL = 1
USER_ALLOWED = 2
USER_DENIED = 3
AUTOMATICALLY_ALLOWED = 4
DENIED_INVALID_KEY = 5
DENIED_VOLD_DECRYPT = 6
DISCONNECTED = 7


if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'B\rAdbProtoEnumsP\001'
  _ADBCONNECTIONSTATEENUM._serialized_start=74
  _ADBCONNECTIONSTATEENUM._serialized_end=268
# @@protoc_insertion_point(module_scope)