# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: frameworks/proto_logging/stats/enums/app/media_output_enum.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n@frameworks/proto_logging/stats/enums/app/media_output_enum.proto\x12 android.app.settings.mediaoutput*\xa7\x03\n\nMediumType\x12\x10\n\x0cUNKNOWN_TYPE\x10\x00\x12\x13\n\x0f\x42UILTIN_SPEAKER\x10\x01\x12\x1a\n\x16WIRED_3POINT5_MM_AUDIO\x10\x64\x12\x1c\n\x18WIRED_3POINT5_MM_HEADSET\x10\x65\x12\x1f\n\x1bWIRED_3POINT5_MM_HEADPHONES\x10\x66\x12\x10\n\x0bUSB_C_AUDIO\x10\xc8\x01\x12\x11\n\x0cUSB_C_DEVICE\x10\xc9\x01\x12\x12\n\rUSB_C_HEADSET\x10\xca\x01\x12\x14\n\x0fUSB_C_ACCESSORY\x10\xcb\x01\x12\x0f\n\nUSB_C_DOCK\x10\xcc\x01\x12\x0f\n\nUSB_C_HDMI\x10\xcd\x01\x12\x0e\n\tBLUETOOTH\x10\xac\x02\x12\x1a\n\x15\x42LUETOOTH_HEARING_AID\x10\xad\x02\x12\x13\n\x0e\x42LUETOOTH_A2DP\x10\xae\x02\x12\x12\n\rREMOTE_SINGLE\x10\x90\x03\x12\x0e\n\tREMOTE_TV\x10\x91\x03\x12\x13\n\x0eREMOTE_SPEAKER\x10\x92\x03\x12\x11\n\x0cREMOTE_GROUP\x10\xf4\x03\x12\x19\n\x14REMOTE_DYNAMIC_GROUP\x10\xf5\x03*!\n\x0cSwitchResult\x12\t\n\x05\x45RROR\x10\x00\x12\x06\n\x02OK\x10\x01*{\n\tSubResult\x12\x11\n\rUNKNOWN_ERROR\x10\x00\x12\x0c\n\x08NO_ERROR\x10\x01\x12\x0c\n\x08REJECTED\x10\x02\x12\x11\n\rNETWORK_ERROR\x10\x03\x12\x17\n\x13ROUTE_NOT_AVAILABLE\x10\x04\x12\x13\n\x0fINVALID_COMMAND\x10\x05\x42\x02P\x01')

_MEDIUMTYPE = DESCRIPTOR.enum_types_by_name['MediumType']
MediumType = enum_type_wrapper.EnumTypeWrapper(_MEDIUMTYPE)
_SWITCHRESULT = DESCRIPTOR.enum_types_by_name['SwitchResult']
SwitchResult = enum_type_wrapper.EnumTypeWrapper(_SWITCHRESULT)
_SUBRESULT = DESCRIPTOR.enum_types_by_name['SubResult']
SubResult = enum_type_wrapper.EnumTypeWrapper(_SUBRESULT)
UNKNOWN_TYPE = 0
BUILTIN_SPEAKER = 1
WIRED_3POINT5_MM_AUDIO = 100
WIRED_3POINT5_MM_HEADSET = 101
WIRED_3POINT5_MM_HEADPHONES = 102
USB_C_AUDIO = 200
USB_C_DEVICE = 201
USB_C_HEADSET = 202
USB_C_ACCESSORY = 203
USB_C_DOCK = 204
USB_C_HDMI = 205
BLUETOOTH = 300
BLUETOOTH_HEARING_AID = 301
BLUETOOTH_A2DP = 302
REMOTE_SINGLE = 400
REMOTE_TV = 401
REMOTE_SPEAKER = 402
REMOTE_GROUP = 500
REMOTE_DYNAMIC_GROUP = 501
ERROR = 0
OK = 1
UNKNOWN_ERROR = 0
NO_ERROR = 1
REJECTED = 2
NETWORK_ERROR = 3
ROUTE_NOT_AVAILABLE = 4
INVALID_COMMAND = 5


if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'P\001'
  _MEDIUMTYPE._serialized_start=103
  _MEDIUMTYPE._serialized_end=526
  _SWITCHRESULT._serialized_start=528
  _SWITCHRESULT._serialized_end=561
  _SUBRESULT._serialized_start=563
  _SUBRESULT._serialized_end=686
# @@protoc_insertion_point(module_scope)
