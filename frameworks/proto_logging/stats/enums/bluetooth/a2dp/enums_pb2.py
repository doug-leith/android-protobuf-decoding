# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: frameworks/proto_logging/stats/enums/bluetooth/a2dp/enums.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n?frameworks/proto_logging/stats/enums/bluetooth/a2dp/enums.proto\x12\x16\x61ndroid.bluetooth.a2dp*k\n\x11PlaybackStateEnum\x12\x1a\n\x16PLAYBACK_STATE_UNKNOWN\x10\x00\x12\x1a\n\x16PLAYBACK_STATE_PLAYING\x10\n\x12\x1e\n\x1aPLAYBACK_STATE_NOT_PLAYING\x10\x0b*t\n\x13\x41udioCodingModeEnum\x12\x1d\n\x19\x41UDIO_CODING_MODE_UNKNOWN\x10\x00\x12\x1e\n\x1a\x41UDIO_CODING_MODE_HARDWARE\x10\x01\x12\x1e\n\x1a\x41UDIO_CODING_MODE_SOFTWARE\x10\x02\x42\x1b\x42\x17\x42luetoothA2dpProtoEnumsP\x01')

_PLAYBACKSTATEENUM = DESCRIPTOR.enum_types_by_name['PlaybackStateEnum']
PlaybackStateEnum = enum_type_wrapper.EnumTypeWrapper(_PLAYBACKSTATEENUM)
_AUDIOCODINGMODEENUM = DESCRIPTOR.enum_types_by_name['AudioCodingModeEnum']
AudioCodingModeEnum = enum_type_wrapper.EnumTypeWrapper(_AUDIOCODINGMODEENUM)
PLAYBACK_STATE_UNKNOWN = 0
PLAYBACK_STATE_PLAYING = 10
PLAYBACK_STATE_NOT_PLAYING = 11
AUDIO_CODING_MODE_UNKNOWN = 0
AUDIO_CODING_MODE_HARDWARE = 1
AUDIO_CODING_MODE_SOFTWARE = 2


if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'B\027BluetoothA2dpProtoEnumsP\001'
  _PLAYBACKSTATEENUM._serialized_start=91
  _PLAYBACKSTATEENUM._serialized_end=198
  _AUDIOCODINGMODEENUM._serialized_start=200
  _AUDIOCODINGMODEENUM._serialized_end=316
# @@protoc_insertion_point(module_scope)