# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: frameworks/proto_logging/stats/enums/hardware/biometrics/enums.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\nDframeworks/proto_logging/stats/enums/hardware/biometrics/enums.proto\x12\x1b\x61ndroid.hardware.biometrics*d\n\x0cModalityEnum\x12\x14\n\x10MODALITY_UNKNOWN\x10\x00\x12\x18\n\x14MODALITY_FINGERPRINT\x10\x01\x12\x11\n\rMODALITY_IRIS\x10\x02\x12\x11\n\rMODALITY_FACE\x10\x04*r\n\nClientEnum\x12\x12\n\x0e\x43LIENT_UNKNOWN\x10\x00\x12\x13\n\x0f\x43LIENT_KEYGUARD\x10\x01\x12\x1b\n\x17\x43LIENT_BIOMETRIC_PROMPT\x10\x02\x12\x1e\n\x1a\x43LIENT_FINGERPRINT_MANAGER\x10\x03*u\n\nActionEnum\x12\x12\n\x0e\x41\x43TION_UNKNOWN\x10\x00\x12\x11\n\rACTION_ENROLL\x10\x01\x12\x17\n\x13\x41\x43TION_AUTHENTICATE\x10\x02\x12\x14\n\x10\x41\x43TION_ENUMERATE\x10\x03\x12\x11\n\rACTION_REMOVE\x10\x04*\xa7\x01\n\tIssueEnum\x12\x11\n\rISSUE_UNKNOWN\x10\x00\x12\x13\n\x0fISSUE_HAL_DEATH\x10\x01\x12-\n)ISSUE_UNKNOWN_TEMPLATE_ENROLLED_FRAMEWORK\x10\x02\x12\'\n#ISSUE_UNKNOWN_TEMPLATE_ENROLLED_HAL\x10\x03\x12\x1a\n\x16ISSUE_CANCEL_TIMED_OUT\x10\x04\x42\x18\x42\x14\x42iometricsProtoEnumsP\x01')

_MODALITYENUM = DESCRIPTOR.enum_types_by_name['ModalityEnum']
ModalityEnum = enum_type_wrapper.EnumTypeWrapper(_MODALITYENUM)
_CLIENTENUM = DESCRIPTOR.enum_types_by_name['ClientEnum']
ClientEnum = enum_type_wrapper.EnumTypeWrapper(_CLIENTENUM)
_ACTIONENUM = DESCRIPTOR.enum_types_by_name['ActionEnum']
ActionEnum = enum_type_wrapper.EnumTypeWrapper(_ACTIONENUM)
_ISSUEENUM = DESCRIPTOR.enum_types_by_name['IssueEnum']
IssueEnum = enum_type_wrapper.EnumTypeWrapper(_ISSUEENUM)
MODALITY_UNKNOWN = 0
MODALITY_FINGERPRINT = 1
MODALITY_IRIS = 2
MODALITY_FACE = 4
CLIENT_UNKNOWN = 0
CLIENT_KEYGUARD = 1
CLIENT_BIOMETRIC_PROMPT = 2
CLIENT_FINGERPRINT_MANAGER = 3
ACTION_UNKNOWN = 0
ACTION_ENROLL = 1
ACTION_AUTHENTICATE = 2
ACTION_ENUMERATE = 3
ACTION_REMOVE = 4
ISSUE_UNKNOWN = 0
ISSUE_HAL_DEATH = 1
ISSUE_UNKNOWN_TEMPLATE_ENROLLED_FRAMEWORK = 2
ISSUE_UNKNOWN_TEMPLATE_ENROLLED_HAL = 3
ISSUE_CANCEL_TIMED_OUT = 4


if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'B\024BiometricsProtoEnumsP\001'
  _MODALITYENUM._serialized_start=101
  _MODALITYENUM._serialized_end=201
  _CLIENTENUM._serialized_start=203
  _CLIENTENUM._serialized_end=317
  _ACTIONENUM._serialized_start=319
  _ACTIONENUM._serialized_end=436
  _ISSUEENUM._serialized_start=439
  _ISSUEENUM._serialized_end=606
# @@protoc_insertion_point(module_scope)