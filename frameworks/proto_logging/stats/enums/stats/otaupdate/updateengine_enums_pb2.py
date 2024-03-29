# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: frameworks/proto_logging/stats/enums/stats/otaupdate/updateengine_enums.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\nMframeworks/proto_logging/stats/enums/stats/otaupdate/updateengine_enums.proto\x12\x17\x61ndroid.stats.otaupdate*$\n\x0bPayloadType\x12\t\n\x04\x46ULL\x10\x90N\x12\n\n\x05\x44\x45LTA\x10\x91N*\xf6\x02\n\rAttemptResult\x12\x15\n\x10UPDATE_SUCCEEDED\x10\x90N\x12\x13\n\x0eINTERNAL_ERROR\x10\x91N\x12\x1b\n\x16PAYLOAD_DOWNLOAD_ERROR\x10\x92N\x12\x17\n\x12METADATA_MALFORMED\x10\x93N\x12\x18\n\x13OPERATION_MALFORMED\x10\x94N\x12\x1e\n\x19OPERATION_EXECUTION_ERROR\x10\x95N\x12!\n\x1cMETADATA_VERIFICATION_FAILED\x10\x96N\x12 \n\x1bPAYLOAD_VERIFICATION_FAILED\x10\x97N\x12\x18\n\x13VERIFICATION_FAILED\x10\x98N\x12\x17\n\x12POSTINSTALL_FAILED\x10\x99N\x12\x19\n\x14\x41\x42NORMAL_TERMINATION\x10\x9aN\x12\x14\n\x0fUPDATE_CANCELED\x10\x9bN\x12 \n\x1bUPDATE_SUCCEEDED_NOT_ACTIVE\x10\x9cN*\xb0\n\n\tErrorCode\x12\x0c\n\x07SUCCESS\x10\x90N\x12\n\n\x05\x45RROR\x10\x91N\x12\x1c\n\x17\x46ILESYSTEM_COPIER_ERROR\x10\x94N\x12\x1e\n\x19POST_INSTALL_RUNNER_ERROR\x10\x95N\x12\"\n\x1dPAYLOAD_MISMATCHED_TYPE_ERROR\x10\x96N\x12\x1e\n\x19INSTALL_DEVICE_OPEN_ERROR\x10\x97N\x12\x1d\n\x18KERNEL_DEVICE_OPEN_ERROR\x10\x98N\x12\x1c\n\x17\x44OWNLOAD_TRANSFER_ERROR\x10\x99N\x12 \n\x1bPAYLOAD_HASH_MISMATCH_ERROR\x10\x9aN\x12 \n\x1bPAYLOAD_SIZE_MISMATCH_ERROR\x10\x9bN\x12(\n#DOWNLOAD_PAYLOAD_VERIFICATION_ERROR\x10\x9cN\x12&\n!DOWNLOAD_NEW_PARTITION_INFO_ERROR\x10\x9dN\x12\x19\n\x14\x44OWNLOAD_WRITE_ERROR\x10\x9eN\x12\"\n\x1dNEW_ROOTFS_VERIFICATION_ERROR\x10\x9fN\x12(\n#SIGNED_DELTA_PAYLOAD_EXPECTED_ERROR\x10\xa1N\x12\x30\n+DOWNLOAD_PAYLOAD_PUB_KEY_VERIFICATION_ERROR\x10\xa2N\x12(\n#DOWNLOAD_STATE_INITIALIZATION_ERROR\x10\xa4N\x12+\n&DOWNLOAD_INVALID_METADATA_MAGIC_STRING\x10\xa5N\x12+\n&DOWNLOAD_SIGNATURE_MISSING_IN_MANIFEST\x10\xa6N\x12\"\n\x1d\x44OWNLOAD_MANIFEST_PARSE_ERROR\x10\xa7N\x12&\n!DOWNLOAD_METADATA_SIGNATURE_ERROR\x10\xa8N\x12\x33\n.DOWNLOAD_METADATA_SIGNATURE_VERIFICATION_ERROR\x10\xa9N\x12)\n$DOWNLOAD_METADATA_SIGNATURE_MISMATCH\x10\xaaN\x12/\n*DOWNLOAD_OPERATION_HASH_VERIFICATION_ERROR\x10\xabN\x12\'\n\"DOWNLOAD_OPERATION_EXECUTION_ERROR\x10\xacN\x12%\n DOWNLOAD_OPERATION_HASH_MISMATCH\x10\xadN\x12#\n\x1e\x44OWNLOAD_INVALID_METADATA_SIZE\x10\xb0N\x12(\n#DOWNLOAD_INVALID_METADATA_SIGNATURE\x10\xb1N\x12*\n%DOWNLOAD_OPERATION_HASH_MISSING_ERROR\x10\xb6N\x12.\n)DOWNLOAD_METADATA_SIGNATURE_MISSING_ERROR\x10\xb7N\x12&\n!UNSUPPORTED_MAJOR_PAYLOAD_VERSION\x10\xbcN\x12&\n!UNSUPPORTED_MINOR_PAYLOAD_VERSION\x10\xbdN\x12\x1e\n\x19\x46ILESYSTEM_VERIFIER_ERROR\x10\xbfN\x12\x12\n\rUSER_CANCELED\x10\xc0N\x12\x1c\n\x17PAYLOAD_TIMESTAMP_ERROR\x10\xc3N\x12\x1b\n\x16UPDATED_BUT_NOT_ACTIVE\x10\xc4N')

_PAYLOADTYPE = DESCRIPTOR.enum_types_by_name['PayloadType']
PayloadType = enum_type_wrapper.EnumTypeWrapper(_PAYLOADTYPE)
_ATTEMPTRESULT = DESCRIPTOR.enum_types_by_name['AttemptResult']
AttemptResult = enum_type_wrapper.EnumTypeWrapper(_ATTEMPTRESULT)
_ERRORCODE = DESCRIPTOR.enum_types_by_name['ErrorCode']
ErrorCode = enum_type_wrapper.EnumTypeWrapper(_ERRORCODE)
FULL = 10000
DELTA = 10001
UPDATE_SUCCEEDED = 10000
INTERNAL_ERROR = 10001
PAYLOAD_DOWNLOAD_ERROR = 10002
METADATA_MALFORMED = 10003
OPERATION_MALFORMED = 10004
OPERATION_EXECUTION_ERROR = 10005
METADATA_VERIFICATION_FAILED = 10006
PAYLOAD_VERIFICATION_FAILED = 10007
VERIFICATION_FAILED = 10008
POSTINSTALL_FAILED = 10009
ABNORMAL_TERMINATION = 10010
UPDATE_CANCELED = 10011
UPDATE_SUCCEEDED_NOT_ACTIVE = 10012
SUCCESS = 10000
ERROR = 10001
FILESYSTEM_COPIER_ERROR = 10004
POST_INSTALL_RUNNER_ERROR = 10005
PAYLOAD_MISMATCHED_TYPE_ERROR = 10006
INSTALL_DEVICE_OPEN_ERROR = 10007
KERNEL_DEVICE_OPEN_ERROR = 10008
DOWNLOAD_TRANSFER_ERROR = 10009
PAYLOAD_HASH_MISMATCH_ERROR = 10010
PAYLOAD_SIZE_MISMATCH_ERROR = 10011
DOWNLOAD_PAYLOAD_VERIFICATION_ERROR = 10012
DOWNLOAD_NEW_PARTITION_INFO_ERROR = 10013
DOWNLOAD_WRITE_ERROR = 10014
NEW_ROOTFS_VERIFICATION_ERROR = 10015
SIGNED_DELTA_PAYLOAD_EXPECTED_ERROR = 10017
DOWNLOAD_PAYLOAD_PUB_KEY_VERIFICATION_ERROR = 10018
DOWNLOAD_STATE_INITIALIZATION_ERROR = 10020
DOWNLOAD_INVALID_METADATA_MAGIC_STRING = 10021
DOWNLOAD_SIGNATURE_MISSING_IN_MANIFEST = 10022
DOWNLOAD_MANIFEST_PARSE_ERROR = 10023
DOWNLOAD_METADATA_SIGNATURE_ERROR = 10024
DOWNLOAD_METADATA_SIGNATURE_VERIFICATION_ERROR = 10025
DOWNLOAD_METADATA_SIGNATURE_MISMATCH = 10026
DOWNLOAD_OPERATION_HASH_VERIFICATION_ERROR = 10027
DOWNLOAD_OPERATION_EXECUTION_ERROR = 10028
DOWNLOAD_OPERATION_HASH_MISMATCH = 10029
DOWNLOAD_INVALID_METADATA_SIZE = 10032
DOWNLOAD_INVALID_METADATA_SIGNATURE = 10033
DOWNLOAD_OPERATION_HASH_MISSING_ERROR = 10038
DOWNLOAD_METADATA_SIGNATURE_MISSING_ERROR = 10039
UNSUPPORTED_MAJOR_PAYLOAD_VERSION = 10044
UNSUPPORTED_MINOR_PAYLOAD_VERSION = 10045
FILESYSTEM_VERIFIER_ERROR = 10047
USER_CANCELED = 10048
PAYLOAD_TIMESTAMP_ERROR = 10051
UPDATED_BUT_NOT_ACTIVE = 10052


if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _PAYLOADTYPE._serialized_start=106
  _PAYLOADTYPE._serialized_end=142
  _ATTEMPTRESULT._serialized_start=145
  _ATTEMPTRESULT._serialized_end=519
  _ERRORCODE._serialized_start=522
  _ERRORCODE._serialized_end=1850
# @@protoc_insertion_point(module_scope)
