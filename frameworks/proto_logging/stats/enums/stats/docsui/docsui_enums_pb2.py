# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: frameworks/proto_logging/stats/enums/stats/docsui/docsui_enums.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\nDframeworks/proto_logging/stats/enums/stats/docsui/docsui_enums.proto\x12\x14\x61ndroid.stats.docsui*|\n\x0cLaunchAction\x12\x0b\n\x07UNKNOWN\x10\x00\x12\x08\n\x04OPEN\x10\x01\x12\n\n\x06\x43REATE\x10\x02\x12\x0f\n\x0bGET_CONTENT\x10\x03\x12\r\n\tOPEN_TREE\x10\x04\x12\x12\n\x0ePICK_COPY_DEST\x10\x05\x12\n\n\x06\x42ROWSE\x10\x06\x12\t\n\x05OTHER\x10\x07*\xc4\x01\n\x08MimeType\x12\x10\n\x0cMIME_UNKNOWN\x10\x00\x12\r\n\tMIME_NONE\x10\x01\x12\x0c\n\x08MIME_ANY\x10\x02\x12\x14\n\x10MIME_APPLICATION\x10\x03\x12\x0e\n\nMIME_AUDIO\x10\x04\x12\x0e\n\nMIME_IMAGE\x10\x05\x12\x10\n\x0cMIME_MESSAGE\x10\x06\x12\x12\n\x0eMIME_MULTIPART\x10\x07\x12\r\n\tMIME_TEXT\x10\x08\x12\x0e\n\nMIME_VIDEO\x10\t\x12\x0e\n\nMIME_OTHER\x10\n*\x81\x02\n\x04Root\x12\x10\n\x0cROOT_UNKNOWN\x10\x00\x12\r\n\tROOT_NONE\x10\x01\x12\x1c\n\x18ROOT_OTHER_DOCS_PROVIDER\x10\x02\x12\x0e\n\nROOT_AUDIO\x10\x03\x12\x17\n\x13ROOT_DEVICE_STORAGE\x10\x04\x12\x12\n\x0eROOT_DOWNLOADS\x10\x05\x12\r\n\tROOT_HOME\x10\x06\x12\x0f\n\x0bROOT_IMAGES\x10\x07\x12\x10\n\x0cROOT_RECENTS\x10\x08\x12\x0f\n\x0bROOT_VIDEOS\x10\t\x12\x0c\n\x08ROOT_MTP\x10\n\x12\x18\n\x14ROOT_THIRD_PARTY_APP\x10\x0b\x12\x12\n\x0eROOT_DOCUMENTS\x10\x0c*D\n\x0c\x43ontextScope\x12\x11\n\rSCOPE_UNKNOWN\x10\x00\x12\x0f\n\x0bSCOPE_FILES\x10\x01\x12\x10\n\x0cSCOPE_PICKER\x10\x02*L\n\x08Provider\x12\x14\n\x10PROVIDER_UNKNOWN\x10\x00\x12\x13\n\x0fPROVIDER_SYSTEM\x10\x01\x12\x15\n\x11PROVIDER_EXTERNAL\x10\x02*\x97\x05\n\rFileOperation\x12\x0e\n\nOP_UNKNOWN\x10\x00\x12\x0c\n\x08OP_OTHER\x10\x01\x12\x0b\n\x07OP_COPY\x10\x02\x12\x1a\n\x16OP_COPY_INTRA_PROVIDER\x10\x03\x12\x1b\n\x17OP_COPY_SYSTEM_PROVIDER\x10\x04\x12\x1d\n\x19OP_COPY_EXTERNAL_PROVIDER\x10\x05\x12\x0b\n\x07OP_MOVE\x10\x06\x12\x1a\n\x16OP_MOVE_INTRA_PROVIDER\x10\x07\x12\x1b\n\x17OP_MOVE_SYSTEM_PROVIDER\x10\x08\x12\x1d\n\x19OP_MOVE_EXTERNAL_PROVIDER\x10\t\x12\r\n\tOP_DELETE\x10\n\x12\r\n\tOP_RENAME\x10\x0b\x12\x11\n\rOP_CREATE_DIR\x10\x0c\x12\x12\n\x0eOP_OTHER_ERROR\x10\r\x12\x13\n\x0fOP_DELETE_ERROR\x10\x0e\x12\x11\n\rOP_MOVE_ERROR\x10\x0f\x12\x11\n\rOP_COPY_ERROR\x10\x10\x12\x13\n\x0fOP_RENAME_ERROR\x10\x11\x12\x17\n\x13OP_CREATE_DIR_ERROR\x10\x12\x12\x1e\n\x1aOP_COMPRESS_INTRA_PROVIDER\x10\x13\x12\x1f\n\x1bOP_COMPRESS_SYSTEM_PROVIDER\x10\x14\x12!\n\x1dOP_COMPRESS_EXTERNAL_PROVIDER\x10\x15\x12\x1d\n\x19OP_EXTRACT_INTRA_PROVIDER\x10\x16\x12\x1e\n\x1aOP_EXTRACT_SYSTEM_PROVIDER\x10\x17\x12 \n\x1cOP_EXTRACT_EXTERNAL_PROVIDER\x10\x18\x12\x15\n\x11OP_COMPRESS_ERROR\x10\x19\x12\x14\n\x10OP_EXTRACT_ERROR\x10\x1a*\x92\x02\n\x10SubFileOperation\x12\x12\n\x0eSUB_OP_UNKNOWN\x10\x00\x12\x14\n\x10SUB_OP_QUERY_DOC\x10\x01\x12\x16\n\x12SUB_OP_QUERY_CHILD\x10\x02\x12\x14\n\x10SUB_OP_OPEN_FILE\x10\x03\x12\x14\n\x10SUB_OP_READ_FILE\x10\x04\x12\x15\n\x11SUB_OP_CREATE_DOC\x10\x05\x12\x15\n\x11SUB_OP_WRITE_FILE\x10\x06\x12\x15\n\x11SUB_OP_DELETE_DOC\x10\x07\x12\x1d\n\x19SUB_OP_OBTAIN_STREAM_TYPE\x10\x08\x12\x15\n\x11SUB_OP_QUICK_MOVE\x10\t\x12\x15\n\x11SUB_OP_QUICK_COPY\x10\n*`\n\x0e\x43opyMoveOpMode\x12\x10\n\x0cMODE_UNKNOWN\x10\x00\x12\x11\n\rMODE_PROVIDER\x10\x01\x12\x12\n\x0eMODE_CONVERTED\x10\x02\x12\x15\n\x11MODE_CONVENTIONAL\x10\x03*\x95\x01\n\tAuthority\x12\x10\n\x0c\x41UTH_UNKNOWN\x10\x00\x12\x0e\n\nAUTH_OTHER\x10\x01\x12\x0e\n\nAUTH_MEDIA\x10\x02\x12\x19\n\x15\x41UTH_STORAGE_INTERNAL\x10\x03\x12\x19\n\x15\x41UTH_STORAGE_EXTERNAL\x10\x04\x12\x12\n\x0e\x41UTH_DOWNLOADS\x10\x05\x12\x0c\n\x08\x41UTH_MTP\x10\x06*\x8d\x06\n\nUserAction\x12\x12\n\x0e\x41\x43TION_UNKNOWN\x10\x00\x12\x10\n\x0c\x41\x43TION_OTHER\x10\x01\x12\x0f\n\x0b\x41\x43TION_GRID\x10\x02\x12\x0f\n\x0b\x41\x43TION_LIST\x10\x03\x12\x14\n\x10\x41\x43TION_SORT_NAME\x10\x04\x12\x14\n\x10\x41\x43TION_SORT_DATE\x10\x05\x12\x14\n\x10\x41\x43TION_SORT_SIZE\x10\x06\x12\x14\n\x10\x41\x43TION_SORT_TYPE\x10\x07\x12\x11\n\rACTION_SEARCH\x10\x08\x12\x14\n\x10\x41\x43TION_SHOW_SIZE\x10\t\x12\x14\n\x10\x41\x43TION_HIDE_SIZE\x10\n\x12\x13\n\x0f\x41\x43TION_SETTINGS\x10\x0b\x12\x12\n\x0e\x41\x43TION_COPY_TO\x10\x0c\x12\x12\n\x0e\x41\x43TION_MOVE_TO\x10\r\x12\x11\n\rACTION_DELETE\x10\x0e\x12\x11\n\rACTION_RENAME\x10\x0f\x12\x15\n\x11\x41\x43TION_CREATE_DIR\x10\x10\x12\x15\n\x11\x41\x43TION_SELECT_ALL\x10\x11\x12\x10\n\x0c\x41\x43TION_SHARE\x10\x12\x12\x0f\n\x0b\x41\x43TION_OPEN\x10\x13\x12\x18\n\x14\x41\x43TION_SHOW_ADVANCED\x10\x14\x12\x18\n\x14\x41\x43TION_HIDE_ADVANCED\x10\x15\x12\x15\n\x11\x41\x43TION_NEW_WINDOW\x10\x16\x12\x1a\n\x16\x41\x43TION_PASTE_CLIPBOARD\x10\x17\x12\x19\n\x15\x41\x43TION_COPY_CLIPBOARD\x10\x18\x12\x16\n\x12\x41\x43TION_DRAG_N_DROP\x10\x19\x12#\n\x1f\x41\x43TION_DRAG_N_DROP_MULTI_WINDOW\x10\x1a\x12\x18\n\x14\x41\x43TION_CUT_CLIPBOARD\x10\x1b\x12\x13\n\x0f\x41\x43TION_COMPRESS\x10\x1c\x12\x15\n\x11\x41\x43TION_EXTRACT_TO\x10\x1d\x12\x1e\n\x1a\x41\x43TION_VIEW_IN_APPLICATION\x10\x1e\x12\x14\n\x10\x41\x43TION_INSPECTOR\x10\x1f\x12\x16\n\x12\x41\x43TION_SEARCH_CHIP\x10 \x12\x19\n\x15\x41\x43TION_SEARCH_HISTORY\x10!*\xc5\x01\n\x13InvalidScopedAccess\x12\x1d\n\x19SCOPED_DIR_ACCESS_UNKNOWN\x10\x00\x12\'\n#SCOPED_DIR_ACCESS_INVALID_ARGUMENTS\x10\x01\x12\'\n#SCOPED_DIR_ACCESS_INVALID_DIRECTORY\x10\x02\x12\x1b\n\x17SCOPED_DIR_ACCESS_ERROR\x10\x03\x12 \n\x1cSCOPED_DIR_ACCESS_DEPRECATED\x10\x04*\xde\x01\n\nSearchType\x12\x10\n\x0cTYPE_UNKNOWN\x10\x00\x12\x14\n\x10TYPE_CHIP_IMAGES\x10\x01\x12\x14\n\x10TYPE_CHIP_AUDIOS\x10\x02\x12\x14\n\x10TYPE_CHIP_VIDEOS\x10\x03\x12\x12\n\x0eTYPE_CHIP_DOCS\x10\x04\x12\x17\n\x13TYPE_SEARCH_HISTORY\x10\x05\x12\x16\n\x12TYPE_SEARCH_STRING\x10\x06\x12\x19\n\x15TYPE_CHIP_LARGE_FILES\x10\x07\x12\x1c\n\x18TYPE_CHIP_FROM_THIS_WEEK\x10\x08*b\n\nSearchMode\x12\x12\n\x0eSEARCH_UNKNOWN\x10\x00\x12\x12\n\x0eSEARCH_KEYWORD\x10\x01\x12\x10\n\x0cSEARCH_CHIPS\x10\x02\x12\x1a\n\x16SEARCH_KEYWORD_N_CHIPS\x10\x03\x42\x02P\x01')

_LAUNCHACTION = DESCRIPTOR.enum_types_by_name['LaunchAction']
LaunchAction = enum_type_wrapper.EnumTypeWrapper(_LAUNCHACTION)
_MIMETYPE = DESCRIPTOR.enum_types_by_name['MimeType']
MimeType = enum_type_wrapper.EnumTypeWrapper(_MIMETYPE)
_ROOT = DESCRIPTOR.enum_types_by_name['Root']
Root = enum_type_wrapper.EnumTypeWrapper(_ROOT)
_CONTEXTSCOPE = DESCRIPTOR.enum_types_by_name['ContextScope']
ContextScope = enum_type_wrapper.EnumTypeWrapper(_CONTEXTSCOPE)
_PROVIDER = DESCRIPTOR.enum_types_by_name['Provider']
Provider = enum_type_wrapper.EnumTypeWrapper(_PROVIDER)
_FILEOPERATION = DESCRIPTOR.enum_types_by_name['FileOperation']
FileOperation = enum_type_wrapper.EnumTypeWrapper(_FILEOPERATION)
_SUBFILEOPERATION = DESCRIPTOR.enum_types_by_name['SubFileOperation']
SubFileOperation = enum_type_wrapper.EnumTypeWrapper(_SUBFILEOPERATION)
_COPYMOVEOPMODE = DESCRIPTOR.enum_types_by_name['CopyMoveOpMode']
CopyMoveOpMode = enum_type_wrapper.EnumTypeWrapper(_COPYMOVEOPMODE)
_AUTHORITY = DESCRIPTOR.enum_types_by_name['Authority']
Authority = enum_type_wrapper.EnumTypeWrapper(_AUTHORITY)
_USERACTION = DESCRIPTOR.enum_types_by_name['UserAction']
UserAction = enum_type_wrapper.EnumTypeWrapper(_USERACTION)
_INVALIDSCOPEDACCESS = DESCRIPTOR.enum_types_by_name['InvalidScopedAccess']
InvalidScopedAccess = enum_type_wrapper.EnumTypeWrapper(_INVALIDSCOPEDACCESS)
_SEARCHTYPE = DESCRIPTOR.enum_types_by_name['SearchType']
SearchType = enum_type_wrapper.EnumTypeWrapper(_SEARCHTYPE)
_SEARCHMODE = DESCRIPTOR.enum_types_by_name['SearchMode']
SearchMode = enum_type_wrapper.EnumTypeWrapper(_SEARCHMODE)
UNKNOWN = 0
OPEN = 1
CREATE = 2
GET_CONTENT = 3
OPEN_TREE = 4
PICK_COPY_DEST = 5
BROWSE = 6
OTHER = 7
MIME_UNKNOWN = 0
MIME_NONE = 1
MIME_ANY = 2
MIME_APPLICATION = 3
MIME_AUDIO = 4
MIME_IMAGE = 5
MIME_MESSAGE = 6
MIME_MULTIPART = 7
MIME_TEXT = 8
MIME_VIDEO = 9
MIME_OTHER = 10
ROOT_UNKNOWN = 0
ROOT_NONE = 1
ROOT_OTHER_DOCS_PROVIDER = 2
ROOT_AUDIO = 3
ROOT_DEVICE_STORAGE = 4
ROOT_DOWNLOADS = 5
ROOT_HOME = 6
ROOT_IMAGES = 7
ROOT_RECENTS = 8
ROOT_VIDEOS = 9
ROOT_MTP = 10
ROOT_THIRD_PARTY_APP = 11
ROOT_DOCUMENTS = 12
SCOPE_UNKNOWN = 0
SCOPE_FILES = 1
SCOPE_PICKER = 2
PROVIDER_UNKNOWN = 0
PROVIDER_SYSTEM = 1
PROVIDER_EXTERNAL = 2
OP_UNKNOWN = 0
OP_OTHER = 1
OP_COPY = 2
OP_COPY_INTRA_PROVIDER = 3
OP_COPY_SYSTEM_PROVIDER = 4
OP_COPY_EXTERNAL_PROVIDER = 5
OP_MOVE = 6
OP_MOVE_INTRA_PROVIDER = 7
OP_MOVE_SYSTEM_PROVIDER = 8
OP_MOVE_EXTERNAL_PROVIDER = 9
OP_DELETE = 10
OP_RENAME = 11
OP_CREATE_DIR = 12
OP_OTHER_ERROR = 13
OP_DELETE_ERROR = 14
OP_MOVE_ERROR = 15
OP_COPY_ERROR = 16
OP_RENAME_ERROR = 17
OP_CREATE_DIR_ERROR = 18
OP_COMPRESS_INTRA_PROVIDER = 19
OP_COMPRESS_SYSTEM_PROVIDER = 20
OP_COMPRESS_EXTERNAL_PROVIDER = 21
OP_EXTRACT_INTRA_PROVIDER = 22
OP_EXTRACT_SYSTEM_PROVIDER = 23
OP_EXTRACT_EXTERNAL_PROVIDER = 24
OP_COMPRESS_ERROR = 25
OP_EXTRACT_ERROR = 26
SUB_OP_UNKNOWN = 0
SUB_OP_QUERY_DOC = 1
SUB_OP_QUERY_CHILD = 2
SUB_OP_OPEN_FILE = 3
SUB_OP_READ_FILE = 4
SUB_OP_CREATE_DOC = 5
SUB_OP_WRITE_FILE = 6
SUB_OP_DELETE_DOC = 7
SUB_OP_OBTAIN_STREAM_TYPE = 8
SUB_OP_QUICK_MOVE = 9
SUB_OP_QUICK_COPY = 10
MODE_UNKNOWN = 0
MODE_PROVIDER = 1
MODE_CONVERTED = 2
MODE_CONVENTIONAL = 3
AUTH_UNKNOWN = 0
AUTH_OTHER = 1
AUTH_MEDIA = 2
AUTH_STORAGE_INTERNAL = 3
AUTH_STORAGE_EXTERNAL = 4
AUTH_DOWNLOADS = 5
AUTH_MTP = 6
ACTION_UNKNOWN = 0
ACTION_OTHER = 1
ACTION_GRID = 2
ACTION_LIST = 3
ACTION_SORT_NAME = 4
ACTION_SORT_DATE = 5
ACTION_SORT_SIZE = 6
ACTION_SORT_TYPE = 7
ACTION_SEARCH = 8
ACTION_SHOW_SIZE = 9
ACTION_HIDE_SIZE = 10
ACTION_SETTINGS = 11
ACTION_COPY_TO = 12
ACTION_MOVE_TO = 13
ACTION_DELETE = 14
ACTION_RENAME = 15
ACTION_CREATE_DIR = 16
ACTION_SELECT_ALL = 17
ACTION_SHARE = 18
ACTION_OPEN = 19
ACTION_SHOW_ADVANCED = 20
ACTION_HIDE_ADVANCED = 21
ACTION_NEW_WINDOW = 22
ACTION_PASTE_CLIPBOARD = 23
ACTION_COPY_CLIPBOARD = 24
ACTION_DRAG_N_DROP = 25
ACTION_DRAG_N_DROP_MULTI_WINDOW = 26
ACTION_CUT_CLIPBOARD = 27
ACTION_COMPRESS = 28
ACTION_EXTRACT_TO = 29
ACTION_VIEW_IN_APPLICATION = 30
ACTION_INSPECTOR = 31
ACTION_SEARCH_CHIP = 32
ACTION_SEARCH_HISTORY = 33
SCOPED_DIR_ACCESS_UNKNOWN = 0
SCOPED_DIR_ACCESS_INVALID_ARGUMENTS = 1
SCOPED_DIR_ACCESS_INVALID_DIRECTORY = 2
SCOPED_DIR_ACCESS_ERROR = 3
SCOPED_DIR_ACCESS_DEPRECATED = 4
TYPE_UNKNOWN = 0
TYPE_CHIP_IMAGES = 1
TYPE_CHIP_AUDIOS = 2
TYPE_CHIP_VIDEOS = 3
TYPE_CHIP_DOCS = 4
TYPE_SEARCH_HISTORY = 5
TYPE_SEARCH_STRING = 6
TYPE_CHIP_LARGE_FILES = 7
TYPE_CHIP_FROM_THIS_WEEK = 8
SEARCH_UNKNOWN = 0
SEARCH_KEYWORD = 1
SEARCH_CHIPS = 2
SEARCH_KEYWORD_N_CHIPS = 3


if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'P\001'
  _LAUNCHACTION._serialized_start=94
  _LAUNCHACTION._serialized_end=218
  _MIMETYPE._serialized_start=221
  _MIMETYPE._serialized_end=417
  _ROOT._serialized_start=420
  _ROOT._serialized_end=677
  _CONTEXTSCOPE._serialized_start=679
  _CONTEXTSCOPE._serialized_end=747
  _PROVIDER._serialized_start=749
  _PROVIDER._serialized_end=825
  _FILEOPERATION._serialized_start=828
  _FILEOPERATION._serialized_end=1491
  _SUBFILEOPERATION._serialized_start=1494
  _SUBFILEOPERATION._serialized_end=1768
  _COPYMOVEOPMODE._serialized_start=1770
  _COPYMOVEOPMODE._serialized_end=1866
  _AUTHORITY._serialized_start=1869
  _AUTHORITY._serialized_end=2018
  _USERACTION._serialized_start=2021
  _USERACTION._serialized_end=2802
  _INVALIDSCOPEDACCESS._serialized_start=2805
  _INVALIDSCOPEDACCESS._serialized_end=3002
  _SEARCHTYPE._serialized_start=3005
  _SEARCHTYPE._serialized_end=3227
  _SEARCHMODE._serialized_start=3229
  _SEARCHMODE._serialized_end=3327
# @@protoc_insertion_point(module_scope)