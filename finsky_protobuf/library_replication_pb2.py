# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: library_replication.proto
# Protobuf Python Version: 4.25.1
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import library_update_proto_pb2 as library__update__proto__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x19library_replication.proto\x12\x12LibraryReplication\x1a\x1alibrary_update_proto.proto\"\x86\x01\n\x1aLibraryReplicationResponse\x12\x31\n\x06update\x18\x01 \x03(\x0b\x32!.LibraryUpdateProto.LibraryUpdate\x12\x35\n-autoAcquireFreeAppIfHigherVersionAvailableTag\x18\x02 \x03(\t\"Y\n\x19LibraryReplicationRequest\x12<\n\x0clibraryState\x18\x01 \x03(\x0b\x32&.LibraryUpdateProto.ClientLibraryStateB6\n com.google.android.finsky.protosB\x12LibraryReplication')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'library_replication_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  _globals['DESCRIPTOR']._options = None
  _globals['DESCRIPTOR']._serialized_options = b'\n com.google.android.finsky.protosB\022LibraryReplication'
  _globals['_LIBRARYREPLICATIONRESPONSE']._serialized_start=78
  _globals['_LIBRARYREPLICATIONRESPONSE']._serialized_end=212
  _globals['_LIBRARYREPLICATIONREQUEST']._serialized_start=214
  _globals['_LIBRARYREPLICATIONREQUEST']._serialized_end=303
# @@protoc_insertion_point(module_scope)
