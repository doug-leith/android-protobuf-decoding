# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: search_suggest.proto
# Protobuf Python Version: 4.25.1
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import document_v2_pb2 as document__v2__pb2
import doc_annotations_pb2 as doc__annotations__pb2
import common_pb2 as common__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x14search_suggest.proto\x12\rSearchSuggest\x1a\x11\x64ocument_v2.proto\x1a\x15\x64oc_annotations.proto\x1a\x0c\x63ommon.proto\"d\n\rNavSuggestion\x12\r\n\x05\x64ocId\x18\x01 \x01(\t\x12\x11\n\timageBlob\x18\x02 \x01(\x0c\x12\x1c\n\x05image\x18\x03 \x01(\x0b\x32\r.Common.Image\x12\x13\n\x0b\x64\x65scription\x18\x04 \x01(\t\"\xfd\x01\n\nSuggestion\x12\x0c\n\x04type\x18\x01 \x01(\x05\x12\x16\n\x0esuggestedQuery\x18\x02 \x01(\t\x12\x33\n\rnavSuggestion\x18\x03 \x01(\x0b\x32\x1c.SearchSuggest.NavSuggestion\x12\x18\n\x10serverLogsCookie\x18\x04 \x01(\x0c\x12\x1c\n\x05image\x18\x05 \x01(\x0b\x32\r.Common.Image\x12\x13\n\x0b\x64isplayText\x18\x06 \x01(\t\x12\"\n\x04link\x18\x07 \x01(\x0b\x32\x14.DocAnnotations.Link\x12#\n\x08\x64ocument\x18\x08 \x01(\x0b\x32\x11.DocumentV2.DocV2\"`\n\x15SearchSuggestResponse\x12-\n\nsuggestion\x18\x01 \x03(\x0b\x32\x19.SearchSuggest.Suggestion\x12\x18\n\x10serverLogsCookie\x18\x02 \x01(\x0c\x42\x31\n com.google.android.finsky.protosB\rSearchSuggest')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'search_suggest_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  _globals['DESCRIPTOR']._options = None
  _globals['DESCRIPTOR']._serialized_options = b'\n com.google.android.finsky.protosB\rSearchSuggest'
  _globals['_NAVSUGGESTION']._serialized_start=95
  _globals['_NAVSUGGESTION']._serialized_end=195
  _globals['_SUGGESTION']._serialized_start=198
  _globals['_SUGGESTION']._serialized_end=451
  _globals['_SEARCHSUGGESTRESPONSE']._serialized_start=453
  _globals['_SEARCHSUGGESTRESPONSE']._serialized_end=549
# @@protoc_insertion_point(module_scope)
