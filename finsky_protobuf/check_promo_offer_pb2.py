# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: check_promo_offer.proto
# Protobuf Python Version: 4.25.1
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import common_pb2 as common__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x17\x63heck_promo_offer.proto\x12\x0f\x43heckPromoOffer\x1a\x0c\x63ommon.proto\"_\n\x12RedeemedPromoOffer\x12\x12\n\nheaderText\x18\x01 \x01(\t\x12\x17\n\x0f\x64\x65scriptionHtml\x18\x02 \x01(\t\x12\x1c\n\x05image\x18\x03 \x01(\x0b\x32\r.Common.Image\"[\n\x13\x41vailablePromoOffer\x12\x44\n\x12\x61\x64\x64\x43reditCardOffer\x18\x01 \x01(\x0b\x32(.CheckPromoOffer.AddCreditCardPromoOffer\"\xd3\x01\n\x17\x41\x64\x64\x43reditCardPromoOffer\x12\x12\n\nheaderText\x18\x01 \x01(\t\x12\x17\n\x0f\x64\x65scriptionHtml\x18\x02 \x01(\t\x12\x1c\n\x05image\x18\x03 \x01(\x0b\x32\r.Common.Image\x12\x1c\n\x14introductoryTextHtml\x18\x04 \x01(\t\x12\x12\n\nofferTitle\x18\x05 \x01(\t\x12\x1b\n\x13noActionDescription\x18\x06 \x01(\t\x12\x1e\n\x16termsAndConditionsHtml\x18\x07 \x01(\t\"\xd5\x01\n\x17\x43heckPromoOfferResponse\x12<\n\x0e\x61vailableOffer\x18\x01 \x03(\x0b\x32$.CheckPromoOffer.AvailablePromoOffer\x12:\n\rredeemedOffer\x18\x02 \x01(\x0b\x32#.CheckPromoOffer.RedeemedPromoOffer\x12\x1d\n\x15\x63heckoutTokenRequired\x18\x03 \x01(\x08\x12!\n\x19\x61vailablePromoOfferStatus\x18\x04 \x01(\x05\x42\x33\n com.google.android.finsky.protosB\x0f\x43heckPromoOffer')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'check_promo_offer_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  _globals['DESCRIPTOR']._options = None
  _globals['DESCRIPTOR']._serialized_options = b'\n com.google.android.finsky.protosB\017CheckPromoOffer'
  _globals['_REDEEMEDPROMOOFFER']._serialized_start=58
  _globals['_REDEEMEDPROMOOFFER']._serialized_end=153
  _globals['_AVAILABLEPROMOOFFER']._serialized_start=155
  _globals['_AVAILABLEPROMOOFFER']._serialized_end=246
  _globals['_ADDCREDITCARDPROMOOFFER']._serialized_start=249
  _globals['_ADDCREDITCARDPROMOOFFER']._serialized_end=460
  _globals['_CHECKPROMOOFFERRESPONSE']._serialized_start=463
  _globals['_CHECKPROMOOFFERRESPONSE']._serialized_end=676
# @@protoc_insertion_point(module_scope)
