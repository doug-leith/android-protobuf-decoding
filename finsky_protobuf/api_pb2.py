# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: api.proto
# Protobuf Python Version: 4.25.1
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import request_context_outer_class_pb2 as request__context__outer__class__pb2
import ui_error_outer_class_pb2 as ui__error__outer__class__pb2
import form_field_reference_outer_class_pb2 as form__field__reference__outer__class__pb2
import image_with_caption_outer_class_pb2 as image__with__caption__outer__class__pb2
import info_message_outer_class_pb2 as info__message__outer__class__pb2
import customer_form_outer_class_pb2 as customer__form__outer__class__pb2
import response_context_outer_class_pb2 as response__context__outer__class__pb2
import instrument_form_outer_class_pb2 as instrument__form__outer__class__pb2
import credit_card_pb2 as credit__card__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\tapi.proto\x12\x03\x41pi\x1a!request_context_outer_class.proto\x1a\x1aui_error_outer_class.proto\x1a&form_field_reference_outer_class.proto\x1a$image_with_caption_outer_class.proto\x1a\x1einfo_message_outer_class.proto\x1a\x1f\x63ustomer_form_outer_class.proto\x1a\"response_context_outer_class.proto\x1a!instrument_form_outer_class.proto\x1a\x11\x63redit_card.proto\"\x9c\x01\n\x12InitializeResponse\x12\x1e\n\x0binitialPage\x18\x04 \x01(\x0b\x32\t.Api.Page\x12)\n\x05\x65rror\x18\x05 \x01(\x0b\x32\x1a.UiErrorOuterClass.UiError\x12;\n\x07\x63ontext\x18\x06 \x01(\x0b\x32*.ResponseContextOuterClass.ResponseContext\"\xb9\x01\n\x1bInstrumentManagerParameters\x12\x0e\n\x06\x61\x63tion\x18\x01 \x01(\x05\x12\x13\n\x0b\x63\x64pBrokerId\x18\x02 \x01(\t\x12\x14\n\x0c\x63urrencyCode\x18\x03 \x01(\t\x12\x0f\n\x07\x63ountry\x18\x04 \x01(\t\x12\x14\n\x0cinstrumentId\x18\x05 \x01(\t\x12\x14\n\x0clanguageCode\x18\x06 \x01(\t\x12\"\n\x1a\x61llowCreditCardCameraInput\x18\x07 \x01(\x08\"\xc1\x01\n\x12RefreshPageRequest\x12\x39\n\x07\x63ontext\x18\x01 \x01(\x0b\x32(.RequestContextOuterClass.RequestContext\x12!\n\tpageValue\x18\x02 \x01(\x0b\x32\x0e.Api.PageValue\x12M\n\x13refreshTriggerField\x18\x03 \x01(\x0b\x32\x30.FormFieldReferenceOuterClass.FormFieldReference\"\xc3\x01\n\x10SavePageResponse\x12\x14\n\x0cinstrumentId\x18\x01 \x01(\t\x12\x1b\n\x08nextPage\x18\x02 \x01(\x0b\x32\t.Api.Page\x12)\n\x05\x65rror\x18\x03 \x01(\x0b\x32\x1a.UiErrorOuterClass.UiError\x12;\n\x07\x63ontext\x18\x04 \x01(\x0b\x32*.ResponseContextOuterClass.ResponseContext\x12\x14\n\x0c\x66lowComplete\x18\x05 \x01(\x08\"\xa5\x01\n\x0fSavePageRequest\x12\x39\n\x07\x63ontext\x18\x01 \x01(\x0b\x32(.RequestContextOuterClass.RequestContext\x12\x34\n\nparameters\x18\x02 \x01(\x0b\x32 .Api.InstrumentManagerParameters\x12!\n\tpageValue\x18\x04 \x01(\x0b\x32\x0e.Api.PageValue\"*\n\x10\x43lientParameters\x12\x16\n\x0etitleIconStyle\x18\x03 \x01(\x05\"\xe5\x01\n\tPageValue\x12>\n\x0bnewCustomer\x18\x01 \x01(\x0b\x32).CustomerFormOuterClass.CustomerFormValue\x12\x44\n\rnewInstrument\x18\x02 \x01(\x0b\x32-.InstrumentFormOuterClass.InstrumentFormValue\x12R\n\x1bnewCreditCardExpirationDate\x18\x03 \x01(\x0b\x32-.CreditCard.CreditCardExpirationDateFormValue\"\x9a\x01\n\x13RefreshPageResponse\x12)\n\x05\x65rror\x18\x01 \x01(\x0b\x32\x1a.UiErrorOuterClass.UiError\x12;\n\x07\x63ontext\x18\x02 \x01(\x0b\x32*.ResponseContextOuterClass.ResponseContext\x12\x1b\n\x08nextPage\x18\x03 \x01(\x0b\x32\t.Api.Page\"\x97\x04\n\x04Page\x12:\n\x0c\x63ustomerForm\x18\x01 \x01(\x0b\x32$.CustomerFormOuterClass.CustomerForm\x12@\n\x0einstrumentForm\x18\x02 \x01(\x0b\x32(.InstrumentFormOuterClass.InstrumentForm\x12N\n\x1c\x63reditCardExpirationDateForm\x18\x03 \x01(\x0b\x32(.CreditCard.CreditCardExpirationDateForm\x12\r\n\x05title\x18\x04 \x01(\t\x12\x18\n\x10submitButtonText\x18\x05 \x01(\t\x12M\n\x13refreshTriggerField\x18\x08 \x03(\x0b\x32\x30.FormFieldReferenceOuterClass.FormFieldReference\x12\x1a\n\x12progressDialogText\x18\t \x01(\t\x12:\n\x0etopInfoMessage\x18\n \x01(\x0b\x32\".InfoMessageOuterClass.InfoMessage\x12@\n\ntitleImage\x18\x0b \x01(\x0b\x32,.ImageWithCaptionOuterClass.ImageWithCaption\x12\x1b\n\x13progressDialogTitle\x18\x0c \x01(\t\x12\x12\n\nautoSubmit\x18\r \x01(\x08\x42L\nEcom.google.commerce.payments.orchestration.proto.ui.instrumentmanagerB\x03\x41pi')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'api_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  _globals['DESCRIPTOR']._options = None
  _globals['DESCRIPTOR']._serialized_options = b'\nEcom.google.commerce.payments.orchestration.proto.ui.instrumentmanagerB\003Api'
  _globals['_INITIALIZERESPONSE']._serialized_start=315
  _globals['_INITIALIZERESPONSE']._serialized_end=471
  _globals['_INSTRUMENTMANAGERPARAMETERS']._serialized_start=474
  _globals['_INSTRUMENTMANAGERPARAMETERS']._serialized_end=659
  _globals['_REFRESHPAGEREQUEST']._serialized_start=662
  _globals['_REFRESHPAGEREQUEST']._serialized_end=855
  _globals['_SAVEPAGERESPONSE']._serialized_start=858
  _globals['_SAVEPAGERESPONSE']._serialized_end=1053
  _globals['_SAVEPAGEREQUEST']._serialized_start=1056
  _globals['_SAVEPAGEREQUEST']._serialized_end=1221
  _globals['_CLIENTPARAMETERS']._serialized_start=1223
  _globals['_CLIENTPARAMETERS']._serialized_end=1265
  _globals['_PAGEVALUE']._serialized_start=1268
  _globals['_PAGEVALUE']._serialized_end=1497
  _globals['_REFRESHPAGERESPONSE']._serialized_start=1500
  _globals['_REFRESHPAGERESPONSE']._serialized_end=1654
  _globals['_PAGE']._serialized_start=1657
  _globals['_PAGE']._serialized_end=2192
# @@protoc_insertion_point(module_scope)
