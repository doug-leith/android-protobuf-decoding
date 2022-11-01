# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: app_measurement.proto3
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import any_pb2 as google_dot_protobuf_dot_any__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x16\x61pp_measurement.proto3\x1a\x19google/protobuf/any.proto\"3\n\tPOST_body\x12&\n\x04\x62ody\x18\x01 \x03(\x0b\x32\x18.FirebaseAnalyticsEvents\"\x9c\x0c\n\x17\x46irebaseAnalyticsEvents\x12\x12\n\nalways_one\x18\x01 \x01(\x05\x12\x33\n\x05\x65vent\x18\x02 \x03(\x0b\x32$.FirebaseAnalyticsEvents.EventParcel\x12:\n\x04user\x18\x03 \x03(\x0b\x32,.FirebaseAnalyticsEvents.UserAttributeParcel\x12\x19\n\x11message_timestamp\x18\x04 \x01(\x03\x12\x17\n\x0f\x65vent_timestamp\x18\x05 \x01(\x03\x12\x1c\n\x14\x62undle_end_timestamp\x18\x06 \x01(\x03\x12!\n\x19last_bundle_end_timestamp\x18\x07 \x01(\x03\x12\x18\n\x10operating_system\x18\x08 \x01(\t\x12 \n\x18operating_system_version\x18\t \x01(\t\x12\x13\n\x0b\x42uild_MODEL\x18\n \x01(\t\x12\x18\n\x10language_country\x18\x0b \x01(\t\x12\t\n\x01\x63\x18\x0c \x01(\x05\x12\x11\n\tapp_store\x18\r \x01(\t\x12\x14\n\x0cpackage_name\x18\x0e \x01(\t\x12\x13\n\x0b\x61pp_version\x18\x10 \x01(\t\x12\x13\n\x0bgmp_version\x18\x11 \x01(\x03\x12\x13\n\x0bgms_version\x18\x12 \x01(\x03\x12\x14\n\x0cgoogle_ad_id\x18\x13 \x01(\t\x12\x10\n\x08no_ad_id\x18\x14 \x01(\x08\x12\x15\n\rappInstanceId\x18\x15 \x01(\t\x12\x15\n\rdev_cert_hash\x18\x16 \x01(\x04\x12\x1f\n\x17\x64\x61ily_conversions_count\x18\x17 \x01(\x05\x12\x1d\n\x15health_monitor_sample\x18\x18 \x01(\t\x12\x12\n\ngmp_app_id\x18\x19 \x01(\t\x12$\n\x1clast_bundle_start_timestamp2\x18\x1a \x01(\x03\x12\x13\n\x0b\x61lways_true\x18\x1c \x01(\x08\x12\x38\n\x0b\x66ilter_list\x18\x1d \x03(\x0b\x32#.FirebaseAnalyticsEvents.FilterList\x12\x1c\n\x14\x66irebase_instance_id\x18\x1e \x01(\t\x12\x17\n\x0f\x61pp_version_int\x18\x1f \x01(\x05\x12\x16\n\x0e\x61ndroid_id_str\x18\" \x01(\t\x12\x16\n\x0e\x63onfig_version\x18# \x01(\x03\x12\x16\n\x0e\x61ndroid_id_int\x18$ \x01(\x03\x12\x0e\n\x06\x63ookie\x18% \x01(\t\x12\x13\n\x0bretry_count\x18\' \x01(\x05\x12\x14\n\x0c\x61\x64mob_app_id\x18) \x01(\t\x12\x1f\n\x01L\x18, \x01(\x0b\x32\x14.google.protobuf.Any\x12\t\n\x01M\x18- \x03(\r\x12\x18\n\x10\x64ynamite_version\x18. \x01(\x03\x12\t\n\x01O\x18/ \x01(\x03\x12\x15\n\rconsent_state\x18\x34 \x01(\t\x1a\x86\x02\n\x0b\x45ventParcel\x12\x42\n\nevent_info\x18\x01 \x03(\x0b\x32..FirebaseAnalyticsEvents.EventParcel.EventInfo\x12\x12\n\nevent_code\x18\x02 \x01(\t\x12\x17\n\x0f\x65vent_timestamp\x18\x03 \x01(\x03\x12 \n\x18previous_event_timestamp\x18\x04 \x01(\x03\x12\t\n\x01\x66\x18\x05 \x01(\x05\x1aY\n\tEventInfo\x12\x14\n\x0csetting_code\x18\x01 \x01(\t\x12\x10\n\x08\x64\x61ta_str\x18\x02 \x01(\t\x12\x10\n\x08\x64\x61ta_int\x18\x03 \x01(\x03\x12\x12\n\ndata_float\x18\x05 \x01(\x02\x1aq\n\x13UserAttributeParcel\x12\x11\n\ttimestamp\x18\x01 \x01(\x03\x12\x0f\n\x07setting\x18\x02 \x01(\t\x12\x10\n\x08\x64\x61ta_str\x18\x03 \x01(\t\x12\x10\n\x08\x64\x61ta_int\x18\x04 \x01(\x03\x12\x12\n\ndata_float\x18\x06 \x01(\x02\x1al\n\nFilterList\x12\x11\n\tfilter_id\x18\x01 \x01(\x05\x12\x1f\n\x01\x63\x18\x02 \x01(\x0b\x32\x14.google.protobuf.Any\x12\x1f\n\x01\x64\x18\x03 \x01(\x0b\x32\x14.google.protobuf.Any\x12\t\n\x01\x65\x18\x04 \x01(\x08\x62\x06proto3')



_POST_BODY = DESCRIPTOR.message_types_by_name['POST_body']
_FIREBASEANALYTICSEVENTS = DESCRIPTOR.message_types_by_name['FirebaseAnalyticsEvents']
_FIREBASEANALYTICSEVENTS_EVENTPARCEL = _FIREBASEANALYTICSEVENTS.nested_types_by_name['EventParcel']
_FIREBASEANALYTICSEVENTS_EVENTPARCEL_EVENTINFO = _FIREBASEANALYTICSEVENTS_EVENTPARCEL.nested_types_by_name['EventInfo']
_FIREBASEANALYTICSEVENTS_USERATTRIBUTEPARCEL = _FIREBASEANALYTICSEVENTS.nested_types_by_name['UserAttributeParcel']
_FIREBASEANALYTICSEVENTS_FILTERLIST = _FIREBASEANALYTICSEVENTS.nested_types_by_name['FilterList']
POST_body = _reflection.GeneratedProtocolMessageType('POST_body', (_message.Message,), {
  'DESCRIPTOR' : _POST_BODY,
  '__module__' : 'app_measurement.proto3_pb2'
  # @@protoc_insertion_point(class_scope:POST_body)
  })
_sym_db.RegisterMessage(POST_body)

FirebaseAnalyticsEvents = _reflection.GeneratedProtocolMessageType('FirebaseAnalyticsEvents', (_message.Message,), {

  'EventParcel' : _reflection.GeneratedProtocolMessageType('EventParcel', (_message.Message,), {

    'EventInfo' : _reflection.GeneratedProtocolMessageType('EventInfo', (_message.Message,), {
      'DESCRIPTOR' : _FIREBASEANALYTICSEVENTS_EVENTPARCEL_EVENTINFO,
      '__module__' : 'app_measurement.proto3_pb2'
      # @@protoc_insertion_point(class_scope:FirebaseAnalyticsEvents.EventParcel.EventInfo)
      })
    ,
    'DESCRIPTOR' : _FIREBASEANALYTICSEVENTS_EVENTPARCEL,
    '__module__' : 'app_measurement.proto3_pb2'
    # @@protoc_insertion_point(class_scope:FirebaseAnalyticsEvents.EventParcel)
    })
  ,

  'UserAttributeParcel' : _reflection.GeneratedProtocolMessageType('UserAttributeParcel', (_message.Message,), {
    'DESCRIPTOR' : _FIREBASEANALYTICSEVENTS_USERATTRIBUTEPARCEL,
    '__module__' : 'app_measurement.proto3_pb2'
    # @@protoc_insertion_point(class_scope:FirebaseAnalyticsEvents.UserAttributeParcel)
    })
  ,

  'FilterList' : _reflection.GeneratedProtocolMessageType('FilterList', (_message.Message,), {
    'DESCRIPTOR' : _FIREBASEANALYTICSEVENTS_FILTERLIST,
    '__module__' : 'app_measurement.proto3_pb2'
    # @@protoc_insertion_point(class_scope:FirebaseAnalyticsEvents.FilterList)
    })
  ,
  'DESCRIPTOR' : _FIREBASEANALYTICSEVENTS,
  '__module__' : 'app_measurement.proto3_pb2'
  # @@protoc_insertion_point(class_scope:FirebaseAnalyticsEvents)
  })
_sym_db.RegisterMessage(FirebaseAnalyticsEvents)
_sym_db.RegisterMessage(FirebaseAnalyticsEvents.EventParcel)
_sym_db.RegisterMessage(FirebaseAnalyticsEvents.EventParcel.EventInfo)
_sym_db.RegisterMessage(FirebaseAnalyticsEvents.UserAttributeParcel)
_sym_db.RegisterMessage(FirebaseAnalyticsEvents.FilterList)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _POST_BODY._serialized_start=53
  _POST_BODY._serialized_end=104
  _FIREBASEANALYTICSEVENTS._serialized_start=107
  _FIREBASEANALYTICSEVENTS._serialized_end=1671
  _FIREBASEANALYTICSEVENTS_EVENTPARCEL._serialized_start=1184
  _FIREBASEANALYTICSEVENTS_EVENTPARCEL._serialized_end=1446
  _FIREBASEANALYTICSEVENTS_EVENTPARCEL_EVENTINFO._serialized_start=1357
  _FIREBASEANALYTICSEVENTS_EVENTPARCEL_EVENTINFO._serialized_end=1446
  _FIREBASEANALYTICSEVENTS_USERATTRIBUTEPARCEL._serialized_start=1448
  _FIREBASEANALYTICSEVENTS_USERATTRIBUTEPARCEL._serialized_end=1561
  _FIREBASEANALYTICSEVENTS_FILTERLIST._serialized_start=1563
  _FIREBASEANALYTICSEVENTS_FILTERLIST._serialized_end=1671
# @@protoc_insertion_point(module_scope)