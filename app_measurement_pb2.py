# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: app_measurement.proto3
# Protobuf Python Version: 5.29.3
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    5,
    29,
    3,
    '',
    'app_measurement.proto3'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import any_pb2 as google_dot_protobuf_dot_any__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x16\x61pp_measurement.proto3\x1a\x19google/protobuf/any.proto\"3\n\tPOST_body\x12&\n\x04\x62ody\x18\x01 \x03(\x0b\x32\x18.FirebaseAnalyticsEvents\"\xcd\x14\n\x17\x46irebaseAnalyticsEvents\x12\x18\n\x10protocol_version\x18\x01 \x01(\x05\x12\x33\n\x05\x65vent\x18\x02 \x03(\x0b\x32$.FirebaseAnalyticsEvents.EventParcel\x12:\n\x04user\x18\x03 \x03(\x0b\x32,.FirebaseAnalyticsEvents.UserAttributeParcel\x12\x1f\n\x17upload_timestamp_millis\x18\x04 \x01(\x03\x12\x17\n\x0f\x65vent_timestamp\x18\x05 \x01(\x03\x12\x1c\n\x14\x62undle_end_timestamp\x18\x06 \x01(\x03\x12%\n\x1dprevious_bundle_end_timestamp\x18\x07 \x01(\x03\x12\x18\n\x10operating_system\x18\x08 \x01(\t\x12 \n\x18operating_system_version\x18\t \x01(\t\x12\x14\n\x0c\x64\x65vice_model\x18\n \x01(\t\x12\x1d\n\x15user_default_language\x18\x0b \x01(\t\x12\x18\n\x10time_zone_offset\x18\x0c \x01(\x05\x12\x11\n\tapp_store\x18\r \x01(\t\x12\x14\n\x0cpackage_name\x18\x0e \x01(\t\x12\x13\n\x0b\x61pp_version\x18\x10 \x01(\t\x12\x13\n\x0bgmp_version\x18\x11 \x01(\x03\x12\x1d\n\x15uploading_gmp_version\x18\x12 \x01(\x03\x12\x14\n\x0cgoogle_ad_id\x18\x13 \x01(\t\x12\x1b\n\x13limited_ad_tracking\x18\x14 \x01(\x08\x12\x15\n\rappInstanceId\x18\x15 \x01(\t\x12\x15\n\rdev_cert_hash\x18\x16 \x01(\x04\x12\x1f\n\x17\x64\x61ily_conversions_count\x18\x17 \x01(\x05\x12\x1d\n\x15health_monitor_sample\x18\x18 \x01(\t\x12\x12\n\ngmp_app_id\x18\x19 \x01(\t\x12(\n previous_bundle_start_timestamp2\x18\x1a \x01(\x03\x12\x16\n\x0eservice_upload\x18\x1c \x01(\x08\x12@\n\x0b\x66ilter_list\x18\x1d \x03(\x0b\x32+.FirebaseAnalyticsEvents.AudienceMembership\x12\x1c\n\x14\x66irebase_instance_id\x18\x1e \x01(\t\x12\x17\n\x0f\x61pp_version_int\x18\x1f \x01(\x05\x12\x16\n\x0e\x61ndroid_id_str\x18\" \x01(\t\x12\x16\n\x0e\x63onfig_version\x18# \x01(\x03\x12\x16\n\x0e\x61ndroid_id_int\x18$ \x01(\x03\x12\x0e\n\x06\x63ookie\x18% \x01(\t\x12\x13\n\x0bretry_count\x18\' \x01(\x05\x12\x14\n\x0c\x61\x64mob_app_id\x18) \x01(\t\x12\x1f\n\x01L\x18, \x01(\x0b\x32\x14.google.protobuf.Any\x12\t\n\x01M\x18- \x03(\r\x12\x18\n\x10\x64ynamite_version\x18. \x01(\x03\x12\t\n\x01O\x18/ \x01(\x03\x12\x15\n\rconsent_state\x18\x34 \x01(\t\x12\x1f\n\x17session_stitching_token\x18? \x01(\t\x12\x16\n\x0egoogle_signals\x18@ \x01(\t\x12\x19\n\x11target_os_version\x18\x43 \x01(\x03\x12\x1b\n\x13\x63onsent_diagnostics\x18G \x01(\t\x12\x15\n\ris_dma_region\x18H \x01(\x08\x12\x1e\n\x16\x63ore_platform_services\x18I \x01(\t\x12\x1b\n\x13\x61\x64_services_version\x18J \x01(\x05\x12_\n\x1e\x61ttribution_eligibility_status\x18L \x01(\x0b\x32\x37.FirebaseAnalyticsEvents.Attribution_eligibility_status\x12\x16\n\x0e\x64\x65livery_index\x18M \x01(\x05\x12\x43\n\x10\x61\x64_campaign_info\x18O \x01(\x0b\x32).FirebaseAnalyticsEvents.Ad_campaign_info\x1a\x86\x02\n\x0b\x45ventParcel\x12\x42\n\nevent_info\x18\x01 \x03(\x0b\x32..FirebaseAnalyticsEvents.EventParcel.EventInfo\x12\x12\n\nevent_code\x18\x02 \x01(\t\x12\x17\n\x0f\x65vent_timestamp\x18\x03 \x01(\x03\x12 \n\x18previous_event_timestamp\x18\x04 \x01(\x03\x12\t\n\x01\x66\x18\x05 \x01(\x05\x1aY\n\tEventInfo\x12\x14\n\x0csetting_code\x18\x01 \x01(\t\x12\x10\n\x08\x64\x61ta_str\x18\x02 \x01(\t\x12\x10\n\x08\x64\x61ta_int\x18\x03 \x01(\x03\x12\x12\n\ndata_float\x18\x05 \x01(\x02\x1a\x95\x01\n\x13UserAttributeParcel\x12\x1c\n\x14set_timestamp_millos\x18\x01 \x01(\x03\x12\x0c\n\x04name\x18\x02 \x01(\t\x12\x14\n\x0cstring_value\x18\x03 \x01(\t\x12\x11\n\tint_value\x18\x04 \x01(\x03\x12\x13\n\x0b\x66loat_value\x18\x05 \x01(\x02\x12\x14\n\x0c\x64ouble_value\x18\x06 \x01(\x01\x1a\x98\x01\n\x12\x41udienceMembership\x12\x13\n\x0b\x61udience_id\x18\x01 \x01(\x05\x12*\n\x0c\x63urrent_data\x18\x02 \x01(\x0b\x32\x14.google.protobuf.Any\x12+\n\rprevious_data\x18\x03 \x01(\x0b\x32\x14.google.protobuf.Any\x12\x14\n\x0cnew_audience\x18\x04 \x01(\x08\x1a\x80\x02\n\x1e\x41ttribution_eligibility_status\x12\x10\n\x08\x65ligible\x18\x01 \x01(\x08\x12\x33\n+no_access_adservices_attribution_permission\x18\x02 \x01(\x08\x12\r\n\x05pre_r\x18\x03 \x01(\x08\x12\x1c\n\x14r_extensions_too_old\x18\x04 \x01(\x08\x12$\n\x1c\x61\x64services_extension_too_old\x18\x05 \x01(\x08\x12\x1e\n\x16\x61\x64_storage_not_allowed\x18\x06 \x01(\x08\x12$\n\x1cmeasurement_manager_disabled\x18\x07 \x01(\x08\x1a\x8d\x02\n\x10\x41\x64_campaign_info\x12\x17\n\x0f\x64\x65\x65p_link_gclid\x18\x01 \x01(\t\x12\x18\n\x10\x64\x65\x65p_link_gbraid\x18\x02 \x01(\t\x12\x1c\n\x14\x64\x65\x65p_link_gad_source\x18\x03 \x01(\t\x12 \n\x18\x64\x65\x65p_link_session_millis\x18\x04 \x01(\x03\x12\x1d\n\x15market_referrer_gclid\x18\x05 \x01(\t\x12\x1d\n\x15market_referrer_gbrai\x18\x06 \x01(\t\x12\"\n\x1amarket_referrer_gad_source\x18\x07 \x01(\t\x12$\n\x1cmarket_referrer_click_millis\x18\x08 \x01(\x03\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'app_measurement.proto3_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_POST_BODY']._serialized_start=53
  _globals['_POST_BODY']._serialized_end=104
  _globals['_FIREBASEANALYTICSEVENTS']._serialized_start=107
  _globals['_FIREBASEANALYTICSEVENTS']._serialized_end=2744
  _globals['_FIREBASEANALYTICSEVENTS_EVENTPARCEL']._serialized_start=1644
  _globals['_FIREBASEANALYTICSEVENTS_EVENTPARCEL']._serialized_end=1906
  _globals['_FIREBASEANALYTICSEVENTS_EVENTPARCEL_EVENTINFO']._serialized_start=1817
  _globals['_FIREBASEANALYTICSEVENTS_EVENTPARCEL_EVENTINFO']._serialized_end=1906
  _globals['_FIREBASEANALYTICSEVENTS_USERATTRIBUTEPARCEL']._serialized_start=1909
  _globals['_FIREBASEANALYTICSEVENTS_USERATTRIBUTEPARCEL']._serialized_end=2058
  _globals['_FIREBASEANALYTICSEVENTS_AUDIENCEMEMBERSHIP']._serialized_start=2061
  _globals['_FIREBASEANALYTICSEVENTS_AUDIENCEMEMBERSHIP']._serialized_end=2213
  _globals['_FIREBASEANALYTICSEVENTS_ATTRIBUTION_ELIGIBILITY_STATUS']._serialized_start=2216
  _globals['_FIREBASEANALYTICSEVENTS_ATTRIBUTION_ELIGIBILITY_STATUS']._serialized_end=2472
  _globals['_FIREBASEANALYTICSEVENTS_AD_CAMPAIGN_INFO']._serialized_start=2475
  _globals['_FIREBASEANALYTICSEVENTS_AD_CAMPAIGN_INFO']._serialized_end=2744
# @@protoc_insertion_point(module_scope)
