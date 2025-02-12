# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: firebase_logbatch.proto
# Protobuf Python Version: 5.29.2
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
    2,
    '',
    'firebase_logbatch.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x17\x66irebase_logbatch.proto\"\xcb\x0f\n\x0c\x46irelogEvent\x12\x36\n\x0f\x61pplicationInfo\x18\x01 \x01(\x0b\x32\x1d.FirelogEvent.ApplicationInfo\x12.\n\x0btraceMetric\x18\x02 \x01(\x0b\x32\x19.FirelogEvent.TraceMetric\x12@\n\x14networkRequestMetric\x18\x03 \x01(\x0b\x32\".FirelogEvent.NetworkRequestMetric\x12.\n\x0bgaugeMetric\x18\x04 \x01(\x0b\x32\x19.FirelogEvent.GaugeMetric\x12\x32\n\rtransportInfo\x18\x05 \x01(\x0b\x32\x1b.FirelogEvent.TransportInfo\x1a.\n\x10\x43ustomAttributes\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t\x1a!\n\x0cPerfSessions\x12\x11\n\tsessionID\x18\x01 \x01(\t\x1a\xae\x02\n\x0f\x41pplicationInfo\x12\x13\n\x0bgoogleAppId\x18\x01 \x01(\t\x12\x15\n\rappInstanceId\x18\x02 \x01(\t\x12\x44\n\x0e\x61ndroidAppInfo\x18\x03 \x01(\x0b\x32,.FirelogEvent.ApplicationInfo.AndroidAppInfo\x12\x1f\n\x17\x61pplicationProcessState\x18\x05 \x01(\x05\x12\x38\n\x10\x63ustomAttributes\x18\x06 \x01(\x0b\x32\x1e.FirelogEvent.CustomAttributes\x1aN\n\x0e\x41ndroidAppInfo\x12\x13\n\x0bpackageName\x18\x01 \x01(\t\x12\x12\n\nsdkVersion\x18\x02 \x01(\t\x12\x13\n\x0bversionName\x18\x03 \x01(\t\x1a\xa4\x02\n\x0bTraceMetric\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x0e\n\x06isAuto\x18\x02 \x01(\x08\x12\x19\n\x11\x63lientStartTimeis\x18\x04 \x01(\x03\x12\x12\n\ndurationUs\x18\x05 \x01(\x03\x12\x34\n\x08\x63ounters\x18\x06 \x01(\x0b\x32\".FirelogEvent.TraceMetric.Counters\x12\x38\n\x10\x63ustomAttributes\x18\x08 \x01(\x0b\x32\x1e.FirelogEvent.CustomAttributes\x12\x30\n\x0cperfSessions\x18\t \x01(\x0b\x32\x1a.FirelogEvent.PerfSessions\x1a&\n\x08\x43ounters\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x03\x1a\xf3\x04\n\x14NetworkRequestMetric\x12\x0b\n\x03url\x18\x01 \x01(\t\x12\x41\n\nhttpMethod\x18\x02 \x01(\x0e\x32-.FirelogEvent.NetworkRequestMetric.HttpMethod\x12\x1b\n\x13requestPayloadBytes\x18\x03 \x01(\x03\x12\x1c\n\x14responsePayloadBytes\x18\x04 \x01(\x03\x12\x18\n\x10httpResponseCode\x18\x05 \x01(\x05\x12\x1b\n\x13responseContentType\x18\x06 \x01(\t\x12\x19\n\x11\x63lientStartTimeUs\x18\x07 \x01(\x03\x12 \n\x18timeToRequestCompletedUs\x18\x08 \x01(\x03\x12!\n\x19timeToResponseInitiatedUs\x18\t \x01(\x03\x12!\n\x19timeToResponseCompletedUs\x18\n \x01(\x03\x12 \n\x18networkClientErrorReason\x18\x0b \x01(\x05\x12\x38\n\x10\x63ustomAttributes\x18\x0c \x01(\x0b\x32\x1e.FirelogEvent.CustomAttributes\x12\x30\n\x0cperfSessions\x18\r \x01(\x0b\x32\x1a.FirelogEvent.PerfSessions\"\x87\x01\n\nHttpMethod\x12\x17\n\x13HTTP_METHOD_UNKNOWN\x10\x00\x12\x07\n\x03GET\x10\x01\x12\x07\n\x03PUT\x10\x02\x12\x08\n\x04POST\x10\x03\x12\n\n\x06\x44\x45LETE\x10\x04\x12\x08\n\x04HEAD\x10\x05\x12\t\n\x05PATCH\x10\x06\x12\x0b\n\x07OPTIONS\x10\x07\x12\t\n\x05TRACE\x10\x08\x12\x0b\n\x07\x43ONNECT\x10\t\x1a\xdd\x02\n\x0bGaugeMetric\x12\x11\n\tsessionId\x18\x01 \x01(\t\x12\x46\n\x11\x63puMetricReadings\x18\x02 \x01(\x0b\x32+.FirelogEvent.GaugeMetric.CpuMetricReadings\x12N\n\x15\x61ndroidMemoryReadings\x18\x04 \x01(\x0b\x32/.FirelogEvent.GaugeMetric.AndroidMemoryReadings\x1aS\n\x11\x43puMetricReadings\x12\x14\n\x0c\x63lientTimeUs\x18\x01 \x01(\x03\x12\x12\n\nuserTimeUs\x18\x02 \x01(\x03\x12\x14\n\x0csystemTimeUs\x18\x03 \x01(\x03\x1aN\n\x15\x41ndroidMemoryReadings\x12\x14\n\x0c\x63lientTimeUs\x18\x01 \x01(\x03\x12\x1f\n\x17usedAppJavaHeapMemoryKb\x18\x02 \x01(\x05\x1a,\n\rTransportInfo\x12\x1b\n\x13\x64ispatchDestination\x18\x01 \x01(\x05')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'firebase_logbatch_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_FIRELOGEVENT']._serialized_start=28
  _globals['_FIRELOGEVENT']._serialized_end=2023
  _globals['_FIRELOGEVENT_CUSTOMATTRIBUTES']._serialized_start=314
  _globals['_FIRELOGEVENT_CUSTOMATTRIBUTES']._serialized_end=360
  _globals['_FIRELOGEVENT_PERFSESSIONS']._serialized_start=362
  _globals['_FIRELOGEVENT_PERFSESSIONS']._serialized_end=395
  _globals['_FIRELOGEVENT_APPLICATIONINFO']._serialized_start=398
  _globals['_FIRELOGEVENT_APPLICATIONINFO']._serialized_end=700
  _globals['_FIRELOGEVENT_APPLICATIONINFO_ANDROIDAPPINFO']._serialized_start=622
  _globals['_FIRELOGEVENT_APPLICATIONINFO_ANDROIDAPPINFO']._serialized_end=700
  _globals['_FIRELOGEVENT_TRACEMETRIC']._serialized_start=703
  _globals['_FIRELOGEVENT_TRACEMETRIC']._serialized_end=995
  _globals['_FIRELOGEVENT_TRACEMETRIC_COUNTERS']._serialized_start=957
  _globals['_FIRELOGEVENT_TRACEMETRIC_COUNTERS']._serialized_end=995
  _globals['_FIRELOGEVENT_NETWORKREQUESTMETRIC']._serialized_start=998
  _globals['_FIRELOGEVENT_NETWORKREQUESTMETRIC']._serialized_end=1625
  _globals['_FIRELOGEVENT_NETWORKREQUESTMETRIC_HTTPMETHOD']._serialized_start=1490
  _globals['_FIRELOGEVENT_NETWORKREQUESTMETRIC_HTTPMETHOD']._serialized_end=1625
  _globals['_FIRELOGEVENT_GAUGEMETRIC']._serialized_start=1628
  _globals['_FIRELOGEVENT_GAUGEMETRIC']._serialized_end=1977
  _globals['_FIRELOGEVENT_GAUGEMETRIC_CPUMETRICREADINGS']._serialized_start=1814
  _globals['_FIRELOGEVENT_GAUGEMETRIC_CPUMETRICREADINGS']._serialized_end=1897
  _globals['_FIRELOGEVENT_GAUGEMETRIC_ANDROIDMEMORYREADINGS']._serialized_start=1899
  _globals['_FIRELOGEVENT_GAUGEMETRIC_ANDROIDMEMORYREADINGS']._serialized_end=1977
  _globals['_FIRELOGEVENT_TRANSPORTINFO']._serialized_start=1979
  _globals['_FIRELOGEVENT_TRANSPORTINFO']._serialized_end=2023
# @@protoc_insertion_point(module_scope)
