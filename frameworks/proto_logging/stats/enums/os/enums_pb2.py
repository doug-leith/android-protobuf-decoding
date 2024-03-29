# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: frameworks/proto_logging/stats/enums/os/enums.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n3frameworks/proto_logging/stats/enums/os/enums.proto\x12\nandroid.os*\xfc\x01\n\x11\x42\x61tteryHealthEnum\x12\x1a\n\x16\x42\x41TTERY_HEALTH_INVALID\x10\x00\x12\x1a\n\x16\x42\x41TTERY_HEALTH_UNKNOWN\x10\x01\x12\x17\n\x13\x42\x41TTERY_HEALTH_GOOD\x10\x02\x12\x1b\n\x17\x42\x41TTERY_HEALTH_OVERHEAT\x10\x03\x12\x17\n\x13\x42\x41TTERY_HEALTH_DEAD\x10\x04\x12\x1f\n\x1b\x42\x41TTERY_HEALTH_OVER_VOLTAGE\x10\x05\x12&\n\"BATTERY_HEALTH_UNSPECIFIED_FAILURE\x10\x06\x12\x17\n\x13\x42\x41TTERY_HEALTH_COLD\x10\x07*\x82\x01\n\x17\x42\x61tteryPluggedStateEnum\x12\x18\n\x14\x42\x41TTERY_PLUGGED_NONE\x10\x00\x12\x16\n\x12\x42\x41TTERY_PLUGGED_AC\x10\x01\x12\x17\n\x13\x42\x41TTERY_PLUGGED_USB\x10\x02\x12\x1c\n\x18\x42\x41TTERY_PLUGGED_WIRELESS\x10\x04*\xc2\x01\n\x11\x42\x61tteryStatusEnum\x12\x1a\n\x16\x42\x41TTERY_STATUS_INVALID\x10\x00\x12\x1a\n\x16\x42\x41TTERY_STATUS_UNKNOWN\x10\x01\x12\x1b\n\x17\x42\x41TTERY_STATUS_CHARGING\x10\x02\x12\x1e\n\x1a\x42\x41TTERY_STATUS_DISCHARGING\x10\x03\x12\x1f\n\x1b\x42\x41TTERY_STATUS_NOT_CHARGING\x10\x04\x12\x17\n\x13\x42\x41TTERY_STATUS_FULL\x10\x05*\xbb\x04\n\x12PowerComponentEnum\x12\x1a\n\x16POWER_COMPONENT_SCREEN\x10\x00\x12\x17\n\x13POWER_COMPONENT_CPU\x10\x01\x12\x1d\n\x19POWER_COMPONENT_BLUETOOTH\x10\x02\x12\x1a\n\x16POWER_COMPONENT_CAMERA\x10\x03\x12\x19\n\x15POWER_COMPONENT_AUDIO\x10\x04\x12\x19\n\x15POWER_COMPONENT_VIDEO\x10\x05\x12\x1e\n\x1aPOWER_COMPONENT_FLASHLIGHT\x10\x06\x12#\n\x1fPOWER_COMPONENT_SYSTEM_SERVICES\x10\x07\x12 \n\x1cPOWER_COMPONENT_MOBILE_RADIO\x10\x08\x12\x1b\n\x17POWER_COMPONENT_SENSORS\x10\t\x12\x18\n\x14POWER_COMPONENT_GNSS\x10\n\x12\x18\n\x14POWER_COMPONENT_WIFI\x10\x0b\x12\x1c\n\x18POWER_COMPONENT_WAKELOCK\x10\x0c\x12\x1a\n\x16POWER_COMPONENT_MEMORY\x10\r\x12\x19\n\x15POWER_COMPONENT_PHONE\x10\x0e\x12#\n\x1fPOWER_COMPONENT_AMBIENT_DISPLAY\x10\x0f\x12\x18\n\x14POWER_COMPONENT_IDLE\x10\x10\x12\x33\n/POWER_COMPONENT_REATTRIBUTED_TO_OTHER_CONSUMERS\x10\x11*\xf1\x02\n\x13TemperatureTypeEnum\x12%\n\x18TEMPERATURE_TYPE_UNKNOWN\x10\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01\x12\x18\n\x14TEMPERATURE_TYPE_CPU\x10\x00\x12\x18\n\x14TEMPERATURE_TYPE_GPU\x10\x01\x12\x1c\n\x18TEMPERATURE_TYPE_BATTERY\x10\x02\x12\x19\n\x15TEMPERATURE_TYPE_SKIN\x10\x03\x12\x1d\n\x19TEMPERATURE_TYPE_USB_PORT\x10\x04\x12$\n TEMPERATURE_TYPE_POWER_AMPLIFIER\x10\x05\x12 \n\x1cTEMPERATURE_TYPE_BCL_VOLTAGE\x10\x06\x12 \n\x1cTEMPERATURE_TYPE_BCL_CURRENT\x10\x07\x12#\n\x1fTEMPERATURE_TYPE_BCL_PERCENTAGE\x10\x08\x12\x18\n\x14TEMPERATURE_TYPE_NPU\x10\t*r\n\x16ThrottlingSeverityEnum\x12\x08\n\x04NONE\x10\x00\x12\t\n\x05LIGHT\x10\x01\x12\x0c\n\x08MODERATE\x10\x02\x12\n\n\x06SEVERE\x10\x03\x12\x0c\n\x08\x43RITICAL\x10\x04\x12\r\n\tEMERGENCY\x10\x05\x12\x0c\n\x08SHUTDOWN\x10\x06*\\\n\x0f\x43oolingTypeEnum\x12\x07\n\x03\x46\x41N\x10\x00\x12\x0b\n\x07\x42\x41TTERY\x10\x01\x12\x07\n\x03\x43PU\x10\x02\x12\x07\n\x03GPU\x10\x03\x12\t\n\x05MODEM\x10\x04\x12\x07\n\x03NPU\x10\x05\x12\r\n\tCOMPONENT\x10\x06*\xce\x01\n\x11WakeLockLevelEnum\x12\x15\n\x11PARTIAL_WAKE_LOCK\x10\x01\x12\x1c\n\x14SCREEN_DIM_WAKE_LOCK\x10\x06\x1a\x02\x08\x01\x12\x1f\n\x17SCREEN_BRIGHT_WAKE_LOCK\x10\n\x1a\x02\x08\x01\x12\x16\n\x0e\x46ULL_WAKE_LOCK\x10\x1a\x1a\x02\x08\x01\x12\"\n\x1ePROXIMITY_SCREEN_OFF_WAKE_LOCK\x10 \x12\x12\n\x0e\x44OZE_WAKE_LOCK\x10@\x12\x13\n\x0e\x44RAW_WAKE_LOCK\x10\x80\x01\x42\x10\x42\x0cOsProtoEnumsP\x01')

_BATTERYHEALTHENUM = DESCRIPTOR.enum_types_by_name['BatteryHealthEnum']
BatteryHealthEnum = enum_type_wrapper.EnumTypeWrapper(_BATTERYHEALTHENUM)
_BATTERYPLUGGEDSTATEENUM = DESCRIPTOR.enum_types_by_name['BatteryPluggedStateEnum']
BatteryPluggedStateEnum = enum_type_wrapper.EnumTypeWrapper(_BATTERYPLUGGEDSTATEENUM)
_BATTERYSTATUSENUM = DESCRIPTOR.enum_types_by_name['BatteryStatusEnum']
BatteryStatusEnum = enum_type_wrapper.EnumTypeWrapper(_BATTERYSTATUSENUM)
_POWERCOMPONENTENUM = DESCRIPTOR.enum_types_by_name['PowerComponentEnum']
PowerComponentEnum = enum_type_wrapper.EnumTypeWrapper(_POWERCOMPONENTENUM)
_TEMPERATURETYPEENUM = DESCRIPTOR.enum_types_by_name['TemperatureTypeEnum']
TemperatureTypeEnum = enum_type_wrapper.EnumTypeWrapper(_TEMPERATURETYPEENUM)
_THROTTLINGSEVERITYENUM = DESCRIPTOR.enum_types_by_name['ThrottlingSeverityEnum']
ThrottlingSeverityEnum = enum_type_wrapper.EnumTypeWrapper(_THROTTLINGSEVERITYENUM)
_COOLINGTYPEENUM = DESCRIPTOR.enum_types_by_name['CoolingTypeEnum']
CoolingTypeEnum = enum_type_wrapper.EnumTypeWrapper(_COOLINGTYPEENUM)
_WAKELOCKLEVELENUM = DESCRIPTOR.enum_types_by_name['WakeLockLevelEnum']
WakeLockLevelEnum = enum_type_wrapper.EnumTypeWrapper(_WAKELOCKLEVELENUM)
BATTERY_HEALTH_INVALID = 0
BATTERY_HEALTH_UNKNOWN = 1
BATTERY_HEALTH_GOOD = 2
BATTERY_HEALTH_OVERHEAT = 3
BATTERY_HEALTH_DEAD = 4
BATTERY_HEALTH_OVER_VOLTAGE = 5
BATTERY_HEALTH_UNSPECIFIED_FAILURE = 6
BATTERY_HEALTH_COLD = 7
BATTERY_PLUGGED_NONE = 0
BATTERY_PLUGGED_AC = 1
BATTERY_PLUGGED_USB = 2
BATTERY_PLUGGED_WIRELESS = 4
BATTERY_STATUS_INVALID = 0
BATTERY_STATUS_UNKNOWN = 1
BATTERY_STATUS_CHARGING = 2
BATTERY_STATUS_DISCHARGING = 3
BATTERY_STATUS_NOT_CHARGING = 4
BATTERY_STATUS_FULL = 5
POWER_COMPONENT_SCREEN = 0
POWER_COMPONENT_CPU = 1
POWER_COMPONENT_BLUETOOTH = 2
POWER_COMPONENT_CAMERA = 3
POWER_COMPONENT_AUDIO = 4
POWER_COMPONENT_VIDEO = 5
POWER_COMPONENT_FLASHLIGHT = 6
POWER_COMPONENT_SYSTEM_SERVICES = 7
POWER_COMPONENT_MOBILE_RADIO = 8
POWER_COMPONENT_SENSORS = 9
POWER_COMPONENT_GNSS = 10
POWER_COMPONENT_WIFI = 11
POWER_COMPONENT_WAKELOCK = 12
POWER_COMPONENT_MEMORY = 13
POWER_COMPONENT_PHONE = 14
POWER_COMPONENT_AMBIENT_DISPLAY = 15
POWER_COMPONENT_IDLE = 16
POWER_COMPONENT_REATTRIBUTED_TO_OTHER_CONSUMERS = 17
TEMPERATURE_TYPE_UNKNOWN = -1
TEMPERATURE_TYPE_CPU = 0
TEMPERATURE_TYPE_GPU = 1
TEMPERATURE_TYPE_BATTERY = 2
TEMPERATURE_TYPE_SKIN = 3
TEMPERATURE_TYPE_USB_PORT = 4
TEMPERATURE_TYPE_POWER_AMPLIFIER = 5
TEMPERATURE_TYPE_BCL_VOLTAGE = 6
TEMPERATURE_TYPE_BCL_CURRENT = 7
TEMPERATURE_TYPE_BCL_PERCENTAGE = 8
TEMPERATURE_TYPE_NPU = 9
NONE = 0
LIGHT = 1
MODERATE = 2
SEVERE = 3
CRITICAL = 4
EMERGENCY = 5
SHUTDOWN = 6
FAN = 0
BATTERY = 1
CPU = 2
GPU = 3
MODEM = 4
NPU = 5
COMPONENT = 6
PARTIAL_WAKE_LOCK = 1
SCREEN_DIM_WAKE_LOCK = 6
SCREEN_BRIGHT_WAKE_LOCK = 10
FULL_WAKE_LOCK = 26
PROXIMITY_SCREEN_OFF_WAKE_LOCK = 32
DOZE_WAKE_LOCK = 64
DRAW_WAKE_LOCK = 128


if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'B\014OsProtoEnumsP\001'
  _WAKELOCKLEVELENUM.values_by_name["SCREEN_DIM_WAKE_LOCK"]._options = None
  _WAKELOCKLEVELENUM.values_by_name["SCREEN_DIM_WAKE_LOCK"]._serialized_options = b'\010\001'
  _WAKELOCKLEVELENUM.values_by_name["SCREEN_BRIGHT_WAKE_LOCK"]._options = None
  _WAKELOCKLEVELENUM.values_by_name["SCREEN_BRIGHT_WAKE_LOCK"]._serialized_options = b'\010\001'
  _WAKELOCKLEVELENUM.values_by_name["FULL_WAKE_LOCK"]._options = None
  _WAKELOCKLEVELENUM.values_by_name["FULL_WAKE_LOCK"]._serialized_options = b'\010\001'
  _BATTERYHEALTHENUM._serialized_start=68
  _BATTERYHEALTHENUM._serialized_end=320
  _BATTERYPLUGGEDSTATEENUM._serialized_start=323
  _BATTERYPLUGGEDSTATEENUM._serialized_end=453
  _BATTERYSTATUSENUM._serialized_start=456
  _BATTERYSTATUSENUM._serialized_end=650
  _POWERCOMPONENTENUM._serialized_start=653
  _POWERCOMPONENTENUM._serialized_end=1224
  _TEMPERATURETYPEENUM._serialized_start=1227
  _TEMPERATURETYPEENUM._serialized_end=1596
  _THROTTLINGSEVERITYENUM._serialized_start=1598
  _THROTTLINGSEVERITYENUM._serialized_end=1712
  _COOLINGTYPEENUM._serialized_start=1714
  _COOLINGTYPEENUM._serialized_end=1806
  _WAKELOCKLEVELENUM._serialized_start=1809
  _WAKELOCKLEVELENUM._serialized_end=2015
# @@protoc_insertion_point(module_scope)
