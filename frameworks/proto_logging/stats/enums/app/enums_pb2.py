# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: frameworks/proto_logging/stats/enums/app/enums.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n4frameworks/proto_logging/stats/enums/app/enums.proto\x12\x0b\x61ndroid.app*\xda\x01\n\x17\x41ppTransitionReasonEnum\x12!\n\x1d\x41PP_TRANSITION_REASON_UNKNOWN\x10\x00\x12 \n\x1c\x41PP_TRANSITION_SPLASH_SCREEN\x10\x01\x12 \n\x1c\x41PP_TRANSITION_WINDOWS_DRAWN\x10\x02\x12\x1a\n\x16\x41PP_TRANSITION_TIMEOUT\x10\x03\x12\x1b\n\x17\x41PP_TRANSITION_SNAPSHOT\x10\x04\x12\x1f\n\x1b\x41PP_TRANSITION_RECENTS_ANIM\x10\x05*\x9c\x06\n\x10ProcessStateEnum\x12#\n\x1ePROCESS_STATE_UNKNOWN_TO_PROTO\x10\xe6\x07\x12\x1a\n\x15PROCESS_STATE_UNKNOWN\x10\xe7\x07\x12\x1d\n\x18PROCESS_STATE_PERSISTENT\x10\xe8\x07\x12 \n\x1bPROCESS_STATE_PERSISTENT_UI\x10\xe9\x07\x12\x16\n\x11PROCESS_STATE_TOP\x10\xea\x07\x12\x1c\n\x17PROCESS_STATE_BOUND_TOP\x10\xfc\x07\x12%\n PROCESS_STATE_FOREGROUND_SERVICE\x10\xeb\x07\x12+\n&PROCESS_STATE_BOUND_FOREGROUND_SERVICE\x10\xec\x07\x12\'\n\"PROCESS_STATE_IMPORTANT_FOREGROUND\x10\xed\x07\x12\'\n\"PROCESS_STATE_IMPORTANT_BACKGROUND\x10\xee\x07\x12\'\n\"PROCESS_STATE_TRANSIENT_BACKGROUND\x10\xef\x07\x12\x19\n\x14PROCESS_STATE_BACKUP\x10\xf0\x07\x12\x1a\n\x15PROCESS_STATE_SERVICE\x10\xf1\x07\x12\x1b\n\x16PROCESS_STATE_RECEIVER\x10\xf2\x07\x12\x1f\n\x1aPROCESS_STATE_TOP_SLEEPING\x10\xf3\x07\x12\x1f\n\x1aPROCESS_STATE_HEAVY_WEIGHT\x10\xf4\x07\x12\x17\n\x12PROCESS_STATE_HOME\x10\xf5\x07\x12 \n\x1bPROCESS_STATE_LAST_ACTIVITY\x10\xf6\x07\x12\"\n\x1dPROCESS_STATE_CACHED_ACTIVITY\x10\xf7\x07\x12)\n$PROCESS_STATE_CACHED_ACTIVITY_CLIENT\x10\xf8\x07\x12 \n\x1bPROCESS_STATE_CACHED_RECENT\x10\xf9\x07\x12\x1f\n\x1aPROCESS_STATE_CACHED_EMPTY\x10\xfa\x07\x12\x1e\n\x19PROCESS_STATE_NONEXISTENT\x10\xfb\x07*\xc9\x1b\n\tAppOpEnum\x12\x18\n\x0b\x41PP_OP_NONE\x10\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01\x12\x1a\n\x16\x41PP_OP_COARSE_LOCATION\x10\x00\x12\x18\n\x14\x41PP_OP_FINE_LOCATION\x10\x01\x12\x0e\n\nAPP_OP_GPS\x10\x02\x12\x12\n\x0e\x41PP_OP_VIBRATE\x10\x03\x12\x18\n\x14\x41PP_OP_READ_CONTACTS\x10\x04\x12\x19\n\x15\x41PP_OP_WRITE_CONTACTS\x10\x05\x12\x18\n\x14\x41PP_OP_READ_CALL_LOG\x10\x06\x12\x19\n\x15\x41PP_OP_WRITE_CALL_LOG\x10\x07\x12\x18\n\x14\x41PP_OP_READ_CALENDAR\x10\x08\x12\x19\n\x15\x41PP_OP_WRITE_CALENDAR\x10\t\x12\x14\n\x10\x41PP_OP_WIFI_SCAN\x10\n\x12\x1c\n\x18\x41PP_OP_POST_NOTIFICATION\x10\x0b\x12\x1c\n\x18\x41PP_OP_NEIGHBORING_CELLS\x10\x0c\x12\x15\n\x11\x41PP_OP_CALL_PHONE\x10\r\x12\x13\n\x0f\x41PP_OP_READ_SMS\x10\x0e\x12\x14\n\x10\x41PP_OP_WRITE_SMS\x10\x0f\x12\x16\n\x12\x41PP_OP_RECEIVE_SMS\x10\x10\x12 \n\x1c\x41PP_OP_RECEIVE_EMERGENCY_SMS\x10\x11\x12\x16\n\x12\x41PP_OP_RECEIVE_MMS\x10\x12\x12\x1b\n\x17\x41PP_OP_RECEIVE_WAP_PUSH\x10\x13\x12\x13\n\x0f\x41PP_OP_SEND_SMS\x10\x14\x12\x17\n\x13\x41PP_OP_READ_ICC_SMS\x10\x15\x12\x18\n\x14\x41PP_OP_WRITE_ICC_SMS\x10\x16\x12\x19\n\x15\x41PP_OP_WRITE_SETTINGS\x10\x17\x12\x1e\n\x1a\x41PP_OP_SYSTEM_ALERT_WINDOW\x10\x18\x12\x1f\n\x1b\x41PP_OP_ACCESS_NOTIFICATIONS\x10\x19\x12\x11\n\rAPP_OP_CAMERA\x10\x1a\x12\x17\n\x13\x41PP_OP_RECORD_AUDIO\x10\x1b\x12\x15\n\x11\x41PP_OP_PLAY_AUDIO\x10\x1c\x12\x19\n\x15\x41PP_OP_READ_CLIPBOARD\x10\x1d\x12\x1a\n\x16\x41PP_OP_WRITE_CLIPBOARD\x10\x1e\x12\x1d\n\x19\x41PP_OP_TAKE_MEDIA_BUTTONS\x10\x1f\x12\x1b\n\x17\x41PP_OP_TAKE_AUDIO_FOCUS\x10 \x12\x1e\n\x1a\x41PP_OP_AUDIO_MASTER_VOLUME\x10!\x12\x1d\n\x19\x41PP_OP_AUDIO_VOICE_VOLUME\x10\"\x12\x1c\n\x18\x41PP_OP_AUDIO_RING_VOLUME\x10#\x12\x1d\n\x19\x41PP_OP_AUDIO_MEDIA_VOLUME\x10$\x12\x1d\n\x19\x41PP_OP_AUDIO_ALARM_VOLUME\x10%\x12$\n APP_OP_AUDIO_NOTIFICATION_VOLUME\x10&\x12!\n\x1d\x41PP_OP_AUDIO_BLUETOOTH_VOLUME\x10\'\x12\x14\n\x10\x41PP_OP_WAKE_LOCK\x10(\x12\x1b\n\x17\x41PP_OP_MONITOR_LOCATION\x10)\x12&\n\"APP_OP_MONITOR_HIGH_POWER_LOCATION\x10*\x12\x1a\n\x16\x41PP_OP_GET_USAGE_STATS\x10+\x12\x1a\n\x16\x41PP_OP_MUTE_MICROPHONE\x10,\x12\x17\n\x13\x41PP_OP_TOAST_WINDOW\x10-\x12\x18\n\x14\x41PP_OP_PROJECT_MEDIA\x10.\x12\x17\n\x13\x41PP_OP_ACTIVATE_VPN\x10/\x12\x1a\n\x16\x41PP_OP_WRITE_WALLPAPER\x10\x30\x12\x1b\n\x17\x41PP_OP_ASSIST_STRUCTURE\x10\x31\x12\x1c\n\x18\x41PP_OP_ASSIST_SCREENSHOT\x10\x32\x12\x1b\n\x17\x41PP_OP_READ_PHONE_STATE\x10\x33\x12\x18\n\x14\x41PP_OP_ADD_VOICEMAIL\x10\x34\x12\x12\n\x0e\x41PP_OP_USE_SIP\x10\x35\x12!\n\x1d\x41PP_OP_PROCESS_OUTGOING_CALLS\x10\x36\x12\x1a\n\x16\x41PP_OP_USE_FINGERPRINT\x10\x37\x12\x17\n\x13\x41PP_OP_BODY_SENSORS\x10\x38\x12\x1f\n\x1b\x41PP_OP_READ_CELL_BROADCASTS\x10\x39\x12\x18\n\x14\x41PP_OP_MOCK_LOCATION\x10:\x12 \n\x1c\x41PP_OP_READ_EXTERNAL_STORAGE\x10;\x12!\n\x1d\x41PP_OP_WRITE_EXTERNAL_STORAGE\x10<\x12\x19\n\x15\x41PP_OP_TURN_SCREEN_ON\x10=\x12\x17\n\x13\x41PP_OP_GET_ACCOUNTS\x10>\x12\x1c\n\x18\x41PP_OP_RUN_IN_BACKGROUND\x10?\x12%\n!APP_OP_AUDIO_ACCESSIBILITY_VOLUME\x10@\x12\x1d\n\x19\x41PP_OP_READ_PHONE_NUMBERS\x10\x41\x12#\n\x1f\x41PP_OP_REQUEST_INSTALL_PACKAGES\x10\x42\x12\x1d\n\x19\x41PP_OP_PICTURE_IN_PICTURE\x10\x43\x12\'\n#APP_OP_INSTANT_APP_START_FOREGROUND\x10\x44\x12\x1d\n\x19\x41PP_OP_ANSWER_PHONE_CALLS\x10\x45\x12 \n\x1c\x41PP_OP_RUN_ANY_IN_BACKGROUND\x10\x46\x12\x1c\n\x18\x41PP_OP_CHANGE_WIFI_STATE\x10G\x12\"\n\x1e\x41PP_OP_REQUEST_DELETE_PACKAGES\x10H\x12%\n!APP_OP_BIND_ACCESSIBILITY_SERVICE\x10I\x12\x1a\n\x16\x41PP_OP_ACCEPT_HANDOVER\x10J\x12\x1f\n\x1b\x41PP_OP_MANAGE_IPSEC_TUNNELS\x10K\x12\x1b\n\x17\x41PP_OP_START_FOREGROUND\x10L\x12\x19\n\x15\x41PP_OP_BLUETOOTH_SCAN\x10M\x12\x18\n\x14\x41PP_OP_USE_BIOMETRIC\x10N\x12\x1f\n\x1b\x41PP_OP_ACTIVITY_RECOGNITION\x10O\x12%\n!APP_OP_SMS_FINANCIAL_TRANSACTIONS\x10P\x12\x1b\n\x17\x41PP_OP_READ_MEDIA_AUDIO\x10Q\x12\x1c\n\x18\x41PP_OP_WRITE_MEDIA_AUDIO\x10R\x12\x1b\n\x17\x41PP_OP_READ_MEDIA_VIDEO\x10S\x12\x1c\n\x18\x41PP_OP_WRITE_MEDIA_VIDEO\x10T\x12\x1c\n\x18\x41PP_OP_READ_MEDIA_IMAGES\x10U\x12\x1d\n\x19\x41PP_OP_WRITE_MEDIA_IMAGES\x10V\x12\x19\n\x15\x41PP_OP_LEGACY_STORAGE\x10W\x12\x1f\n\x1b\x41PP_OP_ACCESS_ACCESSIBILITY\x10X\x12\"\n\x1e\x41PP_OP_READ_DEVICE_IDENTIFIERS\x10Y\x12 \n\x1c\x41PP_OP_ACCESS_MEDIA_LOCATION\x10Z\x12\x1d\n\x19\x41PP_OP_QUERY_ALL_PACKAGES\x10[\x12\"\n\x1e\x41PP_OP_MANAGE_EXTERNAL_STORAGE\x10\\\x12#\n\x1f\x41PP_OP_INTERACT_ACROSS_PROFILES\x10]\x12 \n\x1c\x41PP_OP_ACTIVATE_PLATFORM_VPN\x10^\x12\x1d\n\x19\x41PP_OP_LOADER_USAGE_STATS\x10_\x12\x1b\n\x13\x41PP_OP_DEPRECATED_1\x10`\x1a\x02\x08\x01\x12,\n(APP_OP_AUTO_REVOKE_PERMISSIONS_IF_UNUSED\x10\x61\x12+\n\'APP_OP_AUTO_REVOKE_MANAGED_BY_INSTALLER\x10\x62\x12\x1e\n\x1a\x41PP_OP_NO_ISOLATED_STORAGE\x10\x63\x12 \n\x1c\x41PP_OP_PHONE_CALL_MICROPHONE\x10\x64\x12\x1c\n\x18\x41PP_OP_PHONE_CALL_CAMERA\x10\x65\x12\x1f\n\x1b\x41PP_OP_RECORD_AUDIO_HOTWORD\x10\x66\x12\x1f\n\x1b\x41PP_OP_MANAGE_ONGOING_CALLS\x10g\x12\x1d\n\x19\x41PP_OP_MANAGE_CREDENTIALS\x10h\x12.\n*APP_OP_USE_ICC_AUTH_WITH_DEVICE_IDENTIFIER\x10i\x12\x1e\n\x1a\x41PP_OP_RECORD_AUDIO_OUTPUT\x10j\x12\x1f\n\x1b\x41PP_OP_SCHEDULE_EXACT_ALARM\x10k\x12\x1f\n\x1b\x41PP_OP_FINE_LOCATION_SOURCE\x10l\x12!\n\x1d\x41PP_OP_COARSE_LOCATION_SOURCE\x10m\x12\x17\n\x13\x41PP_OP_MANAGE_MEDIA\x10n\x12\x1c\n\x18\x41PP_OP_BLUETOOTH_CONNECT\x10o\x12\x16\n\x12\x41PP_OP_UWB_RANGING\x10p\x12&\n\"APP_OP_ACTIVITY_RECOGNITION_SOURCE\x10q\x12\x1e\n\x1a\x41PP_OP_BLUETOOTH_ADVERTISE\x10r\x12&\n\"APP_OP_RECORD_INCOMING_PHONE_AUDIO\x10s*\xec\x02\n\x11\x41ppExitReasonCode\x12\x12\n\x0eREASON_UNKNOWN\x10\x00\x12\x14\n\x10REASON_EXIT_SELF\x10\x01\x12\x13\n\x0fREASON_SIGNALED\x10\x02\x12\x15\n\x11REASON_LOW_MEMORY\x10\x03\x12\x10\n\x0cREASON_CRASH\x10\x04\x12\x17\n\x13REASON_CRASH_NATIVE\x10\x05\x12\x0e\n\nREASON_ANR\x10\x06\x12!\n\x1dREASON_INITIALIZATION_FAILURE\x10\x07\x12\x1c\n\x18REASON_PERMISSION_CHANGE\x10\x08\x12#\n\x1fREASON_EXCESSIVE_RESOURCE_USAGE\x10\t\x12\x19\n\x15REASON_USER_REQUESTED\x10\n\x12\x17\n\x13REASON_USER_STOPPED\x10\x0b\x12\x1a\n\x16REASON_DEPENDENCY_DIED\x10\x0c\x12\x10\n\x0cREASON_OTHER\x10\r*\x9c\x05\n\x14\x41ppExitSubReasonCode\x12\x15\n\x11SUBREASON_UNKNOWN\x10\x00\x12\x1f\n\x1bSUBREASON_WAIT_FOR_DEBUGGER\x10\x01\x12\x1d\n\x19SUBREASON_TOO_MANY_CACHED\x10\x02\x12\x1c\n\x18SUBREASON_TOO_MANY_EMPTY\x10\x03\x12\x18\n\x14SUBREASON_TRIM_EMPTY\x10\x04\x12\x1a\n\x16SUBREASON_LARGE_CACHED\x10\x05\x12\x1d\n\x19SUBREASON_MEMORY_PRESSURE\x10\x06\x12\x1b\n\x17SUBREASON_EXCESSIVE_CPU\x10\x07\x12 \n\x1cSUBREASON_SYSTEM_UPDATE_DONE\x10\x08\x12\x19\n\x15SUBREASON_KILL_ALL_FG\x10\t\x12 \n\x1cSUBREASON_KILL_ALL_BG_EXCEPT\x10\n\x12\x16\n\x12SUBREASON_KILL_UID\x10\x0b\x12\x16\n\x12SUBREASON_KILL_PID\x10\x0c\x12\x1b\n\x17SUBREASON_INVALID_START\x10\r\x12\x1b\n\x17SUBREASON_INVALID_STATE\x10\x0e\x12\x1b\n\x17SUBREASON_IMPERCEPTIBLE\x10\x0f\x12\x18\n\x14SUBREASON_REMOVE_LRU\x10\x10\x12!\n\x1dSUBREASON_ISOLATED_NOT_NEEDED\x10\x11\x12,\n(SUBREASON_CACHED_IDLE_FORCED_APP_STANDBY\x10\x12\x12\"\n\x1eSUBREASON_FREEZER_BINDER_IOCTL\x10\x13\x12(\n$SUBREASON_FREEZER_BINDER_TRANSACTION\x10\x14*\xae\x03\n\nImportance\x12\x19\n\x15IMPORTANCE_FOREGROUND\x10\x64\x12!\n\x1dIMPORTANCE_FOREGROUND_SERVICE\x10}\x12#\n\x1eIMPORTANCE_TOP_SLEEPING_PRE_28\x10\x96\x01\x12\x17\n\x12IMPORTANCE_VISIBLE\x10\xc8\x01\x12\"\n\x1dIMPORTANCE_PERCEPTIBLE_PRE_26\x10\x82\x01\x12\x1b\n\x16IMPORTANCE_PERCEPTIBLE\x10\xe6\x01\x12&\n!IMPORTANCE_CANT_SAVE_STATE_PRE_26\x10\xaa\x01\x12\x17\n\x12IMPORTANCE_SERVICE\x10\xac\x02\x12\x1c\n\x17IMPORTANCE_TOP_SLEEPING\x10\xc5\x02\x12\x1f\n\x1aIMPORTANCE_CANT_SAVE_STATE\x10\xde\x02\x12\x16\n\x11IMPORTANCE_CACHED\x10\x90\x03\x12\x1a\n\x15IMPORTANCE_BACKGROUND\x10\x90\x03\x12\x15\n\x10IMPORTANCE_EMPTY\x10\xf4\x03\x12\x14\n\x0fIMPORTANCE_GONE\x10\xe8\x07\x1a\x02\x10\x01\x42\x11\x42\rAppProtoEnumsP\x01')

_APPTRANSITIONREASONENUM = DESCRIPTOR.enum_types_by_name['AppTransitionReasonEnum']
AppTransitionReasonEnum = enum_type_wrapper.EnumTypeWrapper(_APPTRANSITIONREASONENUM)
_PROCESSSTATEENUM = DESCRIPTOR.enum_types_by_name['ProcessStateEnum']
ProcessStateEnum = enum_type_wrapper.EnumTypeWrapper(_PROCESSSTATEENUM)
_APPOPENUM = DESCRIPTOR.enum_types_by_name['AppOpEnum']
AppOpEnum = enum_type_wrapper.EnumTypeWrapper(_APPOPENUM)
_APPEXITREASONCODE = DESCRIPTOR.enum_types_by_name['AppExitReasonCode']
AppExitReasonCode = enum_type_wrapper.EnumTypeWrapper(_APPEXITREASONCODE)
_APPEXITSUBREASONCODE = DESCRIPTOR.enum_types_by_name['AppExitSubReasonCode']
AppExitSubReasonCode = enum_type_wrapper.EnumTypeWrapper(_APPEXITSUBREASONCODE)
_IMPORTANCE = DESCRIPTOR.enum_types_by_name['Importance']
Importance = enum_type_wrapper.EnumTypeWrapper(_IMPORTANCE)
APP_TRANSITION_REASON_UNKNOWN = 0
APP_TRANSITION_SPLASH_SCREEN = 1
APP_TRANSITION_WINDOWS_DRAWN = 2
APP_TRANSITION_TIMEOUT = 3
APP_TRANSITION_SNAPSHOT = 4
APP_TRANSITION_RECENTS_ANIM = 5
PROCESS_STATE_UNKNOWN_TO_PROTO = 998
PROCESS_STATE_UNKNOWN = 999
PROCESS_STATE_PERSISTENT = 1000
PROCESS_STATE_PERSISTENT_UI = 1001
PROCESS_STATE_TOP = 1002
PROCESS_STATE_BOUND_TOP = 1020
PROCESS_STATE_FOREGROUND_SERVICE = 1003
PROCESS_STATE_BOUND_FOREGROUND_SERVICE = 1004
PROCESS_STATE_IMPORTANT_FOREGROUND = 1005
PROCESS_STATE_IMPORTANT_BACKGROUND = 1006
PROCESS_STATE_TRANSIENT_BACKGROUND = 1007
PROCESS_STATE_BACKUP = 1008
PROCESS_STATE_SERVICE = 1009
PROCESS_STATE_RECEIVER = 1010
PROCESS_STATE_TOP_SLEEPING = 1011
PROCESS_STATE_HEAVY_WEIGHT = 1012
PROCESS_STATE_HOME = 1013
PROCESS_STATE_LAST_ACTIVITY = 1014
PROCESS_STATE_CACHED_ACTIVITY = 1015
PROCESS_STATE_CACHED_ACTIVITY_CLIENT = 1016
PROCESS_STATE_CACHED_RECENT = 1017
PROCESS_STATE_CACHED_EMPTY = 1018
PROCESS_STATE_NONEXISTENT = 1019
APP_OP_NONE = -1
APP_OP_COARSE_LOCATION = 0
APP_OP_FINE_LOCATION = 1
APP_OP_GPS = 2
APP_OP_VIBRATE = 3
APP_OP_READ_CONTACTS = 4
APP_OP_WRITE_CONTACTS = 5
APP_OP_READ_CALL_LOG = 6
APP_OP_WRITE_CALL_LOG = 7
APP_OP_READ_CALENDAR = 8
APP_OP_WRITE_CALENDAR = 9
APP_OP_WIFI_SCAN = 10
APP_OP_POST_NOTIFICATION = 11
APP_OP_NEIGHBORING_CELLS = 12
APP_OP_CALL_PHONE = 13
APP_OP_READ_SMS = 14
APP_OP_WRITE_SMS = 15
APP_OP_RECEIVE_SMS = 16
APP_OP_RECEIVE_EMERGENCY_SMS = 17
APP_OP_RECEIVE_MMS = 18
APP_OP_RECEIVE_WAP_PUSH = 19
APP_OP_SEND_SMS = 20
APP_OP_READ_ICC_SMS = 21
APP_OP_WRITE_ICC_SMS = 22
APP_OP_WRITE_SETTINGS = 23
APP_OP_SYSTEM_ALERT_WINDOW = 24
APP_OP_ACCESS_NOTIFICATIONS = 25
APP_OP_CAMERA = 26
APP_OP_RECORD_AUDIO = 27
APP_OP_PLAY_AUDIO = 28
APP_OP_READ_CLIPBOARD = 29
APP_OP_WRITE_CLIPBOARD = 30
APP_OP_TAKE_MEDIA_BUTTONS = 31
APP_OP_TAKE_AUDIO_FOCUS = 32
APP_OP_AUDIO_MASTER_VOLUME = 33
APP_OP_AUDIO_VOICE_VOLUME = 34
APP_OP_AUDIO_RING_VOLUME = 35
APP_OP_AUDIO_MEDIA_VOLUME = 36
APP_OP_AUDIO_ALARM_VOLUME = 37
APP_OP_AUDIO_NOTIFICATION_VOLUME = 38
APP_OP_AUDIO_BLUETOOTH_VOLUME = 39
APP_OP_WAKE_LOCK = 40
APP_OP_MONITOR_LOCATION = 41
APP_OP_MONITOR_HIGH_POWER_LOCATION = 42
APP_OP_GET_USAGE_STATS = 43
APP_OP_MUTE_MICROPHONE = 44
APP_OP_TOAST_WINDOW = 45
APP_OP_PROJECT_MEDIA = 46
APP_OP_ACTIVATE_VPN = 47
APP_OP_WRITE_WALLPAPER = 48
APP_OP_ASSIST_STRUCTURE = 49
APP_OP_ASSIST_SCREENSHOT = 50
APP_OP_READ_PHONE_STATE = 51
APP_OP_ADD_VOICEMAIL = 52
APP_OP_USE_SIP = 53
APP_OP_PROCESS_OUTGOING_CALLS = 54
APP_OP_USE_FINGERPRINT = 55
APP_OP_BODY_SENSORS = 56
APP_OP_READ_CELL_BROADCASTS = 57
APP_OP_MOCK_LOCATION = 58
APP_OP_READ_EXTERNAL_STORAGE = 59
APP_OP_WRITE_EXTERNAL_STORAGE = 60
APP_OP_TURN_SCREEN_ON = 61
APP_OP_GET_ACCOUNTS = 62
APP_OP_RUN_IN_BACKGROUND = 63
APP_OP_AUDIO_ACCESSIBILITY_VOLUME = 64
APP_OP_READ_PHONE_NUMBERS = 65
APP_OP_REQUEST_INSTALL_PACKAGES = 66
APP_OP_PICTURE_IN_PICTURE = 67
APP_OP_INSTANT_APP_START_FOREGROUND = 68
APP_OP_ANSWER_PHONE_CALLS = 69
APP_OP_RUN_ANY_IN_BACKGROUND = 70
APP_OP_CHANGE_WIFI_STATE = 71
APP_OP_REQUEST_DELETE_PACKAGES = 72
APP_OP_BIND_ACCESSIBILITY_SERVICE = 73
APP_OP_ACCEPT_HANDOVER = 74
APP_OP_MANAGE_IPSEC_TUNNELS = 75
APP_OP_START_FOREGROUND = 76
APP_OP_BLUETOOTH_SCAN = 77
APP_OP_USE_BIOMETRIC = 78
APP_OP_ACTIVITY_RECOGNITION = 79
APP_OP_SMS_FINANCIAL_TRANSACTIONS = 80
APP_OP_READ_MEDIA_AUDIO = 81
APP_OP_WRITE_MEDIA_AUDIO = 82
APP_OP_READ_MEDIA_VIDEO = 83
APP_OP_WRITE_MEDIA_VIDEO = 84
APP_OP_READ_MEDIA_IMAGES = 85
APP_OP_WRITE_MEDIA_IMAGES = 86
APP_OP_LEGACY_STORAGE = 87
APP_OP_ACCESS_ACCESSIBILITY = 88
APP_OP_READ_DEVICE_IDENTIFIERS = 89
APP_OP_ACCESS_MEDIA_LOCATION = 90
APP_OP_QUERY_ALL_PACKAGES = 91
APP_OP_MANAGE_EXTERNAL_STORAGE = 92
APP_OP_INTERACT_ACROSS_PROFILES = 93
APP_OP_ACTIVATE_PLATFORM_VPN = 94
APP_OP_LOADER_USAGE_STATS = 95
APP_OP_DEPRECATED_1 = 96
APP_OP_AUTO_REVOKE_PERMISSIONS_IF_UNUSED = 97
APP_OP_AUTO_REVOKE_MANAGED_BY_INSTALLER = 98
APP_OP_NO_ISOLATED_STORAGE = 99
APP_OP_PHONE_CALL_MICROPHONE = 100
APP_OP_PHONE_CALL_CAMERA = 101
APP_OP_RECORD_AUDIO_HOTWORD = 102
APP_OP_MANAGE_ONGOING_CALLS = 103
APP_OP_MANAGE_CREDENTIALS = 104
APP_OP_USE_ICC_AUTH_WITH_DEVICE_IDENTIFIER = 105
APP_OP_RECORD_AUDIO_OUTPUT = 106
APP_OP_SCHEDULE_EXACT_ALARM = 107
APP_OP_FINE_LOCATION_SOURCE = 108
APP_OP_COARSE_LOCATION_SOURCE = 109
APP_OP_MANAGE_MEDIA = 110
APP_OP_BLUETOOTH_CONNECT = 111
APP_OP_UWB_RANGING = 112
APP_OP_ACTIVITY_RECOGNITION_SOURCE = 113
APP_OP_BLUETOOTH_ADVERTISE = 114
APP_OP_RECORD_INCOMING_PHONE_AUDIO = 115
REASON_UNKNOWN = 0
REASON_EXIT_SELF = 1
REASON_SIGNALED = 2
REASON_LOW_MEMORY = 3
REASON_CRASH = 4
REASON_CRASH_NATIVE = 5
REASON_ANR = 6
REASON_INITIALIZATION_FAILURE = 7
REASON_PERMISSION_CHANGE = 8
REASON_EXCESSIVE_RESOURCE_USAGE = 9
REASON_USER_REQUESTED = 10
REASON_USER_STOPPED = 11
REASON_DEPENDENCY_DIED = 12
REASON_OTHER = 13
SUBREASON_UNKNOWN = 0
SUBREASON_WAIT_FOR_DEBUGGER = 1
SUBREASON_TOO_MANY_CACHED = 2
SUBREASON_TOO_MANY_EMPTY = 3
SUBREASON_TRIM_EMPTY = 4
SUBREASON_LARGE_CACHED = 5
SUBREASON_MEMORY_PRESSURE = 6
SUBREASON_EXCESSIVE_CPU = 7
SUBREASON_SYSTEM_UPDATE_DONE = 8
SUBREASON_KILL_ALL_FG = 9
SUBREASON_KILL_ALL_BG_EXCEPT = 10
SUBREASON_KILL_UID = 11
SUBREASON_KILL_PID = 12
SUBREASON_INVALID_START = 13
SUBREASON_INVALID_STATE = 14
SUBREASON_IMPERCEPTIBLE = 15
SUBREASON_REMOVE_LRU = 16
SUBREASON_ISOLATED_NOT_NEEDED = 17
SUBREASON_CACHED_IDLE_FORCED_APP_STANDBY = 18
SUBREASON_FREEZER_BINDER_IOCTL = 19
SUBREASON_FREEZER_BINDER_TRANSACTION = 20
IMPORTANCE_FOREGROUND = 100
IMPORTANCE_FOREGROUND_SERVICE = 125
IMPORTANCE_TOP_SLEEPING_PRE_28 = 150
IMPORTANCE_VISIBLE = 200
IMPORTANCE_PERCEPTIBLE_PRE_26 = 130
IMPORTANCE_PERCEPTIBLE = 230
IMPORTANCE_CANT_SAVE_STATE_PRE_26 = 170
IMPORTANCE_SERVICE = 300
IMPORTANCE_TOP_SLEEPING = 325
IMPORTANCE_CANT_SAVE_STATE = 350
IMPORTANCE_CACHED = 400
IMPORTANCE_BACKGROUND = 400
IMPORTANCE_EMPTY = 500
IMPORTANCE_GONE = 1000


if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'B\rAppProtoEnumsP\001'
  _APPOPENUM.values_by_name["APP_OP_DEPRECATED_1"]._options = None
  _APPOPENUM.values_by_name["APP_OP_DEPRECATED_1"]._serialized_options = b'\010\001'
  _IMPORTANCE._options = None
  _IMPORTANCE._serialized_options = b'\020\001'
  _APPTRANSITIONREASONENUM._serialized_start=70
  _APPTRANSITIONREASONENUM._serialized_end=288
  _PROCESSSTATEENUM._serialized_start=291
  _PROCESSSTATEENUM._serialized_end=1087
  _APPOPENUM._serialized_start=1090
  _APPOPENUM._serialized_end=4619
  _APPEXITREASONCODE._serialized_start=4622
  _APPEXITREASONCODE._serialized_end=4986
  _APPEXITSUBREASONCODE._serialized_start=4989
  _APPEXITSUBREASONCODE._serialized_end=5657
  _IMPORTANCE._serialized_start=5660
  _IMPORTANCE._serialized_end=6090
# @@protoc_insertion_point(module_scope)