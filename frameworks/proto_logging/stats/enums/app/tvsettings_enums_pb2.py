# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: frameworks/proto_logging/stats/enums/app/tvsettings_enums.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n?frameworks/proto_logging/stats/enums/app/tvsettings_enums.proto\x12\x16\x61ndroid.app.tvsettings*\xaf\x01\n\x06\x41\x63tion\x12\x12\n\x0e\x41\x43TION_UNKNOWN\x10\x00\x12\x10\n\x0cPAGE_FOCUSED\x10\x01\x12\x12\n\x0e\x45NTRY_SELECTED\x10\x02\x12\x15\n\x11TOGGLE_INTERACTED\x10\x03\x12\x18\n\x14PAGE_FOCUSED_FORWARD\x10\x04\x12\x19\n\x15PAGE_FOCUSED_BACKWARD\x10\x05\x12\x0e\n\nTOGGLED_ON\x10\x06\x12\x0f\n\x0bTOGGLED_OFF\x10\x07*\xebl\n\x06ItemId\x12\x0b\n\x07UNKNOWN\x10\x00\x12\x14\n\x10TV_SETTINGS_ROOT\x10\x01\x12\x18\n\x14PAGE_CLASSIC_DEFAULT\x10\x02\x12\x16\n\x12PAGE_SLICE_DEFAULT\x10\x03\x12\x11\n\rENTRY_DEFAULT\x10\x04\x12\x16\n\x12SUGGESTED_SETTINGS\x10\x10\x12\x12\n\x0eQUICK_SETTINGS\x10\x11\x12\x0f\n\x07NETWORK\x10\x80\x80\x80\x88\x01\x12\x1b\n\x13NETWORK_WIFI_ON_OFF\x10\x80\x80\xc0\x88\x01\x12\x17\n\x0fNETWORK_AP_INFO\x10\x80\x80\x80\x89\x01\x12&\n\x1eNETWORK_AP_INFO_PROXY_SETTINGS\x10\x80\x80\x84\x89\x01\x12#\n\x1bNETWORK_AP_INFO_IP_SETTINGS\x10\x80\x80\x88\x89\x01\x12&\n\x1eNETWORK_AP_INFO_FORGET_NETWORK\x10\x80\x80\x8c\x89\x01\x12 \n\x18NETWORK_NOT_CONNECTED_AP\x10\x80\x80\xc0\x89\x01\x12\x17\n\x0fNETWORK_SEE_ALL\x10\x80\x80\x80\x8a\x01\x12\x19\n\x11NETWORK_SEE_FEWER\x10\x80\x80\xc0\x8a\x01\x12\x1f\n\x17NETWORK_ADD_NEW_NETWORK\x10\x80\x80\x80\x8b\x01\x12(\n NETWORK_ALWAYS_SCANNING_NETWORKS\x10\x80\x80\xc0\x8b\x01\x12\'\n\x1fNETWORK_ETHERNET_PROXY_SETTINGS\x10\x80\x80\x80\x8c\x01\x12$\n\x1cNETWORK_ETHERNET_IP_SETTINGS\x10\x80\x80\xc0\x8c\x01\x12\x15\n\rACCOUNT_SLICE\x10\x80\x80\x80\x90\x01\x12!\n\x19\x41\x43\x43OUNT_SLICE_REG_ACCOUNT\x10\x80\x80\xc0\x90\x01\x12*\n\"ACCOUNT_SLICE_REG_ACCOUNT_SERVICES\x10\x80\x80\xc4\x90\x01\x12)\n!ACCOUNT_SLICE_REG_ACCOUNT_PAYMENT\x10\x80\x80\xc8\x90\x01\x12\x30\n(ACCOUNT_SLICE_REG_ACCOUNT_PAYMENT_REAUTH\x10\x80\xa0\xc8\x90\x01\x12\x37\n/ACCOUNT_SLICE_REG_ACCOUNT_PAYMENT_REAUTH_ALWAYS\x10\x80\xa2\xc8\x90\x01\x12\x37\n/ACCOUNT_SLICE_REG_ACCOUNT_PAYMENT_REAUTH_30MINS\x10\x80\xa4\xc8\x90\x01\x12\x36\n.ACCOUNT_SLICE_REG_ACCOUNT_PAYMENT_REAUTH_NEVER\x10\x80\xa6\xc8\x90\x01\x12+\n#ACCOUNT_SLICE_REG_ACCOUNT_ASSISTANT\x10\x80\x80\xcc\x90\x01\x12\x37\n/ACCOUNT_SLICE_REG_ACCOUNT_ASSISTANT_SAFE_SEARCH\x10\x80\xa0\xcc\x90\x01\x12;\n3ACCOUNT_SLICE_REG_ACCOUNT_ASSISTANT_BLOCK_OFFENSIVE\x10\x80\xc0\xcc\x90\x01\x12;\n3ACCOUNT_SLICE_REG_ACCOUNT_ASSISTANT_SEARCHABLE_APPS\x10\x80\xe0\xcc\x90\x01\x12<\n4ACCOUNT_SLICE_REG_ACCOUNT_ASSISTANT_PERSONAL_RESULTS\x10\x80\x80\xcd\x90\x01\x12\x30\n(ACCOUNT_SLICE_REG_ACCOUNT_APPS_ONLY_MODE\x10\x80\x80\xd0\x90\x01\x12(\n ACCOUNT_SLICE_REG_ACCOUNT_REMOVE\x10\x80\x80\xe8\x90\x01\x12!\n\x19\x41\x43\x43OUNT_SLICE_ADD_ACCOUNT\x10\x80\x80\x80\x95\x01\x12\x17\n\x0f\x41\x43\x43OUNT_CLASSIC\x10\x80\x80\x80\x98\x01\x12#\n\x1b\x41\x43\x43OUNT_CLASSIC_REG_ACCOUNT\x10\x80\x80\xc0\x98\x01\x12,\n$ACCOUNT_CLASSIC_REG_ACCOUNT_SYNC_NOW\x10\x80\x80\xc4\x98\x01\x12\x32\n*ACCOUNT_CLASSIC_REG_ACCOUNT_REMOVE_ACCOUNT\x10\x80\x80\xc8\x98\x01\x12\x31\n)ACCOUNT_CLASSIC_REG_ACCOUNT_SYNC_CALENDAR\x10\x80\x80\xcc\x98\x01\x12\x31\n)ACCOUNT_CLASSIC_REG_ACCOUNT_SYNC_CONTACTS\x10\x80\x80\xd0\x98\x01\x12-\n%ACCOUNT_CLASSIC_REG_ACCOUNT_SYNC_GPMT\x10\x80\x80\xd4\x98\x01\x12,\n$ACCOUNT_CLASSIC_REG_ACCOUNT_SYNC_GPM\x10\x80\x80\xd8\x98\x01\x12/\n\'ACCOUNT_CLASSIC_REG_ACCOUNT_SYNC_PEOPLE\x10\x80\x80\xdc\x98\x01\x12#\n\x1b\x41\x43\x43OUNT_CLASSIC_ADD_ACCOUNT\x10\x80\x80\x80\x9d\x01\x12\x0f\n\x07PRIVACY\x10\x80\x80\x80\xa0\x01\x12\x18\n\x10PRIVACY_LOCATION\x10\x80\x80\xc0\xa0\x01\x12\x1f\n\x17PRIVACY_LOCATION_STATUS\x10\x80\x80\xc4\xa0\x01\x12(\n PRIVACY_LOCATION_STATUS_USE_WIFI\x10\x80\xa0\xc4\xa0\x01\x12#\n\x1bPRIVACY_LOCATION_STATUS_OFF\x10\x80\xc0\xc4\xa0\x01\x12\x31\n)PRIVACY_LOCATION_ALWAYS_SCANNING_NETWORKS\x10\x80\x80\xc8\xa0\x01\x12&\n\x1ePRIVACY_LOCATION_REQUESTED_APP\x10\x80\x80\xcc\xa0\x01\x12\x1b\n\x13PRIVACY_DIAGNOSTICS\x10\x80\x80\x80\xa1\x01\x12\"\n\x1aPRIVACY_DIAGNOSTICS_ON_OFF\x10\x80\x80\x84\xa1\x01\x12\x13\n\x0bPRIVACY_ADS\x10\x80\x80\xc0\xa1\x01\x12\x1f\n\x17PRIVACY_ADS_RESET_AD_ID\x10\x80\x80\xc4\xa1\x01\x12+\n#PRIVACY_ADS_OPT_OUT_PERSONALIZATION\x10\x80\x80\xc8\xa1\x01\x12!\n\x19PRIVACY_ADS_ADS_BY_GOOGLE\x10\x80\x80\xcc\xa1\x01\x12\x15\n\rDISPLAY_SOUND\x10\x80\x80\x80\xa8\x01\x12&\n\x1e\x44ISPLAY_SOUND_ADVANCED_DISPLAY\x10\x80\x80\xc0\xa8\x01\x12\x30\n(DISPLAY_SOUND_ADVANCED_DISPLAY_GAME_MODE\x10\x80\x80\xc4\xa8\x01\x12\x37\n/DISPLAY_SOUND_ADVANCED_DISPLAY_FORMAT_SELECTION\x10\x80\x80\xc8\xa8\x01\x12<\n4DISPLAY_SOUND_ADVANCED_DISPLAY_FORMAT_SELECTION_AUTO\x10\x80\xa0\xc8\xa8\x01\x12>\n6DISPLAY_SOUND_ADVANCED_DISPLAY_FORMAT_SELECTION_MANUAL\x10\x80\xc0\xc8\xa8\x01\x12\x44\n<DISPLAY_SOUND_ADVANCED_DISPLAY_FORMAT_SELECTION_DOLBY_VISION\x10\x80\xe0\xc8\xa8\x01\x12=\n5DISPLAY_SOUND_ADVANCED_DISPLAY_FORMAT_SELECTION_HDR10\x10\x80\x80\xc9\xa8\x01\x12;\n3DISPLAY_SOUND_ADVANCED_DISPLAY_FORMAT_SELECTION_HLG\x10\x80\xa0\xc9\xa8\x01\x12\x42\n:DISPLAY_SOUND_ADVANCED_DISPLAY_FORMAT_SELECTION_HDR10_PLUS\x10\x80\xc0\xc9\xa8\x01\x12#\n\x1b\x44ISPLAY_SOUND_SYSTEM_SOUNDS\x10\x80\x80\x80\xa9\x01\x12%\n\x1d\x44ISPLAY_SOUND_ADVANCED_SOUNDS\x10\x80\x80\xc0\xa9\x01\x12\x34\n,DISPLAY_SOUND_ADVANCED_SOUNDS_SELECT_FORMATS\x10\x80\x80\xc4\xa9\x01\x12\x39\n1DISPLAY_SOUND_ADVANCED_SOUNDS_SELECT_FORMATS_AUTO\x10\x80\xa0\xc4\xa9\x01\x12\x39\n1DISPLAY_SOUND_ADVANCED_SOUNDS_SELECT_FORMATS_NONE\x10\x80\xc0\xc4\xa9\x01\x12;\n3DISPLAY_SOUND_ADVANCED_SOUNDS_SELECT_FORMATS_MANUAL\x10\x80\xe0\xc4\xa9\x01\x12*\n\"DISPLAY_SOUND_ADVANCED_SOUNDS_DAC4\x10\x80\x80\xc8\xa9\x01\x12+\n#DISPLAY_SOUND_ADVANCED_SOUNDS_DADDP\x10\x80\x80\xcc\xa9\x01\x12(\n DISPLAY_SOUND_ADVANCED_SOUNDS_DD\x10\x80\x80\xd0\xa9\x01\x12)\n!DISPLAY_SOUND_ADVANCED_SOUNDS_DDP\x10\x80\x80\xd4\xa9\x01\x12)\n!DISPLAY_SOUND_ADVANCED_SOUNDS_DTS\x10\x80\x80\xd8\xa9\x01\x12,\n$DISPLAY_SOUND_ADVANCED_SOUNDS_DTSUHD\x10\x80\xa0\xd8\xa9\x01\x12)\n!DISPLAY_SOUND_ADVANCED_SOUNDS_DRA\x10\x80\xc0\xd8\xa9\x01\x12+\n#DISPLAY_SOUND_ADVANCED_SOUNDS_DTSHD\x10\x80\x80\xdc\xa9\x01\x12)\n!DISPLAY_SOUND_ADVANCED_SOUNDS_AAC\x10\x80\x80\xe0\xa9\x01\x12*\n\"DISPLAY_SOUND_ADVANCED_SOUNDS_DTHD\x10\x80\x80\xe4\xa9\x01\x12-\n%DISPLAY_SOUND_MATCH_CONTENT_FRAMERATE\x10\x80\x80\xc0\xaa\x01\x12\x36\n.DISPLAY_SOUND_MATCH_CONTENT_FRAMERATE_SEAMLESS\x10\x80\x80\xc4\xaa\x01\x12:\n2DISPLAY_SOUND_MATCH_CONTENT_FRAMERATE_NON_SEAMLESS\x10\x80\x80\xc8\xaa\x01\x12\x33\n+DISPLAY_SOUND_MATCH_CONTENT_FRAMERATE_NEVER\x10\x80\x80\xcc\xaa\x01\x12\x0c\n\x04\x41PPS\x10\x80\x80\x80\xb0\x01\x12\x15\n\rAPPS_ALL_APPS\x10\x80\x80\xc0\xb0\x01\x12\x1f\n\x17\x41PPS_ALL_APPS_APP_ENTRY\x10\x80\x80\xc4\xb0\x01\x12$\n\x1c\x41PPS_ALL_APPS_APP_ENTRY_OPEN\x10\x80\xa0\xc4\xb0\x01\x12*\n\"APPS_ALL_APPS_APP_ENTRY_FORCE_STOP\x10\x80\xc0\xc4\xb0\x01\x12)\n!APPS_ALL_APPS_APP_ENTRY_UNINSTALL\x10\x80\xe0\xc4\xb0\x01\x12\x31\n)APPS_ALL_APPS_APP_ENTRY_UNINSTALL_UPDATES\x10\x80\x80\xc5\xb0\x01\x12\'\n\x1f\x41PPS_ALL_APPS_APP_ENTRY_DISABLE\x10\x80\xa0\xc5\xb0\x01\x12*\n\"APPS_ALL_APPS_APP_ENTRY_CLEAR_DATA\x10\x80\xc0\xc5\xb0\x01\x12+\n#APPS_ALL_APPS_APP_ENTRY_CLEAR_CACHE\x10\x80\xe0\xc5\xb0\x01\x12.\n&APPS_ALL_APPS_APP_ENTRY_CLEAR_DEFAULTS\x10\x80\x80\xc6\xb0\x01\x12-\n%APPS_ALL_APPS_APP_ENTRY_NOTIFICATIONS\x10\x80\xa0\xc6\xb0\x01\x12+\n#APPS_ALL_APPS_APP_ENTRY_PERMISSIONS\x10\x80\xc0\xc6\xb0\x01\x12&\n\x1e\x41PPS_ALL_APPS_APP_ENTRY_ENABLE\x10\x80\xe0\xc6\xb0\x01\x12(\n APPS_ALL_APPS_APP_ENTRY_LICENSES\x10\x80\x80\xc7\xb0\x01\x12&\n\x1e\x41PPS_ALL_APPS_SHOW_SYSTEM_APPS\x10\x80\x80\xc8\xb0\x01\x12\x1c\n\x14\x41PPS_APP_PERMISSIONS\x10\x80\x80\x80\xb1\x01\x12)\n!APPS_APP_PERMISSIONS_BODY_SENSORS\x10\x80\x80\x84\xb1\x01\x12%\n\x1d\x41PPS_APP_PERMISSIONS_CALENDAR\x10\x80\x80\x88\xb1\x01\x12&\n\x1e\x41PPS_APP_PERMISSIONS_CALL_LOGS\x10\x80\x80\x8c\xb1\x01\x12#\n\x1b\x41PPS_APP_PERMISSIONS_CAMERA\x10\x80\x80\x90\xb1\x01\x12%\n\x1d\x41PPS_APP_PERMISSIONS_CONTACTS\x10\x80\x80\x94\xb1\x01\x12%\n\x1d\x41PPS_APP_PERMISSIONS_LOCATION\x10\x80\x80\x98\xb1\x01\x12\'\n\x1f\x41PPS_APP_PERMISSIONS_MICROPHONE\x10\x80\x80\x9c\xb1\x01\x12\"\n\x1a\x41PPS_APP_PERMISSIONS_PHONE\x10\x80\x80\xa0\xb1\x01\x12.\n&APPS_APP_PERMISSIONS_PHYSICAL_ACTIVITY\x10\x80\x80\xa4\xb1\x01\x12 \n\x18\x41PPS_APP_PERMISSIONS_SMS\x10\x80\x80\xa8\xb1\x01\x12$\n\x1c\x41PPS_APP_PERMISSIONS_STORAGE\x10\x80\x80\xac\xb1\x01\x12\'\n\x1f\x41PPS_APP_PERMISSIONS_ADDITIONAL\x10\x80\x80\xb0\xb1\x01\x12\x38\n0APPS_APP_PERMISSIONS_ADDITIONAL_READ_TV_LISTINGS\x10\x80\xa0\xb0\xb1\x01\x12=\n5APPS_APP_PERMISSIONS_ADDITIONAL_READ_INSTANT_MESSAGES\x10\x80\xc0\xb0\xb1\x01\x12>\n6APPS_APP_PERMISSIONS_ADDITIONAL_WRITE_INSTANT_MESSAGES\x10\x80\xe0\xb0\xb1\x01\x12\x1f\n\x17\x41PPS_SPECIAL_APP_ACCESS\x10\x80\x80\xc0\xb1\x01\x12\x33\n+APPS_SPECIAL_APP_ACCESS_ENERGY_OPTIMIZATION\x10\x80\x80\xc4\xb1\x01\x12,\n$APPS_SPECIAL_APP_ACCESS_USAGE_ACCESS\x10\x80\x80\xc8\xb1\x01\x12\x33\n+APPS_SPECIAL_APP_ACCESS_NOTIFICATION_ACCESS\x10\x80\x80\xcc\xb1\x01\x12\x33\n+APPS_SPECIAL_APP_ACCESS_DISPLAY_OVER_OTHERS\x10\x80\x80\xd0\xb1\x01\x12\x36\n.APPS_SPECIAL_APP_ACCESS_MODIFY_SYSTEM_SETTINGS\x10\x80\x80\xd4\xb1\x01\x12\x32\n*APPS_SPECIAL_APP_ACCESS_PICTURE_IN_PICTURE\x10\x80\x80\xd8\xb1\x01\x12\x34\n,APPS_SPECIAL_APP_ACCESS_ALARMS_AND_REMINDERS\x10\x80\x80\xdc\xb1\x01\x12\"\n\x1a\x41PPS_SECURITY_RESTRICTIONS\x10\x80\x80\x80\xb2\x01\x12\x32\n*APPS_SECURITY_RESTRICTIONS_UNKNOWN_SOURCES\x10\x80\x80\x84\xb2\x01\x12.\n&APPS_SECURITY_RESTRICTIONS_VERIFY_APPS\x10\x80\x80\x88\xb2\x01\x12\x31\n)APPS_SECURITY_RESTRICTIONS_CREATE_PROFILE\x10\x80\x80\x8c\xb2\x01\x12\x30\n(APPS_SECURITY_RESTRICTIONS_ENTER_PROFILE\x10\x80\x80\x90\xb2\x01\x12\x37\n/APPS_SECURITY_RESTRICTIONS_PROFILE_ALLOWED_APPS\x10\x80\x80\x94\xb2\x01\x12\x35\n-APPS_SECURITY_RESTRICTIONS_PROFILE_CHANGE_PIN\x10\x80\x80\x98\xb2\x01\x12\x31\n)APPS_SECURITY_RESTRICTIONS_DELETE_PROFILE\x10\x80\x80\x9c\xb2\x01\x12/\n\'APPS_SECURITY_RESTRICTIONS_EXIT_PROFILE\x10\x80\x80\xa0\xb2\x01\x12\x0e\n\x06SYSTEM\x10\x80\x80\x80\xb8\x01\x12\x14\n\x0cSYSTEM_ABOUT\x10\x80\x80\xc0\xb8\x01\x12\"\n\x1aSYSTEM_ABOUT_SYSTEM_UPDATE\x10\x80\x80\xc4\xb8\x01\x12 \n\x18SYSTEM_ABOUT_DEVICE_NAME\x10\x80\x80\xc8\xb8\x01\x12\"\n\x1aSYSTEM_ABOUT_FACTORY_RESET\x10\x80\x80\xcc\xb8\x01\x12\x1b\n\x13SYSTEM_ABOUT_STATUS\x10\x80\x80\xd0\xb8\x01\x12\x1f\n\x17SYSTEM_ABOUT_LEGAL_INFO\x10\x80\x80\xd4\xb8\x01\x12+\n#SYSTEM_ABOUT_LEGAL_INFO_OPEN_SOURCE\x10\x80\xa0\xd4\xb8\x01\x12,\n$SYSTEM_ABOUT_LEGAL_INFO_GOOGLE_LEGAL\x10\x80\xc0\xd4\xb8\x01\x12.\n&SYSTEM_ABOUT_LEGAL_INFO_SYSTEM_WEBVIEW\x10\x80\xe0\xd4\xb8\x01\x12\x1a\n\x12SYSTEM_ABOUT_BUILD\x10\x80\x80\xd8\xb8\x01\x12\x18\n\x10SYSTEM_DATE_TIME\x10\x80\x80\x80\xb9\x01\x12\"\n\x1aSYSTEM_DATE_TIME_AUTOMATIC\x10\x80\x80\x84\xb9\x01\x12\x33\n+SYSTEM_DATE_TIME_AUTOMATIC_USE_NETWORK_TIME\x10\x80\xa0\x84\xb9\x01\x12&\n\x1eSYSTEM_DATE_TIME_AUTOMATIC_OFF\x10\x80\xc0\x84\xb9\x01\x12!\n\x19SYSTEM_DATE_TIME_SET_DATE\x10\x80\x80\x88\xb9\x01\x12!\n\x19SYSTEM_DATE_TIME_SET_TIME\x10\x80\x80\x8c\xb9\x01\x12&\n\x1eSYSTEM_DATE_TIME_SET_TIME_ZONE\x10\x80\x80\x90\xb9\x01\x12-\n%SYSTEM_DATE_TIME_SET_TIME_ZONE_BUTTON\x10\x80\xa0\x90\xb9\x01\x12+\n#SYSTEM_DATE_TIME_USE_24_HOUR_FORMAT\x10\x80\x80\x94\xb9\x01\x12\x17\n\x0fSYSTEM_LANGUAGE\x10\x80\x80\xc0\xb9\x01\x12\x1e\n\x16SYSTEM_LANGUAGE_BUTTON\x10\x80\x80\xc4\xb9\x01\x12\x17\n\x0fSYSTEM_KEYBOARD\x10\x80\x80\x80\xba\x01\x12(\n SYSTEM_KEYBOARD_CURRENT_KEYBOARD\x10\x80\x80\x84\xba\x01\x12\'\n\x1fSYSTEM_KEYBOARD_GBOARD_SETTINGS\x10\x80\x80\x88\xba\x01\x12\x31\n)SYSTEM_KEYBOARD_GBOARD_SETTINGS_LANGUAGES\x10\x80\xa0\x88\xba\x01\x12+\n#SYSTEM_KEYBOARD_GBOARD_SETTINGS_TOS\x10\x80\xc0\x88\xba\x01\x12\x36\n.SYSTEM_KEYBOARD_GBOARD_SETTINGS_PRIVACY_POLICY\x10\x80\xe0\x88\xba\x01\x12\x33\n+SYSTEM_KEYBOARD_GBOARD_SETTINGS_OPEN_SOURCE\x10\x80\x80\x89\xba\x01\x12\x39\n1SYSTEM_KEYBOARD_GBOARD_SETTINGS_SHARE_USAGE_STATS\x10\x80\xa0\x89\xba\x01\x12(\n SYSTEM_KEYBOARD_MANAGE_KEYBOARDS\x10\x80\x80\x8c\xba\x01\x12\x16\n\x0eSYSTEM_STORAGE\x10\x80\x80\xc0\xba\x01\x12\'\n\x1fSYSTEM_STORAGE_INTERNAL_STORAGE\x10\x80\x80\xc4\xba\x01\x12,\n$SYSTEM_STORAGE_INTERNAL_STORAGE_APPS\x10\x80\xa0\xc4\xba\x01\x12.\n&SYSTEM_STORAGE_INTERNAL_STORAGE_CACHED\x10\x80\xc0\xc4\xba\x01\x12\x16\n\x0eSYSTEM_AMBIENT\x10\x80\x80\x80\xbb\x01\x12\x1c\n\x14SYSTEM_AMBIENT_START\x10\x80\x80\x84\xbb\x01\x12\x1f\n\x17SYSTEM_AMBIENT_SETTINGS\x10\x80\x80\x88\xbb\x01\x12*\n\"SYSTEM_AMBIENT_SETTINGS_CHANNEL_GP\x10\x80\xa0\x88\xbb\x01\x12*\n\"SYSTEM_AMBIENT_SETTINGS_CHANNEL_AG\x10\x80\xc0\x88\xbb\x01\x12*\n\"SYSTEM_AMBIENT_SETTINGS_CHANNEL_CV\x10\x80\xe0\x88\xbb\x01\x12+\n#SYSTEM_AMBIENT_SETTINGS_CHANNEL_EXP\x10\x80\x80\x89\xbb\x01\x12\'\n\x1fSYSTEM_AMBIENT_SETTINGS_WEATHER\x10\x80\xa0\x89\xbb\x01\x12,\n$SYSTEM_AMBIENT_SETTINGS_WEATHER_HIDE\x10\x80\xa2\x89\xbb\x01\x12.\n&SYSTEM_AMBIENT_SETTINGS_WEATHER_UNIT_C\x10\x80\xa4\x89\xbb\x01\x12.\n&SYSTEM_AMBIENT_SETTINGS_WEATHER_UNIT_F\x10\x80\xa6\x89\xbb\x01\x12\x31\n)SYSTEM_AMBIENT_SETTINGS_WEATHER_UNIT_BOTH\x10\x80\xa8\x89\xbb\x01\x12$\n\x1cSYSTEM_AMBIENT_SETTINGS_TIME\x10\x80\xc0\x89\xbb\x01\x12)\n!SYSTEM_AMBIENT_SETTINGS_TIME_HIDE\x10\x80\xc2\x89\xbb\x01\x12)\n!SYSTEM_AMBIENT_SETTINGS_TIME_SHOW\x10\x80\xc4\x89\xbb\x01\x12+\n#SYSTEM_AMBIENT_SETTINGS_DEVICE_INFO\x10\x80\xe0\x89\xbb\x01\x12\x30\n(SYSTEM_AMBIENT_SETTINGS_DEVICE_INFO_HIDE\x10\x80\xe2\x89\xbb\x01\x12\x30\n(SYSTEM_AMBIENT_SETTINGS_DEVICE_INFO_SHOW\x10\x80\xe4\x89\xbb\x01\x12#\n\x1bSYSTEM_AMBIENT_SETTINGS_PPD\x10\x80\x80\x8a\xbb\x01\x12(\n SYSTEM_AMBIENT_SETTINGS_PPD_HIDE\x10\x80\x82\x8a\xbb\x01\x12(\n SYSTEM_AMBIENT_SETTINGS_PPD_SHOW\x10\x80\x84\x8a\xbb\x01\x12#\n\x1bSYSTEM_AMBIENT_SETTINGS_PGP\x10\x80\xa0\x8a\xbb\x01\x12(\n SYSTEM_AMBIENT_SETTINGS_PGP_HIDE\x10\x80\xa2\x8a\xbb\x01\x12(\n SYSTEM_AMBIENT_SETTINGS_PGP_SHOW\x10\x80\xa4\x8a\xbb\x01\x12.\n&SYSTEM_AMBIENT_SETTINGS_PGP_SHOW_PAIRS\x10\x80\xa6\x8a\xbb\x01\x12#\n\x1bSYSTEM_AMBIENT_SETTINGS_PPC\x10\x80\xc0\x8a\xbb\x01\x12.\n&SYSTEM_AMBIENT_SETTINGS_PPC_ALL_ALBUMS\x10\x80\xc2\x8a\xbb\x01\x12/\n\'SYSTEM_AMBIENT_SETTINGS_PPC_LIVE_ALBUMS\x10\x80\xc4\x8a\xbb\x01\x12+\n#SYSTEM_AMBIENT_SETTINGS_SLIDE_SPEED\x10\x80\xe0\x8a\xbb\x01\x12.\n&SYSTEM_AMBIENT_SETTINGS_SLIDE_SPEED_5S\x10\x80\xe2\x8a\xbb\x01\x12/\n\'SYSTEM_AMBIENT_SETTINGS_SLIDE_SPEED_10S\x10\x80\xe4\x8a\xbb\x01\x12/\n\'SYSTEM_AMBIENT_SETTINGS_SLIDE_SPEED_30S\x10\x80\xe6\x8a\xbb\x01\x12.\n&SYSTEM_AMBIENT_SETTINGS_SLIDE_SPEED_1M\x10\x80\xe8\x8a\xbb\x01\x12.\n&SYSTEM_AMBIENT_SETTINGS_SLIDE_SPEED_3M\x10\x80\xea\x8a\xbb\x01\x12.\n&SYSTEM_AMBIENT_SETTINGS_SLIDE_SPEED_5M\x10\x80\xec\x8a\xbb\x01\x12/\n\'SYSTEM_AMBIENT_SETTINGS_SLIDE_SPEED_10M\x10\x80\xee\x8a\xbb\x01\x12\x1a\n\x12SYSTEM_ENERGYSAVER\x10\x80\x80\xc0\xbb\x01\x12&\n\x1eSYSTEM_ENERGYSAVER_START_DELAY\x10\x80\x80\xc4\xbb\x01\x12*\n\"SYSTEM_ENERGYSAVER_START_DELAY_15M\x10\x80\xa0\xc4\xbb\x01\x12*\n\"SYSTEM_ENERGYSAVER_START_DELAY_30M\x10\x80\xc0\xc4\xbb\x01\x12)\n!SYSTEM_ENERGYSAVER_START_DELAY_1H\x10\x80\xe0\xc4\xbb\x01\x12)\n!SYSTEM_ENERGYSAVER_START_DELAY_3H\x10\x80\x80\xc5\xbb\x01\x12)\n!SYSTEM_ENERGYSAVER_START_DELAY_6H\x10\x80\xa0\xc5\xbb\x01\x12*\n\"SYSTEM_ENERGYSAVER_START_DELAY_12H\x10\x80\xc0\xc5\xbb\x01\x12,\n$SYSTEM_ENERGYSAVER_START_DELAY_NEVER\x10\x80\xe0\xc5\xbb\x01\x12\x13\n\x0bSYSTEM_A11Y\x10\x80\x80\x80\xbc\x01\x12\x1c\n\x14SYSTEM_A11Y_CAPTIONS\x10\x80\x80\x84\xbc\x01\x12+\n#SYSTEM_A11Y_CAPTIONS_DISPLAY_ON_OFF\x10\x80\xa0\x84\xbc\x01\x12%\n\x1dSYSTEM_A11Y_CAPTIONS_LANGUAGE\x10\x80\xc0\x84\xbc\x01\x12,\n$SYSTEM_A11Y_CAPTIONS_LANGUAGE_BUTTON\x10\x80\xc2\x84\xbc\x01\x12&\n\x1eSYSTEM_A11Y_CAPTIONS_TEXT_SIZE\x10\x80\xe0\x84\xbc\x01\x12\x31\n)SYSTEM_A11Y_CAPTIONS_TEXT_SIZE_VERY_SMALL\x10\x80\xe2\x84\xbc\x01\x12,\n$SYSTEM_A11Y_CAPTIONS_TEXT_SIZE_SMALL\x10\x80\xe4\x84\xbc\x01\x12-\n%SYSTEM_A11Y_CAPTIONS_TEXT_SIZE_NORMAL\x10\x80\xe6\x84\xbc\x01\x12,\n$SYSTEM_A11Y_CAPTIONS_TEXT_SIZE_LARGE\x10\x80\xe8\x84\xbc\x01\x12\x31\n)SYSTEM_A11Y_CAPTIONS_TEXT_SIZE_VERY_LARGE\x10\x80\xea\x84\xbc\x01\x12+\n#SYSTEM_A11Y_CAPTIONS_WHITE_ON_BLACK\x10\x80\x80\x85\xbc\x01\x12+\n#SYSTEM_A11Y_CAPTIONS_BLACK_ON_WHITE\x10\x80\xa0\x85\xbc\x01\x12,\n$SYSTEM_A11Y_CAPTIONS_YELLOW_ON_BLACK\x10\x80\xc0\x85\xbc\x01\x12+\n#SYSTEM_A11Y_CAPTIONS_YELLOW_ON_BLUE\x10\x80\xe0\x85\xbc\x01\x12#\n\x1bSYSTEM_A11Y_CAPTIONS_CUSTOM\x10\x80\x80\x86\xbc\x01\x12(\n SYSTEM_A11Y_CAPTIONS_CUSTOM_FONT\x10\x80\x82\x86\xbc\x01\x12.\n&SYSTEM_A11Y_CAPTIONS_CUSTOM_TEXT_COLOR\x10\x80\x84\x86\xbc\x01\x12\x30\n(SYSTEM_A11Y_CAPTIONS_CUSTOM_TEXT_OPACITY\x10\x80\x86\x86\xbc\x01\x12-\n%SYSTEM_A11Y_CAPTIONS_CUSTOM_EDGE_TYPE\x10\x80\x88\x86\xbc\x01\x12.\n&SYSTEM_A11Y_CAPTIONS_CUSTOM_EDGE_COLOR\x10\x80\x8a\x86\xbc\x01\x12,\n$SYSTEM_A11Y_CAPTIONS_SHOW_BACKGROUND\x10\x80\x8c\x86\xbc\x01\x12-\n%SYSTEM_A11Y_CAPTIONS_BACKGROUND_COLOR\x10\x80\x8e\x86\xbc\x01\x12/\n\'SYSTEM_A11Y_CAPTIONS_BACKGROUND_OPACITY\x10\x80\x90\x86\xbc\x01\x12(\n SYSTEM_A11Y_CAPTIONS_SHOW_WINDOW\x10\x80\x92\x86\xbc\x01\x12)\n!SYSTEM_A11Y_CAPTIONS_WINDOW_COLOR\x10\x80\x94\x86\xbc\x01\x12+\n#SYSTEM_A11Y_CAPTIONS_WINDOW_OPACITY\x10\x80\x96\x86\xbc\x01\x12&\n\x1eSYSTEM_A11Y_HIGH_CONTRAST_TEXT\x10\x80\x80\x88\xbc\x01\x12\x17\n\x0fSYSTEM_A11Y_TTS\x10\x80\x80\x8c\xbc\x01\x12%\n\x1dSYSTEM_A11Y_TTS_ENGINE_SELECT\x10\x80\xa0\x8c\xbc\x01\x12%\n\x1dSYSTEM_A11Y_TTS_ENGINE_CONFIG\x10\x80\xc0\x8c\xbc\x01\x12.\n&SYSTEM_A11Y_TTS_ENGINE_CONFIG_LANGUAGE\x10\x80\xc2\x8c\xbc\x01\x12>\n6SYSTEM_A11Y_TTS_ENGINE_CONFIG_LANGUAGE_CHOOSE_LANGUAGE\x10\x90\xc2\x8c\xbc\x01\x12:\n2SYSTEM_A11Y_TTS_ENGINE_CONFIG_SETTINGS_GTTS_ENGINE\x10\x80\xc4\x8c\xbc\x01\x12\x38\n0SYSTEM_A11Y_TTS_ENGINE_CONFIG_INSTALL_VOICE_DATA\x10\x80\xc6\x8c\xbc\x01\x12#\n\x1bSYSTEM_A11Y_TTS_SPEECH_RATE\x10\x80\xe0\x8c\xbc\x01\x12&\n\x1eSYSTEM_A11Y_TTS_LISTEN_EXAMPLE\x10\x80\x80\x8d\xbc\x01\x12\x1c\n\x14SYSTEM_A11Y_SHORTCUT\x10\x80\x80\x90\xbc\x01\x12#\n\x1bSYSTEM_A11Y_SHORTCUT_ON_OFF\x10\x80\xa0\x90\xbc\x01\x12$\n\x1cSYSTEM_A11Y_SHORTCUT_SERVICE\x10\x80\xc0\x90\xbc\x01\x12\x1c\n\x14SYSTEM_A11Y_TALKBACK\x10\x80\x80\x94\xbc\x01\x12#\n\x1bSYSTEM_A11Y_TALKBACK_ON_OFF\x10\x80\xa0\x94\xbc\x01\x12#\n\x1bSYSTEM_A11Y_TALKBACK_CONFIG\x10\x80\xc0\x94\xbc\x01\x12\x1d\n\x15SYSTEM_A11Y_A11Y_MENU\x10\x80\x80\x98\xbc\x01\x12$\n\x1cSYSTEM_A11Y_A11Y_MENU_ON_OFF\x10\x80\xa0\x98\xbc\x01\x12$\n\x1cSYSTEM_A11Y_A11Y_MENU_CONFIG\x10\x80\xc0\x98\xbc\x01\x12\x17\n\x0fSYSTEM_A11Y_STS\x10\x80\x80\x9c\xbc\x01\x12\x1e\n\x16SYSTEM_A11Y_STS_ON_OFF\x10\x80\xa0\x9c\xbc\x01\x12\x1e\n\x16SYSTEM_A11Y_STS_CONFIG\x10\x80\xc0\x9c\xbc\x01\x12!\n\x19SYSTEM_A11Y_SWITCH_ACCESS\x10\x80\x80\xa0\xbc\x01\x12(\n SYSTEM_A11Y_SWITCH_ACCESS_ON_OFF\x10\x80\xa0\xa0\xbc\x01\x12(\n SYSTEM_A11Y_SWITCH_ACCESS_CONFIG\x10\x80\xc0\xa0\xbc\x01\x12\x15\n\rSYSTEM_REBOOT\x10\x80\x80\xc0\xbc\x01\x12\x1f\n\x17PREFERENCES_HOME_SCREEN\x10\x80\x80\x80\xbd\x01\x12\x32\n*PREFERENCES_HOME_SCREEN_CUSTOMIZE_CHANNELS\x10\x80\x80\x84\xbd\x01\x12\x35\n-PREFERENCES_HOME_SCREEN_CUSTOMIZE_CHANNELS_PN\x10\x80\xa0\x84\xbd\x01\x12<\n4PREFERENCES_HOME_SCREEN_CUSTOMIZE_CHANNELS_PN_ON_OFF\x10\x80\xa2\x84\xbd\x01\x12:\n2PREFERENCES_HOME_SCREEN_CUSTOMIZE_CHANNELS_PN_GPMT\x10\x80\xa4\x84\xbd\x01\x12\x39\n1PREFERENCES_HOME_SCREEN_CUSTOMIZE_CHANNELS_PN_GPM\x10\x80\xa6\x84\xbd\x01\x12\x41\n9PREFERENCES_HOME_SCREEN_CUSTOMIZE_CHANNELS_PN_PROMOTIONAL\x10\x80\xa8\x84\xbd\x01\x12>\n6PREFERENCES_HOME_SCREEN_CUSTOMIZE_CHANNELS_HOME_SCREEN\x10\x80\xc0\x84\xbd\x01\x12>\n6PREFERENCES_HOME_SCREEN_CUSTOMIZE_CHANNELS_PROMOTIONAL\x10\x80\xe0\x84\xbd\x01\x12.\n&PREFERENCES_HOME_SCREEN_VIDEO_PREVIEWS\x10\x80\x80\x88\xbd\x01\x12.\n&PREFERENCES_HOME_SCREEN_AUDIO_PREVIEWS\x10\x80\x80\x8c\xbd\x01\x12,\n$PREFERENCES_HOME_SCREEN_REORDER_APPS\x10\x80\x80\x90\xbd\x01\x12-\n%PREFERENCES_HOME_SCREEN_REORDER_GAMES\x10\x80\x80\x94\xbd\x01\x12\x30\n(PREFERENCES_HOME_SCREEN_ATVH_OPEN_SOURCE\x10\x80\x80\x98\xbd\x01\x12\x31\n)PREFERENCES_HOME_SCREEN_ATVCS_OPEN_SOURCE\x10\x80\x80\x9c\xbd\x01\x12\x1d\n\x15PREFERENCES_ASSISTANT\x10\x80\x80\xc0\xbd\x01\x12&\n\x1ePREFERENCES_ASSISTANT_ACCOUNTS\x10\x80\x80\xc4\xbd\x01\x12\x30\n(PREFERENCES_ASSISTANT_ACCEPT_PERMISSIONS\x10\x80\x80\xc8\xbd\x01\x12.\n&PREFERENCES_ASSISTANT_VIEW_PERMISSIONS\x10\x80\x80\xcc\xbd\x01\x12-\n%PREFERENCES_ASSISTANT_SEARCHABLE_APPS\x10\x80\xe0\xcc\x90\x01\x12/\n\'PREFERENCES_ASSISTANT_SAFESEARCH_FILTER\x10\x80\xa0\xcc\x90\x01\x12-\n%PREFERENCES_ASSISTANT_BLOCK_OFFENSIVE\x10\x80\xc0\xcc\x90\x01\x12)\n!PREFERENCES_ASSISTANT_OPEN_SOURCE\x10\x80\x80\xd0\xbd\x01\x12$\n\x1cPREFERENCES_CHROMECAST_SHELL\x10\x80\x80\x80\xbe\x01\x12\x30\n(PREFERENCES_CHROMECAST_SHELL_OPEN_SOURCE\x10\x80\x80\x84\xbe\x01\x12\x1f\n\x17PREFERENCES_SCREENSAVER\x10\x80\x80\xc0\xbe\x01\x12\'\n\x1fPREFERENCES_SCREENSAVER_CHOOSER\x10\x80\x80\xc4\xbe\x01\x12\x32\n*PREFERENCES_SCREENSAVER_CHOOSER_SCREEN_OFF\x10\x80\xa0\xc4\xbe\x01\x12\x30\n(PREFERENCES_SCREENSAVER_CHOOSER_BACKDROP\x10\x80\xc0\xc4\xbe\x01\x12.\n&PREFERENCES_SCREENSAVER_CHOOSER_COLORS\x10\x80\xe0\xc4\xbe\x01\x12+\n#PREFERENCES_SCREENSAVER_START_DELAY\x10\x80\x80\xc8\xbe\x01\x12.\n&PREFERENCES_SCREENSAVER_START_DELAY_5M\x10\x80\xa0\xc8\xbe\x01\x12/\n\'PREFERENCES_SCREENSAVER_START_DELAY_15M\x10\x80\xc0\xc8\xbe\x01\x12/\n\'PREFERENCES_SCREENSAVER_START_DELAY_30M\x10\x80\xe0\xc8\xbe\x01\x12.\n&PREFERENCES_SCREENSAVER_START_DELAY_1H\x10\x80\x80\xc9\xbe\x01\x12.\n&PREFERENCES_SCREENSAVER_START_DELAY_2H\x10\x80\xa0\xc9\xbe\x01\x12)\n!PREFERENCES_SCREENSAVER_START_NOW\x10\x80\x80\xcc\xbe\x01\x12\x17\n\x0f\x43ONNECTED_SLICE\x10\x80\x80\x80\xc0\x01\x12+\n#CONNECTED_SLICE_CONNECT_NEW_DEVICES\x10\x80\x80\xc0\xc0\x01\x12$\n\x1c\x43ONNECTED_SLICE_DEVICE_ENTRY\x10\x80\x80\x80\xc1\x01\x12+\n#CONNECTED_SLICE_DEVICE_ENTRY_UPDATE\x10\x80\x80\x84\xc1\x01\x12+\n#CONNECTED_SLICE_DEVICE_ENTRY_RENAME\x10\x80\x80\x88\xc1\x01\x12+\n#CONNECTED_SLICE_DEVICE_ENTRY_FORGET\x10\x80\x80\x8c\xc1\x01\x12\x1f\n\x17\x43ONNECTED_SLICE_HDMICEC\x10\x80\x80\xc0\xc1\x01\x12&\n\x1e\x43ONNECTED_SLICE_HDMICEC_ON_OFF\x10\x80\x80\xc4\xc1\x01\x12\x19\n\x11\x43ONNECTED_CLASSIC\x10\x80\x80\x80\xc0\x01\x12(\n CONNECTED_CLASSIC_CONNECT_REMOTE\x10\x80\x80\xc0\xc0\x01\x12&\n\x1e\x43ONNECTED_CLASSIC_DEVICE_ENTRY\x10\x80\x80\x80\xc1\x01\x12-\n%CONNECTED_CLASSIC_DEVICE_ENTRY_UPDATE\x10\x80\x80\x84\xc1\x01\x12-\n%CONNECTED_CLASSIC_DEVICE_ENTRY_RENAME\x10\x80\x80\x88\xc1\x01\x12-\n%CONNECTED_CLASSIC_DEVICE_ENTRY_FORGET\x10\x80\x80\x8c\xc1\x01\x12!\n\x19\x43ONNECTED_CLASSIC_HDMICEC\x10\x80\x80\xc0\xc1\x01\x12(\n CONNECTED_CLASSIC_HDMICEC_ON_OFF\x10\x80\x80\xc4\xc1\x01\x12\x10\n\x08\x46\x45\x45\x44\x42\x41\x43K\x10\x80\x80\x80\xc8\x01\x12\x15\n\rFEEDBACK_SEND\x10\x80\x80\xc0\xc8\x01\x1a\x02\x10\x01\x42\x13\x42\x0fTvSettingsEnumsP\x01')

_ACTION = DESCRIPTOR.enum_types_by_name['Action']
Action = enum_type_wrapper.EnumTypeWrapper(_ACTION)
_ITEMID = DESCRIPTOR.enum_types_by_name['ItemId']
ItemId = enum_type_wrapper.EnumTypeWrapper(_ITEMID)
ACTION_UNKNOWN = 0
PAGE_FOCUSED = 1
ENTRY_SELECTED = 2
TOGGLE_INTERACTED = 3
PAGE_FOCUSED_FORWARD = 4
PAGE_FOCUSED_BACKWARD = 5
TOGGLED_ON = 6
TOGGLED_OFF = 7
UNKNOWN = 0
TV_SETTINGS_ROOT = 1
PAGE_CLASSIC_DEFAULT = 2
PAGE_SLICE_DEFAULT = 3
ENTRY_DEFAULT = 4
SUGGESTED_SETTINGS = 16
QUICK_SETTINGS = 17
NETWORK = 285212672
NETWORK_WIFI_ON_OFF = 286261248
NETWORK_AP_INFO = 287309824
NETWORK_AP_INFO_PROXY_SETTINGS = 287375360
NETWORK_AP_INFO_IP_SETTINGS = 287440896
NETWORK_AP_INFO_FORGET_NETWORK = 287506432
NETWORK_NOT_CONNECTED_AP = 288358400
NETWORK_SEE_ALL = 289406976
NETWORK_SEE_FEWER = 290455552
NETWORK_ADD_NEW_NETWORK = 291504128
NETWORK_ALWAYS_SCANNING_NETWORKS = 292552704
NETWORK_ETHERNET_PROXY_SETTINGS = 293601280
NETWORK_ETHERNET_IP_SETTINGS = 294649856
ACCOUNT_SLICE = 301989888
ACCOUNT_SLICE_REG_ACCOUNT = 303038464
ACCOUNT_SLICE_REG_ACCOUNT_SERVICES = 303104000
ACCOUNT_SLICE_REG_ACCOUNT_PAYMENT = 303169536
ACCOUNT_SLICE_REG_ACCOUNT_PAYMENT_REAUTH = 303173632
ACCOUNT_SLICE_REG_ACCOUNT_PAYMENT_REAUTH_ALWAYS = 303173888
ACCOUNT_SLICE_REG_ACCOUNT_PAYMENT_REAUTH_30MINS = 303174144
ACCOUNT_SLICE_REG_ACCOUNT_PAYMENT_REAUTH_NEVER = 303174400
ACCOUNT_SLICE_REG_ACCOUNT_ASSISTANT = 303235072
ACCOUNT_SLICE_REG_ACCOUNT_ASSISTANT_SAFE_SEARCH = 303239168
ACCOUNT_SLICE_REG_ACCOUNT_ASSISTANT_BLOCK_OFFENSIVE = 303243264
ACCOUNT_SLICE_REG_ACCOUNT_ASSISTANT_SEARCHABLE_APPS = 303247360
ACCOUNT_SLICE_REG_ACCOUNT_ASSISTANT_PERSONAL_RESULTS = 303251456
ACCOUNT_SLICE_REG_ACCOUNT_APPS_ONLY_MODE = 303300608
ACCOUNT_SLICE_REG_ACCOUNT_REMOVE = 303693824
ACCOUNT_SLICE_ADD_ACCOUNT = 312475648
ACCOUNT_CLASSIC = 318767104
ACCOUNT_CLASSIC_REG_ACCOUNT = 319815680
ACCOUNT_CLASSIC_REG_ACCOUNT_SYNC_NOW = 319881216
ACCOUNT_CLASSIC_REG_ACCOUNT_REMOVE_ACCOUNT = 319946752
ACCOUNT_CLASSIC_REG_ACCOUNT_SYNC_CALENDAR = 320012288
ACCOUNT_CLASSIC_REG_ACCOUNT_SYNC_CONTACTS = 320077824
ACCOUNT_CLASSIC_REG_ACCOUNT_SYNC_GPMT = 320143360
ACCOUNT_CLASSIC_REG_ACCOUNT_SYNC_GPM = 320208896
ACCOUNT_CLASSIC_REG_ACCOUNT_SYNC_PEOPLE = 320274432
ACCOUNT_CLASSIC_ADD_ACCOUNT = 329252864
PRIVACY = 335544320
PRIVACY_LOCATION = 336592896
PRIVACY_LOCATION_STATUS = 336658432
PRIVACY_LOCATION_STATUS_USE_WIFI = 336662528
PRIVACY_LOCATION_STATUS_OFF = 336666624
PRIVACY_LOCATION_ALWAYS_SCANNING_NETWORKS = 336723968
PRIVACY_LOCATION_REQUESTED_APP = 336789504
PRIVACY_DIAGNOSTICS = 337641472
PRIVACY_DIAGNOSTICS_ON_OFF = 337707008
PRIVACY_ADS = 338690048
PRIVACY_ADS_RESET_AD_ID = 338755584
PRIVACY_ADS_OPT_OUT_PERSONALIZATION = 338821120
PRIVACY_ADS_ADS_BY_GOOGLE = 338886656
DISPLAY_SOUND = 352321536
DISPLAY_SOUND_ADVANCED_DISPLAY = 353370112
DISPLAY_SOUND_ADVANCED_DISPLAY_GAME_MODE = 353435648
DISPLAY_SOUND_ADVANCED_DISPLAY_FORMAT_SELECTION = 353501184
DISPLAY_SOUND_ADVANCED_DISPLAY_FORMAT_SELECTION_AUTO = 353505280
DISPLAY_SOUND_ADVANCED_DISPLAY_FORMAT_SELECTION_MANUAL = 353509376
DISPLAY_SOUND_ADVANCED_DISPLAY_FORMAT_SELECTION_DOLBY_VISION = 353513472
DISPLAY_SOUND_ADVANCED_DISPLAY_FORMAT_SELECTION_HDR10 = 353517568
DISPLAY_SOUND_ADVANCED_DISPLAY_FORMAT_SELECTION_HLG = 353521664
DISPLAY_SOUND_ADVANCED_DISPLAY_FORMAT_SELECTION_HDR10_PLUS = 353525760
DISPLAY_SOUND_SYSTEM_SOUNDS = 354418688
DISPLAY_SOUND_ADVANCED_SOUNDS = 355467264
DISPLAY_SOUND_ADVANCED_SOUNDS_SELECT_FORMATS = 355532800
DISPLAY_SOUND_ADVANCED_SOUNDS_SELECT_FORMATS_AUTO = 355536896
DISPLAY_SOUND_ADVANCED_SOUNDS_SELECT_FORMATS_NONE = 355540992
DISPLAY_SOUND_ADVANCED_SOUNDS_SELECT_FORMATS_MANUAL = 355545088
DISPLAY_SOUND_ADVANCED_SOUNDS_DAC4 = 355598336
DISPLAY_SOUND_ADVANCED_SOUNDS_DADDP = 355663872
DISPLAY_SOUND_ADVANCED_SOUNDS_DD = 355729408
DISPLAY_SOUND_ADVANCED_SOUNDS_DDP = 355794944
DISPLAY_SOUND_ADVANCED_SOUNDS_DTS = 355860480
DISPLAY_SOUND_ADVANCED_SOUNDS_DTSUHD = 355864576
DISPLAY_SOUND_ADVANCED_SOUNDS_DRA = 355868672
DISPLAY_SOUND_ADVANCED_SOUNDS_DTSHD = 355926016
DISPLAY_SOUND_ADVANCED_SOUNDS_AAC = 355991552
DISPLAY_SOUND_ADVANCED_SOUNDS_DTHD = 356057088
DISPLAY_SOUND_MATCH_CONTENT_FRAMERATE = 357564416
DISPLAY_SOUND_MATCH_CONTENT_FRAMERATE_SEAMLESS = 357629952
DISPLAY_SOUND_MATCH_CONTENT_FRAMERATE_NON_SEAMLESS = 357695488
DISPLAY_SOUND_MATCH_CONTENT_FRAMERATE_NEVER = 357761024
APPS = 369098752
APPS_ALL_APPS = 370147328
APPS_ALL_APPS_APP_ENTRY = 370212864
APPS_ALL_APPS_APP_ENTRY_OPEN = 370216960
APPS_ALL_APPS_APP_ENTRY_FORCE_STOP = 370221056
APPS_ALL_APPS_APP_ENTRY_UNINSTALL = 370225152
APPS_ALL_APPS_APP_ENTRY_UNINSTALL_UPDATES = 370229248
APPS_ALL_APPS_APP_ENTRY_DISABLE = 370233344
APPS_ALL_APPS_APP_ENTRY_CLEAR_DATA = 370237440
APPS_ALL_APPS_APP_ENTRY_CLEAR_CACHE = 370241536
APPS_ALL_APPS_APP_ENTRY_CLEAR_DEFAULTS = 370245632
APPS_ALL_APPS_APP_ENTRY_NOTIFICATIONS = 370249728
APPS_ALL_APPS_APP_ENTRY_PERMISSIONS = 370253824
APPS_ALL_APPS_APP_ENTRY_ENABLE = 370257920
APPS_ALL_APPS_APP_ENTRY_LICENSES = 370262016
APPS_ALL_APPS_SHOW_SYSTEM_APPS = 370278400
APPS_APP_PERMISSIONS = 371195904
APPS_APP_PERMISSIONS_BODY_SENSORS = 371261440
APPS_APP_PERMISSIONS_CALENDAR = 371326976
APPS_APP_PERMISSIONS_CALL_LOGS = 371392512
APPS_APP_PERMISSIONS_CAMERA = 371458048
APPS_APP_PERMISSIONS_CONTACTS = 371523584
APPS_APP_PERMISSIONS_LOCATION = 371589120
APPS_APP_PERMISSIONS_MICROPHONE = 371654656
APPS_APP_PERMISSIONS_PHONE = 371720192
APPS_APP_PERMISSIONS_PHYSICAL_ACTIVITY = 371785728
APPS_APP_PERMISSIONS_SMS = 371851264
APPS_APP_PERMISSIONS_STORAGE = 371916800
APPS_APP_PERMISSIONS_ADDITIONAL = 371982336
APPS_APP_PERMISSIONS_ADDITIONAL_READ_TV_LISTINGS = 371986432
APPS_APP_PERMISSIONS_ADDITIONAL_READ_INSTANT_MESSAGES = 371990528
APPS_APP_PERMISSIONS_ADDITIONAL_WRITE_INSTANT_MESSAGES = 371994624
APPS_SPECIAL_APP_ACCESS = 372244480
APPS_SPECIAL_APP_ACCESS_ENERGY_OPTIMIZATION = 372310016
APPS_SPECIAL_APP_ACCESS_USAGE_ACCESS = 372375552
APPS_SPECIAL_APP_ACCESS_NOTIFICATION_ACCESS = 372441088
APPS_SPECIAL_APP_ACCESS_DISPLAY_OVER_OTHERS = 372506624
APPS_SPECIAL_APP_ACCESS_MODIFY_SYSTEM_SETTINGS = 372572160
APPS_SPECIAL_APP_ACCESS_PICTURE_IN_PICTURE = 372637696
APPS_SPECIAL_APP_ACCESS_ALARMS_AND_REMINDERS = 372703232
APPS_SECURITY_RESTRICTIONS = 373293056
APPS_SECURITY_RESTRICTIONS_UNKNOWN_SOURCES = 373358592
APPS_SECURITY_RESTRICTIONS_VERIFY_APPS = 373424128
APPS_SECURITY_RESTRICTIONS_CREATE_PROFILE = 373489664
APPS_SECURITY_RESTRICTIONS_ENTER_PROFILE = 373555200
APPS_SECURITY_RESTRICTIONS_PROFILE_ALLOWED_APPS = 373620736
APPS_SECURITY_RESTRICTIONS_PROFILE_CHANGE_PIN = 373686272
APPS_SECURITY_RESTRICTIONS_DELETE_PROFILE = 373751808
APPS_SECURITY_RESTRICTIONS_EXIT_PROFILE = 373817344
SYSTEM = 385875968
SYSTEM_ABOUT = 386924544
SYSTEM_ABOUT_SYSTEM_UPDATE = 386990080
SYSTEM_ABOUT_DEVICE_NAME = 387055616
SYSTEM_ABOUT_FACTORY_RESET = 387121152
SYSTEM_ABOUT_STATUS = 387186688
SYSTEM_ABOUT_LEGAL_INFO = 387252224
SYSTEM_ABOUT_LEGAL_INFO_OPEN_SOURCE = 387256320
SYSTEM_ABOUT_LEGAL_INFO_GOOGLE_LEGAL = 387260416
SYSTEM_ABOUT_LEGAL_INFO_SYSTEM_WEBVIEW = 387264512
SYSTEM_ABOUT_BUILD = 387317760
SYSTEM_DATE_TIME = 387973120
SYSTEM_DATE_TIME_AUTOMATIC = 388038656
SYSTEM_DATE_TIME_AUTOMATIC_USE_NETWORK_TIME = 388042752
SYSTEM_DATE_TIME_AUTOMATIC_OFF = 388046848
SYSTEM_DATE_TIME_SET_DATE = 388104192
SYSTEM_DATE_TIME_SET_TIME = 388169728
SYSTEM_DATE_TIME_SET_TIME_ZONE = 388235264
SYSTEM_DATE_TIME_SET_TIME_ZONE_BUTTON = 388239360
SYSTEM_DATE_TIME_USE_24_HOUR_FORMAT = 388300800
SYSTEM_LANGUAGE = 389021696
SYSTEM_LANGUAGE_BUTTON = 389087232
SYSTEM_KEYBOARD = 390070272
SYSTEM_KEYBOARD_CURRENT_KEYBOARD = 390135808
SYSTEM_KEYBOARD_GBOARD_SETTINGS = 390201344
SYSTEM_KEYBOARD_GBOARD_SETTINGS_LANGUAGES = 390205440
SYSTEM_KEYBOARD_GBOARD_SETTINGS_TOS = 390209536
SYSTEM_KEYBOARD_GBOARD_SETTINGS_PRIVACY_POLICY = 390213632
SYSTEM_KEYBOARD_GBOARD_SETTINGS_OPEN_SOURCE = 390217728
SYSTEM_KEYBOARD_GBOARD_SETTINGS_SHARE_USAGE_STATS = 390221824
SYSTEM_KEYBOARD_MANAGE_KEYBOARDS = 390266880
SYSTEM_STORAGE = 391118848
SYSTEM_STORAGE_INTERNAL_STORAGE = 391184384
SYSTEM_STORAGE_INTERNAL_STORAGE_APPS = 391188480
SYSTEM_STORAGE_INTERNAL_STORAGE_CACHED = 391192576
SYSTEM_AMBIENT = 392167424
SYSTEM_AMBIENT_START = 392232960
SYSTEM_AMBIENT_SETTINGS = 392298496
SYSTEM_AMBIENT_SETTINGS_CHANNEL_GP = 392302592
SYSTEM_AMBIENT_SETTINGS_CHANNEL_AG = 392306688
SYSTEM_AMBIENT_SETTINGS_CHANNEL_CV = 392310784
SYSTEM_AMBIENT_SETTINGS_CHANNEL_EXP = 392314880
SYSTEM_AMBIENT_SETTINGS_WEATHER = 392318976
SYSTEM_AMBIENT_SETTINGS_WEATHER_HIDE = 392319232
SYSTEM_AMBIENT_SETTINGS_WEATHER_UNIT_C = 392319488
SYSTEM_AMBIENT_SETTINGS_WEATHER_UNIT_F = 392319744
SYSTEM_AMBIENT_SETTINGS_WEATHER_UNIT_BOTH = 392320000
SYSTEM_AMBIENT_SETTINGS_TIME = 392323072
SYSTEM_AMBIENT_SETTINGS_TIME_HIDE = 392323328
SYSTEM_AMBIENT_SETTINGS_TIME_SHOW = 392323584
SYSTEM_AMBIENT_SETTINGS_DEVICE_INFO = 392327168
SYSTEM_AMBIENT_SETTINGS_DEVICE_INFO_HIDE = 392327424
SYSTEM_AMBIENT_SETTINGS_DEVICE_INFO_SHOW = 392327680
SYSTEM_AMBIENT_SETTINGS_PPD = 392331264
SYSTEM_AMBIENT_SETTINGS_PPD_HIDE = 392331520
SYSTEM_AMBIENT_SETTINGS_PPD_SHOW = 392331776
SYSTEM_AMBIENT_SETTINGS_PGP = 392335360
SYSTEM_AMBIENT_SETTINGS_PGP_HIDE = 392335616
SYSTEM_AMBIENT_SETTINGS_PGP_SHOW = 392335872
SYSTEM_AMBIENT_SETTINGS_PGP_SHOW_PAIRS = 392336128
SYSTEM_AMBIENT_SETTINGS_PPC = 392339456
SYSTEM_AMBIENT_SETTINGS_PPC_ALL_ALBUMS = 392339712
SYSTEM_AMBIENT_SETTINGS_PPC_LIVE_ALBUMS = 392339968
SYSTEM_AMBIENT_SETTINGS_SLIDE_SPEED = 392343552
SYSTEM_AMBIENT_SETTINGS_SLIDE_SPEED_5S = 392343808
SYSTEM_AMBIENT_SETTINGS_SLIDE_SPEED_10S = 392344064
SYSTEM_AMBIENT_SETTINGS_SLIDE_SPEED_30S = 392344320
SYSTEM_AMBIENT_SETTINGS_SLIDE_SPEED_1M = 392344576
SYSTEM_AMBIENT_SETTINGS_SLIDE_SPEED_3M = 392344832
SYSTEM_AMBIENT_SETTINGS_SLIDE_SPEED_5M = 392345088
SYSTEM_AMBIENT_SETTINGS_SLIDE_SPEED_10M = 392345344
SYSTEM_ENERGYSAVER = 393216000
SYSTEM_ENERGYSAVER_START_DELAY = 393281536
SYSTEM_ENERGYSAVER_START_DELAY_15M = 393285632
SYSTEM_ENERGYSAVER_START_DELAY_30M = 393289728
SYSTEM_ENERGYSAVER_START_DELAY_1H = 393293824
SYSTEM_ENERGYSAVER_START_DELAY_3H = 393297920
SYSTEM_ENERGYSAVER_START_DELAY_6H = 393302016
SYSTEM_ENERGYSAVER_START_DELAY_12H = 393306112
SYSTEM_ENERGYSAVER_START_DELAY_NEVER = 393310208
SYSTEM_A11Y = 394264576
SYSTEM_A11Y_CAPTIONS = 394330112
SYSTEM_A11Y_CAPTIONS_DISPLAY_ON_OFF = 394334208
SYSTEM_A11Y_CAPTIONS_LANGUAGE = 394338304
SYSTEM_A11Y_CAPTIONS_LANGUAGE_BUTTON = 394338560
SYSTEM_A11Y_CAPTIONS_TEXT_SIZE = 394342400
SYSTEM_A11Y_CAPTIONS_TEXT_SIZE_VERY_SMALL = 394342656
SYSTEM_A11Y_CAPTIONS_TEXT_SIZE_SMALL = 394342912
SYSTEM_A11Y_CAPTIONS_TEXT_SIZE_NORMAL = 394343168
SYSTEM_A11Y_CAPTIONS_TEXT_SIZE_LARGE = 394343424
SYSTEM_A11Y_CAPTIONS_TEXT_SIZE_VERY_LARGE = 394343680
SYSTEM_A11Y_CAPTIONS_WHITE_ON_BLACK = 394346496
SYSTEM_A11Y_CAPTIONS_BLACK_ON_WHITE = 394350592
SYSTEM_A11Y_CAPTIONS_YELLOW_ON_BLACK = 394354688
SYSTEM_A11Y_CAPTIONS_YELLOW_ON_BLUE = 394358784
SYSTEM_A11Y_CAPTIONS_CUSTOM = 394362880
SYSTEM_A11Y_CAPTIONS_CUSTOM_FONT = 394363136
SYSTEM_A11Y_CAPTIONS_CUSTOM_TEXT_COLOR = 394363392
SYSTEM_A11Y_CAPTIONS_CUSTOM_TEXT_OPACITY = 394363648
SYSTEM_A11Y_CAPTIONS_CUSTOM_EDGE_TYPE = 394363904
SYSTEM_A11Y_CAPTIONS_CUSTOM_EDGE_COLOR = 394364160
SYSTEM_A11Y_CAPTIONS_SHOW_BACKGROUND = 394364416
SYSTEM_A11Y_CAPTIONS_BACKGROUND_COLOR = 394364672
SYSTEM_A11Y_CAPTIONS_BACKGROUND_OPACITY = 394364928
SYSTEM_A11Y_CAPTIONS_SHOW_WINDOW = 394365184
SYSTEM_A11Y_CAPTIONS_WINDOW_COLOR = 394365440
SYSTEM_A11Y_CAPTIONS_WINDOW_OPACITY = 394365696
SYSTEM_A11Y_HIGH_CONTRAST_TEXT = 394395648
SYSTEM_A11Y_TTS = 394461184
SYSTEM_A11Y_TTS_ENGINE_SELECT = 394465280
SYSTEM_A11Y_TTS_ENGINE_CONFIG = 394469376
SYSTEM_A11Y_TTS_ENGINE_CONFIG_LANGUAGE = 394469632
SYSTEM_A11Y_TTS_ENGINE_CONFIG_LANGUAGE_CHOOSE_LANGUAGE = 394469648
SYSTEM_A11Y_TTS_ENGINE_CONFIG_SETTINGS_GTTS_ENGINE = 394469888
SYSTEM_A11Y_TTS_ENGINE_CONFIG_INSTALL_VOICE_DATA = 394470144
SYSTEM_A11Y_TTS_SPEECH_RATE = 394473472
SYSTEM_A11Y_TTS_LISTEN_EXAMPLE = 394477568
SYSTEM_A11Y_SHORTCUT = 394526720
SYSTEM_A11Y_SHORTCUT_ON_OFF = 394530816
SYSTEM_A11Y_SHORTCUT_SERVICE = 394534912
SYSTEM_A11Y_TALKBACK = 394592256
SYSTEM_A11Y_TALKBACK_ON_OFF = 394596352
SYSTEM_A11Y_TALKBACK_CONFIG = 394600448
SYSTEM_A11Y_A11Y_MENU = 394657792
SYSTEM_A11Y_A11Y_MENU_ON_OFF = 394661888
SYSTEM_A11Y_A11Y_MENU_CONFIG = 394665984
SYSTEM_A11Y_STS = 394723328
SYSTEM_A11Y_STS_ON_OFF = 394727424
SYSTEM_A11Y_STS_CONFIG = 394731520
SYSTEM_A11Y_SWITCH_ACCESS = 394788864
SYSTEM_A11Y_SWITCH_ACCESS_ON_OFF = 394792960
SYSTEM_A11Y_SWITCH_ACCESS_CONFIG = 394797056
SYSTEM_REBOOT = 395313152
PREFERENCES_HOME_SCREEN = 396361728
PREFERENCES_HOME_SCREEN_CUSTOMIZE_CHANNELS = 396427264
PREFERENCES_HOME_SCREEN_CUSTOMIZE_CHANNELS_PN = 396431360
PREFERENCES_HOME_SCREEN_CUSTOMIZE_CHANNELS_PN_ON_OFF = 396431616
PREFERENCES_HOME_SCREEN_CUSTOMIZE_CHANNELS_PN_GPMT = 396431872
PREFERENCES_HOME_SCREEN_CUSTOMIZE_CHANNELS_PN_GPM = 396432128
PREFERENCES_HOME_SCREEN_CUSTOMIZE_CHANNELS_PN_PROMOTIONAL = 396432384
PREFERENCES_HOME_SCREEN_CUSTOMIZE_CHANNELS_HOME_SCREEN = 396435456
PREFERENCES_HOME_SCREEN_CUSTOMIZE_CHANNELS_PROMOTIONAL = 396439552
PREFERENCES_HOME_SCREEN_VIDEO_PREVIEWS = 396492800
PREFERENCES_HOME_SCREEN_AUDIO_PREVIEWS = 396558336
PREFERENCES_HOME_SCREEN_REORDER_APPS = 396623872
PREFERENCES_HOME_SCREEN_REORDER_GAMES = 396689408
PREFERENCES_HOME_SCREEN_ATVH_OPEN_SOURCE = 396754944
PREFERENCES_HOME_SCREEN_ATVCS_OPEN_SOURCE = 396820480
PREFERENCES_ASSISTANT = 397410304
PREFERENCES_ASSISTANT_ACCOUNTS = 397475840
PREFERENCES_ASSISTANT_ACCEPT_PERMISSIONS = 397541376
PREFERENCES_ASSISTANT_VIEW_PERMISSIONS = 397606912
PREFERENCES_ASSISTANT_SEARCHABLE_APPS = 303247360
PREFERENCES_ASSISTANT_SAFESEARCH_FILTER = 303239168
PREFERENCES_ASSISTANT_BLOCK_OFFENSIVE = 303243264
PREFERENCES_ASSISTANT_OPEN_SOURCE = 397672448
PREFERENCES_CHROMECAST_SHELL = 398458880
PREFERENCES_CHROMECAST_SHELL_OPEN_SOURCE = 398524416
PREFERENCES_SCREENSAVER = 399507456
PREFERENCES_SCREENSAVER_CHOOSER = 399572992
PREFERENCES_SCREENSAVER_CHOOSER_SCREEN_OFF = 399577088
PREFERENCES_SCREENSAVER_CHOOSER_BACKDROP = 399581184
PREFERENCES_SCREENSAVER_CHOOSER_COLORS = 399585280
PREFERENCES_SCREENSAVER_START_DELAY = 399638528
PREFERENCES_SCREENSAVER_START_DELAY_5M = 399642624
PREFERENCES_SCREENSAVER_START_DELAY_15M = 399646720
PREFERENCES_SCREENSAVER_START_DELAY_30M = 399650816
PREFERENCES_SCREENSAVER_START_DELAY_1H = 399654912
PREFERENCES_SCREENSAVER_START_DELAY_2H = 399659008
PREFERENCES_SCREENSAVER_START_NOW = 399704064
CONNECTED_SLICE = 402653184
CONNECTED_SLICE_CONNECT_NEW_DEVICES = 403701760
CONNECTED_SLICE_DEVICE_ENTRY = 404750336
CONNECTED_SLICE_DEVICE_ENTRY_UPDATE = 404815872
CONNECTED_SLICE_DEVICE_ENTRY_RENAME = 404881408
CONNECTED_SLICE_DEVICE_ENTRY_FORGET = 404946944
CONNECTED_SLICE_HDMICEC = 405798912
CONNECTED_SLICE_HDMICEC_ON_OFF = 405864448
CONNECTED_CLASSIC = 402653184
CONNECTED_CLASSIC_CONNECT_REMOTE = 403701760
CONNECTED_CLASSIC_DEVICE_ENTRY = 404750336
CONNECTED_CLASSIC_DEVICE_ENTRY_UPDATE = 404815872
CONNECTED_CLASSIC_DEVICE_ENTRY_RENAME = 404881408
CONNECTED_CLASSIC_DEVICE_ENTRY_FORGET = 404946944
CONNECTED_CLASSIC_HDMICEC = 405798912
CONNECTED_CLASSIC_HDMICEC_ON_OFF = 405864448
FEEDBACK = 419430400
FEEDBACK_SEND = 420478976


if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'B\017TvSettingsEnumsP\001'
  _ITEMID._options = None
  _ITEMID._serialized_options = b'\020\001'
  _ACTION._serialized_start=92
  _ACTION._serialized_end=267
  _ITEMID._serialized_start=270
  _ITEMID._serialized_end=14201
# @@protoc_insertion_point(module_scope)
