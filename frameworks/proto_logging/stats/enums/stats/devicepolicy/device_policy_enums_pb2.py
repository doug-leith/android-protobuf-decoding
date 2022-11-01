# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: frameworks/proto_logging/stats/enums/stats/devicepolicy/device_policy_enums.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\nQframeworks/proto_logging/stats/enums/stats/devicepolicy/device_policy_enums.proto\x12\x1a\x61ndroid.stats.devicepolicy*\xda:\n\x07\x45ventId\x12\x18\n\x14SET_PASSWORD_QUALITY\x10\x01\x12\x1f\n\x1bSET_PASSWORD_MINIMUM_LENGTH\x10\x02\x12 \n\x1cSET_PASSWORD_MINIMUM_NUMERIC\x10\x03\x12#\n\x1fSET_PASSWORD_MINIMUM_NON_LETTER\x10\x04\x12 \n\x1cSET_PASSWORD_MINIMUM_LETTERS\x10\x05\x12#\n\x1fSET_PASSWORD_MINIMUM_LOWER_CASE\x10\x06\x12#\n\x1fSET_PASSWORD_MINIMUM_UPPER_CASE\x10\x07\x12 \n\x1cSET_PASSWORD_MINIMUM_SYMBOLS\x10\x08\x12\"\n\x1eSET_KEYGUARD_DISABLED_FEATURES\x10\t\x12\x0c\n\x08LOCK_NOW\x10\n\x12\x19\n\x15WIPE_DATA_WITH_REASON\x10\x0b\x12\x18\n\x14\x41\x44\x44_USER_RESTRICTION\x10\x0c\x12\x1b\n\x17REMOVE_USER_RESTRICTION\x10\r\x12\x16\n\x12SET_SECURE_SETTING\x10\x0e\x12 \n\x1cSET_SECURITY_LOGGING_ENABLED\x10\x0f\x12\x1a\n\x16RETRIEVE_SECURITY_LOGS\x10\x10\x12%\n!RETRIEVE_PRE_REBOOT_SECURITY_LOGS\x10\x11\x12\x19\n\x15SET_PERMISSION_POLICY\x10\x12\x12\x1e\n\x1aSET_PERMISSION_GRANT_STATE\x10\x13\x12\x14\n\x10INSTALL_KEY_PAIR\x10\x14\x12\x13\n\x0fINSTALL_CA_CERT\x10\x15\x12\x1c\n\x18\x43HOOSE_PRIVATE_KEY_ALIAS\x10\x16\x12\x13\n\x0fREMOVE_KEY_PAIR\x10\x17\x12\x16\n\x12UNINSTALL_CA_CERTS\x10\x18\x12\x1e\n\x1aSET_CERT_INSTALLER_PACKAGE\x10\x19\x12\x1d\n\x19SET_ALWAYS_ON_VPN_PACKAGE\x10\x1a\x12\x1f\n\x1bSET_PERMITTED_INPUT_METHODS\x10\x1b\x12(\n$SET_PERMITTED_ACCESSIBILITY_SERVICES\x10\x1c\x12\x1f\n\x1bSET_SCREEN_CAPTURE_DISABLED\x10\x1d\x12\x17\n\x13SET_CAMERA_DISABLED\x10\x1e\x12\x1a\n\x16QUERY_SUMMARY_FOR_USER\x10\x1f\x12\x11\n\rQUERY_SUMMARY\x10 \x12\x11\n\rQUERY_DETAILS\x10!\x12\n\n\x06REBOOT\x10\"\x12\x1b\n\x17SET_MASTER_VOLUME_MUTED\x10#\x12\x1a\n\x16SET_AUTO_TIME_REQUIRED\x10$\x12\x19\n\x15SET_KEYGUARD_DISABLED\x10%\x12\x1b\n\x17SET_STATUS_BAR_DISABLED\x10&\x12\x1a\n\x16SET_ORGANIZATION_COLOR\x10\'\x12\x14\n\x10SET_PROFILE_NAME\x10(\x12\x11\n\rSET_USER_ICON\x10)\x12%\n!SET_DEVICE_OWNER_LOCK_SCREEN_INFO\x10*\x12\x1d\n\x19SET_SHORT_SUPPORT_MESSAGE\x10+\x12\x1c\n\x18SET_LONG_SUPPORT_MESSAGE\x10,\x12.\n*SET_CROSS_PROFILE_CONTACTS_SEARCH_DISABLED\x10-\x12(\n$SET_CROSS_PROFILE_CALLER_ID_DISABLED\x10.\x12*\n&SET_BLUETOOTH_CONTACT_SHARING_DISABLED\x10/\x12#\n\x1f\x41\x44\x44_CROSS_PROFILE_INTENT_FILTER\x10\x30\x12%\n!ADD_CROSS_PROFILE_WIDGET_PROVIDER\x10\x31\x12\x1c\n\x18SET_SYSTEM_UPDATE_POLICY\x10\x32\x12\x1d\n\x19SET_LOCKTASK_MODE_ENABLED\x10\x33\x12%\n!ADD_PERSISTENT_PREFERRED_ACTIVITY\x10\x34\x12\x15\n\x11REQUEST_BUGREPORT\x10\x35\x12\x18\n\x14GET_WIFI_MAC_ADDRESS\x10\x36\x12\x1e\n\x1aREQUEST_QUIET_MODE_ENABLED\x10\x37\x12!\n\x1dWORK_PROFILE_LOCATION_CHANGED\x10\x38\x12\x18\n\x14\x44O_USER_INFO_CLICKED\x10\x39\x12\x16\n\x12TRANSFER_OWNERSHIP\x10:\x12\x15\n\x11GENERATE_KEY_PAIR\x10;\x12\x1c\n\x18SET_KEY_PAIR_CERTIFICATE\x10<\x12!\n\x1dSET_KEEP_UNINSTALLED_PACKAGES\x10=\x12 \n\x1cSET_APPLICATION_RESTRICTIONS\x10>\x12\x1a\n\x16SET_APPLICATION_HIDDEN\x10?\x12\x15\n\x11\x45NABLE_SYSTEM_APP\x10@\x12!\n\x1d\x45NABLE_SYSTEM_APP_WITH_INTENT\x10\x41\x12\x1c\n\x18INSTALL_EXISTING_PACKAGE\x10\x42\x12\x19\n\x15SET_UNINSTALL_BLOCKED\x10\x43\x12\x1a\n\x16SET_PACKAGES_SUSPENDED\x10\x44\x12\x1e\n\x1aON_LOCK_TASK_MODE_ENTERING\x10\x45\x12\'\n#SET_CROSS_PROFILE_CALENDAR_PACKAGES\x10\x46\x12&\n\"GET_USER_PASSWORD_COMPLEXITY_LEVEL\x10H\x12\x19\n\x15INSTALL_SYSTEM_UPDATE\x10I\x12\x1f\n\x1bINSTALL_SYSTEM_UPDATE_ERROR\x10J\x12\x14\n\x10IS_MANAGED_KIOSK\x10K\x12\x1f\n\x1bIS_UNATTENDED_MANAGED_KIOSK\x10L\x12\x38\n4PROVISIONING_MANAGED_PROFILE_ON_FULLY_MANAGED_DEVICE\x10M\x12(\n$PROVISIONING_PERSISTENT_DEVICE_OWNER\x10N\x12 \n\x1cPROVISIONING_ENTRY_POINT_NFC\x10O\x12$\n PROVISIONING_ENTRY_POINT_QR_CODE\x10P\x12-\n)PROVISIONING_ENTRY_POINT_CLOUD_ENROLLMENT\x10Q\x12 \n\x1cPROVISIONING_ENTRY_POINT_ADB\x10R\x12+\n\'PROVISIONING_ENTRY_POINT_TRUSTED_SOURCE\x10S\x12!\n\x1dPROVISIONING_DPC_PACKAGE_NAME\x10T\x12)\n%PROVISIONING_DPC_INSTALLED_BY_PACKAGE\x10U\x12.\n*PROVISIONING_PROVISIONING_ACTIVITY_TIME_MS\x10V\x12\x31\n-PROVISIONING_PREPROVISIONING_ACTIVITY_TIME_MS\x10W\x12\x30\n,PROVISIONING_ENCRYPT_DEVICE_ACTIVITY_TIME_MS\x10X\x12%\n!PROVISIONING_WEB_ACTIVITY_TIME_MS\x10Y\x12\x30\n(PROVISIONING_TRAMPOLINE_ACTIVITY_TIME_MS\x10Z\x1a\x02\x08\x01\x12\x35\n-PROVISIONING_POST_ENCRYPTION_ACTIVITY_TIME_MS\x10[\x1a\x02\x08\x01\x12\x32\n*PROVISIONING_FINALIZATION_ACTIVITY_TIME_MS\x10\\\x1a\x02\x08\x01\x12\x1d\n\x19PROVISIONING_NETWORK_TYPE\x10]\x12\x17\n\x13PROVISIONING_ACTION\x10^\x12\x17\n\x13PROVISIONING_EXTRAS\x10_\x12%\n!PROVISIONING_COPY_ACCOUNT_TASK_MS\x10`\x12\'\n#PROVISIONING_CREATE_PROFILE_TASK_MS\x10\x61\x12&\n\"PROVISIONING_START_PROFILE_TASK_MS\x10\x62\x12)\n%PROVISIONING_DOWNLOAD_PACKAGE_TASK_MS\x10\x63\x12(\n$PROVISIONING_INSTALL_PACKAGE_TASK_MS\x10\x64\x12\x1a\n\x16PROVISIONING_CANCELLED\x10\x65\x12\x16\n\x12PROVISIONING_ERROR\x10\x66\x12$\n PROVISIONING_COPY_ACCOUNT_STATUS\x10g\x12#\n\x1fPROVISIONING_TOTAL_TASK_TIME_MS\x10h\x12 \n\x1cPROVISIONING_SESSION_STARTED\x10i\x12\"\n\x1ePROVISIONING_SESSION_COMPLETED\x10j\x12\'\n#PROVISIONING_TERMS_ACTIVITY_TIME_MS\x10k\x12\x1c\n\x18PROVISIONING_TERMS_COUNT\x10l\x12\x1b\n\x17PROVISIONING_TERMS_READ\x10m\x12&\n\"SEPARATE_PROFILE_CHALLENGE_CHANGED\x10n\x12\x16\n\x12SET_GLOBAL_SETTING\x10o\x12\x13\n\x0fINSTALL_PACKAGE\x10p\x12\x15\n\x11UNINSTALL_PACKAGE\x10q\x12(\n$WIFI_SERVICE_ADD_NETWORK_SUGGESTIONS\x10r\x12&\n\"WIFI_SERVICE_ADD_OR_UPDATE_NETWORK\x10s\x12\x1c\n\x18QUERY_SUMMARY_FOR_DEVICE\x10t\x12(\n$REMOVE_CROSS_PROFILE_WIDGET_PROVIDER\x10u\x12\x11\n\rESTABLISH_VPN\x10v\x12\x1f\n\x1bSET_NETWORK_LOGGING_ENABLED\x10w\x12\x19\n\x15RETRIEVE_NETWORK_LOGS\x10x\x12&\n\"PROVISIONING_PREPARE_TOTAL_TIME_MS\x10y\x12 \n\x1cPROVISIONING_PREPARE_STARTED\x10z\x12\"\n\x1ePROVISIONING_PREPARE_COMPLETED\x10{\x12\x1a\n\x16PROVISIONING_FLOW_TYPE\x10|\x12/\n+CROSS_PROFILE_APPS_GET_TARGET_USER_PROFILES\x10}\x12-\n)CROSS_PROFILE_APPS_START_ACTIVITY_AS_USER\x10~\x12\x11\n\rSET_AUTO_TIME\x10\x7f\x12\x17\n\x12SET_AUTO_TIME_ZONE\x10\x80\x01\x12\'\n\"SET_USER_CONTROL_DISABLED_PACKAGES\x10\x81\x01\x12!\n\x1cSET_FACTORY_RESET_PROTECTION\x10\x82\x01\x12\x1d\n\x18SET_COMMON_CRITERIA_MODE\x10\x83\x01\x12\x34\n/ALLOW_MODIFICATION_OF_ADMIN_CONFIGURED_NETWORKS\x10\x84\x01\x12\r\n\x08SET_TIME\x10\x85\x01\x12\x12\n\rSET_TIME_ZONE\x10\x86\x01\x12 \n\x1bSET_PERSONAL_APPS_SUSPENDED\x10\x87\x01\x12)\n$SET_MANAGED_PROFILE_MAXIMUM_TIME_OFF\x10\x88\x01\x12\"\n\x1d\x43OMP_TO_ORG_OWNED_PO_MIGRATED\x10\x89\x01\x12\x1f\n\x1aSET_CROSS_PROFILE_PACKAGES\x10\x8a\x01\x12(\n#SET_INTERACT_ACROSS_PROFILES_APP_OP\x10\x8b\x01\x12\x1f\n\x1aGET_CROSS_PROFILE_PACKAGES\x10\x8c\x01\x12.\n)CAN_REQUEST_INTERACT_ACROSS_PROFILES_TRUE\x10\x8d\x01\x12;\n6CAN_REQUEST_INTERACT_ACROSS_PROFILES_FALSE_NO_PROFILES\x10\x8e\x01\x12\x39\n4CAN_REQUEST_INTERACT_ACROSS_PROFILES_FALSE_WHITELIST\x10\x8f\x01\x12:\n5CAN_REQUEST_INTERACT_ACROSS_PROFILES_FALSE_PERMISSION\x10\x90\x01\x12&\n!CAN_INTERACT_ACROSS_PROFILES_TRUE\x10\x91\x01\x12\x32\n-CAN_INTERACT_ACROSS_PROFILES_FALSE_PERMISSION\x10\x92\x01\x12\x33\n.CAN_INTERACT_ACROSS_PROFILES_FALSE_NO_PROFILES\x10\x93\x01\x12 \n\x1b\x43REATE_CROSS_PROFILE_INTENT\x10\x94\x01\x12\x17\n\x12IS_MANAGED_PROFILE\x10\x95\x01\x12\x1d\n\x18START_ACTIVITY_BY_INTENT\x10\x96\x01\x12\x1f\n\x1a\x42IND_CROSS_PROFILE_SERVICE\x10\x97\x01\x12#\n\x1ePROVISIONING_DPC_SETUP_STARTED\x10\x98\x01\x12%\n PROVISIONING_DPC_SETUP_COMPLETED\x10\x99\x01\x12\x34\n/PROVISIONING_ORGANIZATION_OWNED_MANAGED_PROFILE\x10\x9a\x01\x12)\n$RESOLVER_CROSS_PROFILE_TARGET_OPENED\x10\x9b\x01\x12\x19\n\x14RESOLVER_SWITCH_TABS\x10\x9c\x01\x12,\n\'RESOLVER_EMPTY_STATE_WORK_APPS_DISABLED\x10\x9d\x01\x12\x30\n+RESOLVER_EMPTY_STATE_NO_SHARING_TO_PERSONAL\x10\x9e\x01\x12,\n\'RESOLVER_EMPTY_STATE_NO_SHARING_TO_WORK\x10\x9f\x01\x12*\n%RESOLVER_EMPTY_STATE_NO_APPS_RESOLVED\x10\xa0\x01\x12-\n(RESOLVER_AUTOLAUNCH_CROSS_PROFILE_TARGET\x10\xa1\x01\x12\x32\n-CROSS_PROFILE_SETTINGS_PAGE_LAUNCHED_FROM_APP\x10\xa2\x01\x12\x37\n2CROSS_PROFILE_SETTINGS_PAGE_LAUNCHED_FROM_SETTINGS\x10\xa3\x01\x12\x31\n,CROSS_PROFILE_SETTINGS_PAGE_ADMIN_RESTRICTED\x10\xa4\x01\x12\x31\n,CROSS_PROFILE_SETTINGS_PAGE_MISSING_WORK_APP\x10\xa5\x01\x12\x35\n0CROSS_PROFILE_SETTINGS_PAGE_MISSING_PERSONAL_APP\x10\xa6\x01\x12>\n9CROSS_PROFILE_SETTINGS_PAGE_MISSING_INSTALL_BANNER_INTENT\x10\xa7\x01\x12\x37\n2CROSS_PROFILE_SETTINGS_PAGE_INSTALL_BANNER_CLICKED\x10\xa8\x01\x12\x41\n<CROSS_PROFILE_SETTINGS_PAGE_INSTALL_BANNER_NO_INTENT_CLICKED\x10\xa9\x01\x12/\n*CROSS_PROFILE_SETTINGS_PAGE_USER_CONSENTED\x10\xaa\x01\x12\x36\n1CROSS_PROFILE_SETTINGS_PAGE_USER_DECLINED_CONSENT\x10\xab\x01\x12\x33\n.CROSS_PROFILE_SETTINGS_PAGE_PERMISSION_REVOKED\x10\xac\x01\x12%\n DOCSUI_EMPTY_STATE_NO_PERMISSION\x10\xad\x01\x12\"\n\x1d\x44OCSUI_EMPTY_STATE_QUIET_MODE\x10\xae\x01\x12\x1c\n\x17\x44OCSUI_LAUNCH_OTHER_APP\x10\xaf\x01\x12\x17\n\x12\x44OCSUI_PICK_RESULT\x10\xb0\x01\x12\x1c\n\x17SET_PASSWORD_COMPLEXITY\x10\xb1\x01\x12+\n&CREDENTIAL_MANAGEMENT_APP_REQUEST_NAME\x10\xb2\x01\x12-\n(CREDENTIAL_MANAGEMENT_APP_REQUEST_POLICY\x10\xb3\x01\x12/\n*CREDENTIAL_MANAGEMENT_APP_REQUEST_ACCEPTED\x10\xb4\x01\x12-\n(CREDENTIAL_MANAGEMENT_APP_REQUEST_DENIED\x10\xb5\x01\x12-\n(CREDENTIAL_MANAGEMENT_APP_REQUEST_FAILED\x10\xb6\x01\x12\x39\n4CREDENTIAL_MANAGEMENT_APP_CREDENTIAL_FOUND_IN_POLICY\x10\xb7\x01\x12\x36\n1CREDENTIAL_MANAGEMENT_APP_INSTALL_KEY_PAIR_FAILED\x10\xb8\x01\x12\x37\n2CREDENTIAL_MANAGEMENT_APP_GENERATE_KEY_PAIR_FAILED\x10\xb9\x01\x12\x33\n.CREDENTIAL_MANAGEMENT_APP_POLICY_LOOKUP_FAILED\x10\xba\x01\x12&\n!CREDENTIAL_MANAGEMENT_APP_REMOVED\x10\xbb\x01\x12\x18\n\x13SET_ORGANIZATION_ID\x10\xbc\x01\x12-\n(IS_ACTIVE_PASSWORD_SUFFICIENT_FOR_DEVICE\x10\xbd\x01\x12*\n%PLATFORM_PROVISIONING_COPY_ACCOUNT_MS\x10\xbe\x01\x12,\n\'PLATFORM_PROVISIONING_CREATE_PROFILE_MS\x10\xbf\x01\x12+\n&PLATFORM_PROVISIONING_START_PROFILE_MS\x10\xc0\x01\x12.\n)PLATFORM_PROVISIONING_COPY_ACCOUNT_STATUS\x10\xc1\x01\x12 \n\x1bPLATFORM_PROVISIONING_ERROR\x10\xc2\x01\x12\x33\n.PROVISIONING_PROVISION_MANAGED_PROFILE_TASK_MS\x10\xc3\x01\x12\x38\n3PROVISIONING_PROVISION_FULLY_MANAGED_DEVICE_TASK_MS\x10\xc4\x01\x12 \n\x1bPLATFORM_PROVISIONING_PARAM\x10\xc5\x01\x12\x1b\n\x16SET_USB_DATA_SIGNALING\x10\xc6\x01\x12-\n(SET_PREFERENTIAL_NETWORK_SERVICE_ENABLED\x10\xc7\x01\x12\x1e\n\x19PROVISIONING_IS_LANDSCAPE\x10\xc8\x01\x12\x1f\n\x1aPROVISIONING_IS_NIGHT_MODE\x10\xc9\x01\x12\x10\n\x0b\x41\x44\x44_ACCOUNT\x10\xca\x01\x12\x1b\n\x16\x41\x44\x44_ACCOUNT_EXPLICITLY\x10\xcb\x01\x12\x1b\n\x16GET_ACCOUNT_AUTH_TOKEN\x10\xcc\x01\x12\x13\n\x0eRESET_PASSWORD\x10\xcd\x01\x12\x1e\n\x19RESET_PASSWORD_WITH_TOKEN\x10\xce\x01\x42\x02P\x01')

_EVENTID = DESCRIPTOR.enum_types_by_name['EventId']
EventId = enum_type_wrapper.EnumTypeWrapper(_EVENTID)
SET_PASSWORD_QUALITY = 1
SET_PASSWORD_MINIMUM_LENGTH = 2
SET_PASSWORD_MINIMUM_NUMERIC = 3
SET_PASSWORD_MINIMUM_NON_LETTER = 4
SET_PASSWORD_MINIMUM_LETTERS = 5
SET_PASSWORD_MINIMUM_LOWER_CASE = 6
SET_PASSWORD_MINIMUM_UPPER_CASE = 7
SET_PASSWORD_MINIMUM_SYMBOLS = 8
SET_KEYGUARD_DISABLED_FEATURES = 9
LOCK_NOW = 10
WIPE_DATA_WITH_REASON = 11
ADD_USER_RESTRICTION = 12
REMOVE_USER_RESTRICTION = 13
SET_SECURE_SETTING = 14
SET_SECURITY_LOGGING_ENABLED = 15
RETRIEVE_SECURITY_LOGS = 16
RETRIEVE_PRE_REBOOT_SECURITY_LOGS = 17
SET_PERMISSION_POLICY = 18
SET_PERMISSION_GRANT_STATE = 19
INSTALL_KEY_PAIR = 20
INSTALL_CA_CERT = 21
CHOOSE_PRIVATE_KEY_ALIAS = 22
REMOVE_KEY_PAIR = 23
UNINSTALL_CA_CERTS = 24
SET_CERT_INSTALLER_PACKAGE = 25
SET_ALWAYS_ON_VPN_PACKAGE = 26
SET_PERMITTED_INPUT_METHODS = 27
SET_PERMITTED_ACCESSIBILITY_SERVICES = 28
SET_SCREEN_CAPTURE_DISABLED = 29
SET_CAMERA_DISABLED = 30
QUERY_SUMMARY_FOR_USER = 31
QUERY_SUMMARY = 32
QUERY_DETAILS = 33
REBOOT = 34
SET_MASTER_VOLUME_MUTED = 35
SET_AUTO_TIME_REQUIRED = 36
SET_KEYGUARD_DISABLED = 37
SET_STATUS_BAR_DISABLED = 38
SET_ORGANIZATION_COLOR = 39
SET_PROFILE_NAME = 40
SET_USER_ICON = 41
SET_DEVICE_OWNER_LOCK_SCREEN_INFO = 42
SET_SHORT_SUPPORT_MESSAGE = 43
SET_LONG_SUPPORT_MESSAGE = 44
SET_CROSS_PROFILE_CONTACTS_SEARCH_DISABLED = 45
SET_CROSS_PROFILE_CALLER_ID_DISABLED = 46
SET_BLUETOOTH_CONTACT_SHARING_DISABLED = 47
ADD_CROSS_PROFILE_INTENT_FILTER = 48
ADD_CROSS_PROFILE_WIDGET_PROVIDER = 49
SET_SYSTEM_UPDATE_POLICY = 50
SET_LOCKTASK_MODE_ENABLED = 51
ADD_PERSISTENT_PREFERRED_ACTIVITY = 52
REQUEST_BUGREPORT = 53
GET_WIFI_MAC_ADDRESS = 54
REQUEST_QUIET_MODE_ENABLED = 55
WORK_PROFILE_LOCATION_CHANGED = 56
DO_USER_INFO_CLICKED = 57
TRANSFER_OWNERSHIP = 58
GENERATE_KEY_PAIR = 59
SET_KEY_PAIR_CERTIFICATE = 60
SET_KEEP_UNINSTALLED_PACKAGES = 61
SET_APPLICATION_RESTRICTIONS = 62
SET_APPLICATION_HIDDEN = 63
ENABLE_SYSTEM_APP = 64
ENABLE_SYSTEM_APP_WITH_INTENT = 65
INSTALL_EXISTING_PACKAGE = 66
SET_UNINSTALL_BLOCKED = 67
SET_PACKAGES_SUSPENDED = 68
ON_LOCK_TASK_MODE_ENTERING = 69
SET_CROSS_PROFILE_CALENDAR_PACKAGES = 70
GET_USER_PASSWORD_COMPLEXITY_LEVEL = 72
INSTALL_SYSTEM_UPDATE = 73
INSTALL_SYSTEM_UPDATE_ERROR = 74
IS_MANAGED_KIOSK = 75
IS_UNATTENDED_MANAGED_KIOSK = 76
PROVISIONING_MANAGED_PROFILE_ON_FULLY_MANAGED_DEVICE = 77
PROVISIONING_PERSISTENT_DEVICE_OWNER = 78
PROVISIONING_ENTRY_POINT_NFC = 79
PROVISIONING_ENTRY_POINT_QR_CODE = 80
PROVISIONING_ENTRY_POINT_CLOUD_ENROLLMENT = 81
PROVISIONING_ENTRY_POINT_ADB = 82
PROVISIONING_ENTRY_POINT_TRUSTED_SOURCE = 83
PROVISIONING_DPC_PACKAGE_NAME = 84
PROVISIONING_DPC_INSTALLED_BY_PACKAGE = 85
PROVISIONING_PROVISIONING_ACTIVITY_TIME_MS = 86
PROVISIONING_PREPROVISIONING_ACTIVITY_TIME_MS = 87
PROVISIONING_ENCRYPT_DEVICE_ACTIVITY_TIME_MS = 88
PROVISIONING_WEB_ACTIVITY_TIME_MS = 89
PROVISIONING_TRAMPOLINE_ACTIVITY_TIME_MS = 90
PROVISIONING_POST_ENCRYPTION_ACTIVITY_TIME_MS = 91
PROVISIONING_FINALIZATION_ACTIVITY_TIME_MS = 92
PROVISIONING_NETWORK_TYPE = 93
PROVISIONING_ACTION = 94
PROVISIONING_EXTRAS = 95
PROVISIONING_COPY_ACCOUNT_TASK_MS = 96
PROVISIONING_CREATE_PROFILE_TASK_MS = 97
PROVISIONING_START_PROFILE_TASK_MS = 98
PROVISIONING_DOWNLOAD_PACKAGE_TASK_MS = 99
PROVISIONING_INSTALL_PACKAGE_TASK_MS = 100
PROVISIONING_CANCELLED = 101
PROVISIONING_ERROR = 102
PROVISIONING_COPY_ACCOUNT_STATUS = 103
PROVISIONING_TOTAL_TASK_TIME_MS = 104
PROVISIONING_SESSION_STARTED = 105
PROVISIONING_SESSION_COMPLETED = 106
PROVISIONING_TERMS_ACTIVITY_TIME_MS = 107
PROVISIONING_TERMS_COUNT = 108
PROVISIONING_TERMS_READ = 109
SEPARATE_PROFILE_CHALLENGE_CHANGED = 110
SET_GLOBAL_SETTING = 111
INSTALL_PACKAGE = 112
UNINSTALL_PACKAGE = 113
WIFI_SERVICE_ADD_NETWORK_SUGGESTIONS = 114
WIFI_SERVICE_ADD_OR_UPDATE_NETWORK = 115
QUERY_SUMMARY_FOR_DEVICE = 116
REMOVE_CROSS_PROFILE_WIDGET_PROVIDER = 117
ESTABLISH_VPN = 118
SET_NETWORK_LOGGING_ENABLED = 119
RETRIEVE_NETWORK_LOGS = 120
PROVISIONING_PREPARE_TOTAL_TIME_MS = 121
PROVISIONING_PREPARE_STARTED = 122
PROVISIONING_PREPARE_COMPLETED = 123
PROVISIONING_FLOW_TYPE = 124
CROSS_PROFILE_APPS_GET_TARGET_USER_PROFILES = 125
CROSS_PROFILE_APPS_START_ACTIVITY_AS_USER = 126
SET_AUTO_TIME = 127
SET_AUTO_TIME_ZONE = 128
SET_USER_CONTROL_DISABLED_PACKAGES = 129
SET_FACTORY_RESET_PROTECTION = 130
SET_COMMON_CRITERIA_MODE = 131
ALLOW_MODIFICATION_OF_ADMIN_CONFIGURED_NETWORKS = 132
SET_TIME = 133
SET_TIME_ZONE = 134
SET_PERSONAL_APPS_SUSPENDED = 135
SET_MANAGED_PROFILE_MAXIMUM_TIME_OFF = 136
COMP_TO_ORG_OWNED_PO_MIGRATED = 137
SET_CROSS_PROFILE_PACKAGES = 138
SET_INTERACT_ACROSS_PROFILES_APP_OP = 139
GET_CROSS_PROFILE_PACKAGES = 140
CAN_REQUEST_INTERACT_ACROSS_PROFILES_TRUE = 141
CAN_REQUEST_INTERACT_ACROSS_PROFILES_FALSE_NO_PROFILES = 142
CAN_REQUEST_INTERACT_ACROSS_PROFILES_FALSE_WHITELIST = 143
CAN_REQUEST_INTERACT_ACROSS_PROFILES_FALSE_PERMISSION = 144
CAN_INTERACT_ACROSS_PROFILES_TRUE = 145
CAN_INTERACT_ACROSS_PROFILES_FALSE_PERMISSION = 146
CAN_INTERACT_ACROSS_PROFILES_FALSE_NO_PROFILES = 147
CREATE_CROSS_PROFILE_INTENT = 148
IS_MANAGED_PROFILE = 149
START_ACTIVITY_BY_INTENT = 150
BIND_CROSS_PROFILE_SERVICE = 151
PROVISIONING_DPC_SETUP_STARTED = 152
PROVISIONING_DPC_SETUP_COMPLETED = 153
PROVISIONING_ORGANIZATION_OWNED_MANAGED_PROFILE = 154
RESOLVER_CROSS_PROFILE_TARGET_OPENED = 155
RESOLVER_SWITCH_TABS = 156
RESOLVER_EMPTY_STATE_WORK_APPS_DISABLED = 157
RESOLVER_EMPTY_STATE_NO_SHARING_TO_PERSONAL = 158
RESOLVER_EMPTY_STATE_NO_SHARING_TO_WORK = 159
RESOLVER_EMPTY_STATE_NO_APPS_RESOLVED = 160
RESOLVER_AUTOLAUNCH_CROSS_PROFILE_TARGET = 161
CROSS_PROFILE_SETTINGS_PAGE_LAUNCHED_FROM_APP = 162
CROSS_PROFILE_SETTINGS_PAGE_LAUNCHED_FROM_SETTINGS = 163
CROSS_PROFILE_SETTINGS_PAGE_ADMIN_RESTRICTED = 164
CROSS_PROFILE_SETTINGS_PAGE_MISSING_WORK_APP = 165
CROSS_PROFILE_SETTINGS_PAGE_MISSING_PERSONAL_APP = 166
CROSS_PROFILE_SETTINGS_PAGE_MISSING_INSTALL_BANNER_INTENT = 167
CROSS_PROFILE_SETTINGS_PAGE_INSTALL_BANNER_CLICKED = 168
CROSS_PROFILE_SETTINGS_PAGE_INSTALL_BANNER_NO_INTENT_CLICKED = 169
CROSS_PROFILE_SETTINGS_PAGE_USER_CONSENTED = 170
CROSS_PROFILE_SETTINGS_PAGE_USER_DECLINED_CONSENT = 171
CROSS_PROFILE_SETTINGS_PAGE_PERMISSION_REVOKED = 172
DOCSUI_EMPTY_STATE_NO_PERMISSION = 173
DOCSUI_EMPTY_STATE_QUIET_MODE = 174
DOCSUI_LAUNCH_OTHER_APP = 175
DOCSUI_PICK_RESULT = 176
SET_PASSWORD_COMPLEXITY = 177
CREDENTIAL_MANAGEMENT_APP_REQUEST_NAME = 178
CREDENTIAL_MANAGEMENT_APP_REQUEST_POLICY = 179
CREDENTIAL_MANAGEMENT_APP_REQUEST_ACCEPTED = 180
CREDENTIAL_MANAGEMENT_APP_REQUEST_DENIED = 181
CREDENTIAL_MANAGEMENT_APP_REQUEST_FAILED = 182
CREDENTIAL_MANAGEMENT_APP_CREDENTIAL_FOUND_IN_POLICY = 183
CREDENTIAL_MANAGEMENT_APP_INSTALL_KEY_PAIR_FAILED = 184
CREDENTIAL_MANAGEMENT_APP_GENERATE_KEY_PAIR_FAILED = 185
CREDENTIAL_MANAGEMENT_APP_POLICY_LOOKUP_FAILED = 186
CREDENTIAL_MANAGEMENT_APP_REMOVED = 187
SET_ORGANIZATION_ID = 188
IS_ACTIVE_PASSWORD_SUFFICIENT_FOR_DEVICE = 189
PLATFORM_PROVISIONING_COPY_ACCOUNT_MS = 190
PLATFORM_PROVISIONING_CREATE_PROFILE_MS = 191
PLATFORM_PROVISIONING_START_PROFILE_MS = 192
PLATFORM_PROVISIONING_COPY_ACCOUNT_STATUS = 193
PLATFORM_PROVISIONING_ERROR = 194
PROVISIONING_PROVISION_MANAGED_PROFILE_TASK_MS = 195
PROVISIONING_PROVISION_FULLY_MANAGED_DEVICE_TASK_MS = 196
PLATFORM_PROVISIONING_PARAM = 197
SET_USB_DATA_SIGNALING = 198
SET_PREFERENTIAL_NETWORK_SERVICE_ENABLED = 199
PROVISIONING_IS_LANDSCAPE = 200
PROVISIONING_IS_NIGHT_MODE = 201
ADD_ACCOUNT = 202
ADD_ACCOUNT_EXPLICITLY = 203
GET_ACCOUNT_AUTH_TOKEN = 204
RESET_PASSWORD = 205
RESET_PASSWORD_WITH_TOKEN = 206


if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'P\001'
  _EVENTID.values_by_name["PROVISIONING_TRAMPOLINE_ACTIVITY_TIME_MS"]._options = None
  _EVENTID.values_by_name["PROVISIONING_TRAMPOLINE_ACTIVITY_TIME_MS"]._serialized_options = b'\010\001'
  _EVENTID.values_by_name["PROVISIONING_POST_ENCRYPTION_ACTIVITY_TIME_MS"]._options = None
  _EVENTID.values_by_name["PROVISIONING_POST_ENCRYPTION_ACTIVITY_TIME_MS"]._serialized_options = b'\010\001'
  _EVENTID.values_by_name["PROVISIONING_FINALIZATION_ACTIVITY_TIME_MS"]._options = None
  _EVENTID.values_by_name["PROVISIONING_FINALIZATION_ACTIVITY_TIME_MS"]._serialized_options = b'\010\001'
  _EVENTID._serialized_start=114
  _EVENTID._serialized_end=7628
# @@protoc_insertion_point(module_scope)