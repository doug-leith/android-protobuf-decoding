import subprocess
import sys
import os
import re


# add folder where this script is to python search path (so can find helpers)
mypath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(mypath)
import app_measurement_pb2


def makeIter(tt):
    try:
        iterator = iter(tt)
    except TypeError:
        # not iterable
        tt=[tt]
    return tt


a = ["ga_conversion", "engagement_time_msec", "exposure_time", "ad_event_id", "ad_unit_id", "ga_error", "ga_error_value", "ga_error_length", "ga_event_origin", "ga_screen", "ga_screen_class", "ga_screen_id", "ga_previous_screen", "ga_previous_class", "ga_previous_id", "message_device_time", "message_id", "message_name", "message_time", "message_tracking_id", "message_type", "previous_app_version", "previous_os_version", "topic", "update_with_analytics", "previous_first_open_count", "system_app", "system_app_update", "previous_install_count", "ga_event_id", "ga_extra_params_ct", "ga_group_name", "ga_list_length", "ga_index", "ga_event_name", "campaign_info_source", "deferred_analytics_collection", "ga_session_number", "ga_session_id", "campaign_extra_referrer", "app_in_background", "firebase_feature_rollouts", "firebase_conversion", "firebase_error", "firebase_error_value", "firebase_error_length", "firebase_event_origin", "firebase_screen", "firebase_screen_class", "firebase_screen_id", "firebase_previous_screen", "firebase_previous_class", "firebase_previous_id", "session_number", "session_id", "app_background", "app_clear_data", "app_exception", "app_remove", "app_upgrade", "app_install", "app_update", "ga_campaign", "error", "first_open", "first_visit", "in_app_purchase", "notification_dismiss", "notification_foreground", "notification_open", "notification_receive", "os_update", "session_start", "user_engagement", "ad_exposure", "adunit_exposure", "ad_query", "ad_activeview", "ad_impression", "ad_click", "ad_reward", "screen_view", "ga_extra_parameter", "session_start_with_rollout", "firebase_campaign", "lifetime_engagement", "session_scoped_engagement","realtime", "first_install"];

b = ["_c", "_et", "_xt", "_aeid", "_ai", "_err", "_ev", "_el", "_o", "_sn", "_sc", "_si", "_pn", "_pc", "_pi", "_ndt", "_nmid", "_nmn", "_nmt", "_nmtid", "_nmc", "_pv", "_po", "_nt", "_uwa", "_pfo", "_sys", "_sysu", "_pin", "_eid", "_epc", "_gn", "_ll", "_i", "_en", "_cis", "_dac", "_sno", "_sid", "_cer", "_aib", "_ffr", "_c", "_err", "_ev", "_el", "_o", "_sn", "_sc", "_si", "_pn", "_pc", "_pi", "_sno", "_sid","_ab", "_cd", "_ae", "_ui", "_ug", "_in", "_au", "_cmp", "_err", "_f", "_v", "_iap", "_nd", "_nf", "_no", "_nr", "_ou", "_s", "_e", "_xa", "_xu", "_aq", "_aa", "_ai", "_ac", "_ar", "_vs", "_ep", "_ssr", "_cmp", "_lte", "_se","_r","_fi"];

# remove duplicates
code2str = {}
for i in range(len(b)):
    code2str[b[i]] = a[i]

try:
    if len(sys.argv)>1:
        fname=sys.argv[1]
    else:
        fname='/tmp/appmeas_bytes'
    decoded = subprocess.check_output("protoc --decode=\"POST_body\" -I='"+mypath+"' app_measurement.proto3  <"+fname,shell=True,stderr=subprocess.STDOUT, text=True)

    for code in code2str.keys():
        decoded = decoded.replace('"'+code+'"', '"'+code+'"'+' // '+code2str[code])

    if True:  # for easy grepping
        try:
            f = open(fname, 'rb')
            firebase_bytes = f.read()
            f.close()
            firebase = app_measurement_pb2.POST_body()
            firebase.ParseFromString(firebase_bytes)
            for b in makeIter(firebase.body):
                for e in makeIter(b.event):
                    #print(e)
                    if e.event_code == "_vs":
                        #print("+++FIREBASE_ANALYTICS_", e.event_timestamp, b.package_name, b.firebase_instance_id)
                        for ei in e.event_info:
                            if ei.setting_code == "_sc":
                                if b.always_null:
                                    cookie=str(b.always_null)
                                else:
                                    cookie="<empty>"
                                print("+++FIREBASE_ANALYTICS", e.event_timestamp, b.package_name, b.firebase_instance_id, ei.data_str, cookie)
        except Exception as e:
            print("grep failed:")
            print(repr(e))
    if False:  # terse
        # just write out minimal event info
        str = decoded.split('\n')
        out = ""
        for s in str:
            m = re.search(' event_timestamp: ([0-9]+)', s)
            if m:
                out = out+" "+m.group(1)
            elif re.search('package_name', s):
                out = out+s
            elif re.search('event {', s):
                out = out+"\n"
            elif re.search('event_code', s):
                out = out+s
            elif re.search('Activity', s):
                out = out+s
        print(out)
    else:
        print(decoded)

except subprocess.CalledProcessError as e:
    print(e.output)
    print(e)
