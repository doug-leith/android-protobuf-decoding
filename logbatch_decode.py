import logbatch_pb2
import stats_log_pb2  # westworld
import lockbox_pb2
#import android_dialer_pb2
import subprocess
import textwrap
import sys, traceback
import os
import re
import dumper
import tempfile
import base64
import functools
import hashlib
from datetime import datetime
import pytz

# add folder where this script is to python search path (so can find helpers)
mypath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(mypath)
from decode_named import decode_named, message_class, DecodeNamedError  # in-process `protoc --decode`
from google.protobuf.internal.decoder import _DecodeVarint
from google.protobuf.message import DecodeError
from decoding_helpers import run_decoder_script, ScriptDecodeError, decode_pb, decode_wbxml, decode_log_batch, decode_firebase_analytics, try_decode_pb_array, protoUnknownFieldsToString, protoToString, fieldIsSet, makeIter
import gboard_named_pb  # LATIN_IME, from gboard_named.proto (old manual gboard.proto3 kept as gboard.proto3.backup)
import icing_named_pb  # ICING, from icing_named.proto (generated from the GMS 21.48.15 APK)
import activity_recognition_pb2


def decode_messaging_pb(bb, verbose=True, terse=False, Grep=True, debug=False):
    if debug:
        fname='/tmp/message_bytes'
        f = open(fname, 'wb')
        f.write(bb)
        f.close()
    try:
        decoded = decode_named("AndroidMessaging_LogEntry", "android_messaging.proto3", bb)
        grep=""
        if decoded is not None and (Grep or terse):
            # just write out minimal event info, handy for getting an overview of a sequence of events
            res = decoded.split('\n')
            out = ""; ts = False
            grep="+++ANDROID_MESSAGING "; 
            try:
                for s in res:
                    m = re.match('timestamp: ([0-9]+)', s)
                    if m and not ts:
                        tstamp=int(m.group(1))
                        out = out+str(tstamp)+" "
                        grep = grep+str(tstamp)+" "
                        date=datetime.utcfromtimestamp(tstamp/1000)
                        date_str = date.astimezone(pytz.FixedOffset(0)).strftime('%d/%m/%Y_%H:%M:%S.%f_%z')
                        grep = grep+date_str+" "
                        ts = True
                    elif re.search('eventType', s):
                        out = out+s
                        grep=grep+s.replace(" ", "")+" "
                    #elif re.search('messageProtocol', s):
                    #    out = out+s
                    #elif re.search('conversationType', s):
                    #    out = out+s
                    #elif re.search('conversationIdSHA1', s):
                    #    out = out+s
                    #elif re.search('configStatus', s):
                    #    out = out+s
                    elif re.search('bugleMessageStatus:', s):
                        out = out+s
                        grep=grep+s.replace(" ", "")+" "
                    #elif re.search('sendAttempt', s):
                    #    out = out+s
                    elif re.search('suggestionEventType', s):
                        out = out+s
                        grep=grep+s+" "
                    elif re.search('appLaunch', s):
                        out = out+s
                        grep=grep+s.replace(" ", "")+" "
                    elif re.search('sha256HashMsg', s):
                        out = out+s
                        grep=grep+s.replace(" ", "")+" "
                    elif re.search('sha256HashPrevMsg', s):
                        out = out+s
                        grep=grep+s.replace(" ", "")+" "
                grep=grep+"\n"
                if terse:
                    print(out)
                    return ""
            except Exception as e:
                print("***ERROR ANDROID_MESSAGING grep: ",e)
        return grep+decoded
    except DecodeNamedError as e:         
        if verbose:
            print("***ERROR: ",e)
        return "Failed"


def decode_dialer_pb(bb, verbose=True, terse=False, Grep=True, debug=False):
    if debug:
        fname='/tmp/dialer_bytes'
        f = open(fname, 'wb')
        f.write(bb)
        f.close()
    try:
        decoded = decode_named("AndroidDialer_LogEntry", "android_dialer.proto3", bb)
        grep=""
        if decoded is not None and (Grep or terse):
            # just write out minimal event info
            res = decoded.split('\n')
            out = ""; ts = False
            grep="+++ANDROID_DIALER "; 
            try:
                for s in res:
                    m = re.match('timestamp: ([0-9]+)', s)
                    if m and not ts:
                        #print(m.groups())
                        tstamp=int(m.group(1))
                        out = out+str(tstamp)+" "
                        grep = grep+str(tstamp)+" "
                        date=datetime.utcfromtimestamp(tstamp/1000)
                        date_str = date.astimezone(pytz.FixedOffset(0)).strftime('%d/%m/%Y_%H:%M:%S.%f_%z')
                        grep = grep+date_str+" "
                        ts = True
                    elif re.search('impressionEvent', s):
                        out = out+s
                        grep=grep+"impressionEvent "
                    elif re.search('AOSPEventType:', s):
                        out = out+s
                        #parts=s.split(" ")
                        grep=grep+s.replace(" ", "")+" "
                    elif re.search('eventType:', s):
                        grep=grep+s.replace(" ", "")+" "
                    elif re.search('searchQuery', s):
                        out = out+s
                        grep=grep+"searchQuery "
                    elif re.search('queryLength:', s):
                        out = out+s
                        grep=grep+s.replace(" ", "")+" "
                    elif re.search('callDetails', s):
                        out = out+s
                        grep=grep+"callDetails "
                    elif re.search('callDuration:', s):
                        out = out+s
                        grep=grep+s.replace(" ", "")+" "
                grep=grep+"\n"
                if terse:
                    print(out)
                    return ""
            except Exception as e:
                print("***ERROR ANDROID_DIALER grep: ",e)
        return grep+decoded
    except DecodeNamedError as e:
        if verbose:
            print("***ERROR: ",e)
        return "Failed"


def decode_gboard_pb(bb, verbose=True, terse=False, Grep=True, debug=False):
    if debug:
        fname='/tmp/gboard_bytes'
        f = open(fname, 'wb')
        f.write(bb)
        f.close()
    try:
        decoded = decode_named("LatinIME_LogEntry", "gboard_named.proto", bb)
        grep=""
        if decoded is not None and terse:
            # just write out minimal event info
            res = decoded.split('\n')
            out = ""; ts = False
            for s in res:
                m = re.match('timestamp: ([0-9]+)', s)
                if m and not ts:
                    out = out+m.group(1)+" "
                    ts = True
                elif re.search('eventType', s):
                    out = out+s
            print(out)
            return ""
        if Grep:
            try: 
                gboard = gboard_named_pb.LatinIME_LogEntry()
                gboard.ParseFromString(bb)
                packageName = "-NoPackageName"
                wordInfo="-NoWordInfo"
                if fieldIsSet(gboard.input_info):
                    if fieldIsSet(gboard.input_info.keyboard_usage_info):
                        if fieldIsSet(gboard.input_info.keyboard_usage_info.applicationName):
                            packageName = gboard.input_info.keyboard_usage_info.applicationName
                    if fieldIsSet(gboard.input_info.word_input_info):
                        if fieldIsSet(gboard.input_info.word_input_info.committedTextLength):
                            wordInfo="len:"+str(gboard.input_info.word_input_info.committedTextLength)
                        if fieldIsSet(gboard.input_info.word_input_info.timeToEnterWord):
                            wordInfo=wordInfo+"+time:"+str(gboard.input_info.word_input_info.timeToEnterWord)                   
                try:
                    kevent=gboard_named_pb.KeyboardEvent
                    event=kevent.Name(gboard.keyboardEvent)
                except:
                    event=str(gboard.keyboardEvent)
                grep="+++LATIN_IME %s %s %s %s %s\n"%(gboard.currentTimeMillis,gboard.elapsedRealtime,event,packageName,wordInfo)
            except Exception as e:
                print("***ERROR LATIN_IME grep: ",e)
        return grep+decoded
    except DecodeNamedError as e: 
        if verbose:
            print("***ERROR LATIN_IME: ",e)
        return "Failed"


def decode_icing_pb(bb, verbose=True, terse=False, Grep=True, debug=False):
    # ICING log source: GMS icing (on-device search index) and the libraries that
    # log under it (MobileDataDownload, MDH channel sync, ProtoDataStore, MobStore)
    if debug:
        fname='/tmp/icing_bytes'
        f = open(fname, 'wb')
        f.write(bb)
        f.close()
    try:
        decoded = decode_named("Icing_LogEntry", "icing_named.proto", bb)
        grep=""
        if Grep:
            try:
                ev = icing_named_pb.Icing_LogEntry()
                ev.ParseFromString(bb)
                # which kinds of record this event carries (one or more IcingLogEvent fields)
                kinds = [fd.name for fd, _v in ev.icing_log_event.ListFields() if fd.name != "sample_interval"]
                pkg = ""
                if ev.icing_log_event.HasField("package_name_and_icing_version_proto"):
                    pkg = " ".join(str(v) for _fd, v in ev.icing_log_event.package_name_and_icing_version_proto.ListFields())
                grep="+++ICING %s %s %s %s\n"%(ev.currentTimeMillis, ev.eventId, ",".join(kinds) or "-", pkg)
            except Exception as e:
                print("***ERROR ICING grep: ",e)
        return grep+decoded
    except DecodeNamedError as e:
        if verbose:
            print("***ERROR ICING: ",e)
        return "Failed"


def chime_event(fe):
    # "INTERACTION:SHOWN", "FAILURE:DROPPED_BY_CLIENT/SILENT_NOTIFICATION", ... for the +++CHIME grep line
    def name(msg, field):
        v = getattr(msg, field)
        e = msg.DESCRIPTOR.fields_by_name[field].enum_type.values_by_number.get(v)
        return e.name if e is not None else str(v)
    kind = fe.WhichOneof("entry")
    if kind == "interaction":
        i = fe.interaction
        detail = [name(i, f) for f in ("remove_reason", "fetch_reason", "built_in_action_type") if i.HasField(f)]
        if i.action_id:
            detail.append("action=" + i.action_id)
        return "/".join(["INTERACTION:" + name(i, "interaction_type")] + detail)
    if kind == "failure":
        f = fe.failure
        detail = [name(f, x) for x in ("drop_reason", "registration_failure_reason") if f.HasField(x)]
        if f.exception:
            detail.append("exception=" + f.exception)
        return "/".join(["FAILURE:" + name(f, "failure_type")] + detail)
    if kind == "system_event":
        return "SYSTEM_EVENT:" + name(fe.system_event, "system_event")
    return kind or "-"

def decode_chime_pb(bb, verbose=True, terse=False, Grep=True, debug=False):
    # CHIME log source: notification events (delivered, shown, clicked, dropped, ...) from Google's notification
    # library GnpSdk/Chime in Google apps and GMS
    if debug:
        fname='/tmp/chime_bytes'
        f = open(fname, 'wb')
        f.write(bb)
        f.close()
    try:
        ev = message_class("Chime_LogEntry", "chime_named.proto")()
        ev.MergeFromString(bb)
    except Exception:
        ev = None
    if ev is None or not ev.HasField("currentTimeMillis"):
        # not one LogEvent (e.g. try_decode_pb_array's first try with the whole length-delimited logEntry array)
        if verbose:
            print("***ERROR CHIME: not a LogEvent")
        return "Failed"
    try:
        decoded = decode_named("Chime_LogEntry", "chime_named.proto", bb)
        grep=""
        if Grep:
            try:
                fe = ev.chime_frontend_log.frontend_entry
                ctx = fe.context
                target = ctx.target
                pkg = target.package_name or target.chime_target.delivery_address.android_target.package_name or ev.packageName
                threads = "|".join(t.thread_id for t in ctx.thread) or "-"
                channels = [t.channel_id for t in ctx.thread if t.channel_id]
                if fe.interaction.HasField("channel"):
                    channels.append(fe.interaction.channel.channel_id)
                if fe.interaction.HasField("channel_group"):
                    channels.append("group:" + fe.interaction.channel_group.group_id)
                app_channels = "|".join(c.channel_id for c in ctx.render_context.device_info.notification_channel) or "-"
                grep="+++CHIME %s %s %s %s threads=%s channel=%s app_channels=%s\n"%(ev.currentTimeMillis, pkg or "-",
                    ctx.client_id or "-", chime_event(fe), threads, "|".join(channels) or "-", app_channels)
            except Exception as e:
                print("***ERROR CHIME grep: ",e)
        return grep+decoded
    except DecodeNamedError as e:
        if verbose:
            print("***ERROR CHIME: ",e)
        return "Failed"


def decode_clientlogging_pb(bb, verbose=True, terse=False, Grep=True, debug=False):
    # CLIENT_LOGGING_PROD log source: warning/error log records uploaded by Google apps built on TikTok
    if debug:
        fname='/tmp/clientlogging_bytes'
        f = open(fname, 'wb')
        f.write(bb)
        f.close()
    try:
        decoded = decode_named("ClientLogging_LogEntry", "client_logging_named.proto", bb)
        grep=""
        if Grep:
            try:
                ev = message_class("ClientLogging_LogEntry", "client_logging_named.proto")()
                ev.MergeFromString(bb)
                cl = ev.client_log
                rec = cl.log_record
                site = "%s.%s:%d"%(rec.class_name, rec.method_name, rec.line_number) if rec.class_name else "-"
                trace = "|".join(cl.trace.span_name) or "-"
                args = "|".join(a.value for a in cl.logged_argument) or "-"
                exc = rec.throwable.throwable.class_name or "-"
                count = " count=%d"%cl.repeat_count if cl.HasField("repeat_count") else ""
                grep="+++CLIENT_LOGGING %s %s %s level=%s %s%s thread=%s site=%s trace=%s args=%s exception=%s message=%r\n"%(
                    ev.currentTimeMillis, cl.client_info.app_info.package_name or "-", cl.client_info.app_info.version_name or "-",
                    rec.level, ev.client_log.DESCRIPTOR.fields_by_name["log_type"].enum_type.values_by_number[cl.log_type].name, count,
                    rec.thread_name or "-", site, trace, args, exc, rec.message)
            except Exception as e:
                print("***ERROR CLIENT_LOGGING grep: ",e)
        return grep+decoded
    except DecodeNamedError as e:
        if verbose:
            print("***ERROR CLIENT_LOGGING: ",e)
        return "Failed"


def ondeviceabuse_event(ml):
    # one-line summary of the classification, package download or package unpacking an ON_DEVICE_ABUSE event reports
    def name(m, f):
        v = getattr(m, f)
        names = m.DESCRIPTOR.fields_by_name[f].enum_type.values_by_number
        return names[v].name if v in names else str(v)
    if ml.HasField("classification"):
        c = ml.classification
        classifiers = "|".join("%s:%s"%(r.label, r.version) for r in c.classifier_result) or "-"
        feedback = " feedback=" + name(c, "user_feedback") if c.HasField("user_feedback") else ""
        return "CLASSIFICATION verdict=%s/%s latency_ms=%d classifiers=%s%s"%(name(c.verdict, "policy_violation"),
            name(c.verdict, "action"), c.latency_ms, classifiers, feedback)
    if ml.HasField("protection_download"):
        d = ml.protection_download
        bt = d.binary_transparency
        check = ("verified" if bt.verified else "failed:" + name(bt, "error")) if d.HasField("binary_transparency") else "-"
        return "DOWNLOAD %s %s duration_ms=%d binary_transparency=%s"%(name(d, "result"), name(d, "download_type"),
            d.duration_ms, check)
    if ml.HasField("protections_extraction"):
        x = ml.protections_extraction
        corrupted = " corrupted_stored_package" if x.HasField("corrupted_protections") else ""
        return "EXTRACTION latency_ms=%d no_rule_script=%s%s"%(x.extraction.latency_ms, x.extraction.no_rule_script, corrupted)
    return "-"

def decode_ondeviceabuse_pb(bb, verbose=True, terse=False, Grep=True, debug=False):
    # ON_DEVICE_ABUSE log source: spam/scam classifier reports (verdicts, rule package downloads) from Google's
    # on-device abuse library Moirai in Google Messages
    if debug:
        fname='/tmp/ondeviceabuse_bytes'
        f = open(fname, 'wb')
        f.write(bb)
        f.close()
    try:
        ev = message_class("OnDeviceAbuse_LogEntry", "on_device_abuse_named.proto")()
        ev.MergeFromString(bb)
    except Exception:
        ev = None
    if ev is None or not ev.HasField("currentTimeMillis"):
        # not one LogEvent (e.g. try_decode_pb_array's first try with the whole length-delimited logEntry array)
        if verbose:
            print("***ERROR ON_DEVICE_ABUSE: not a LogEvent")
        return "Failed"
    try:
        decoded = decode_named("OnDeviceAbuse_LogEntry", "on_device_abuse_named.proto", bb)
        grep=""
        if Grep:
            try:
                ml = ev.moirai_log
                md = ml.client_metadata
                counts = " classifications=%d downloads=%d"%(md.classification_count, md.download_count) \
                    if md.HasField("classification_count") or md.HasField("download_count") else ""
                grep="+++ON_DEVICE_ABUSE %s %s build=%s%s %s protection_token=%s\n"%(ev.currentTimeMillis,
                    md.package_name or "-", md.client_build_version if md.HasField("client_build_version") else "-",
                    counts, ondeviceabuse_event(ml), md.protection_token[:8].hex() or "-")
            except Exception as e:
                print("***ERROR ON_DEVICE_ABUSE grep: ",e)
        return grep+decoded
    except DecodeNamedError as e:
        if verbose:
            print("***ERROR ON_DEVICE_ABUSE: ",e)
        return "Failed"


def autofill_value_names(fd, v):
    # the values of field fd as strings, enum values by name
    vals = v if fd.label == fd.LABEL_REPEATED else [v]
    if fd.enum_type:
        names = fd.enum_type.values_by_number
        return [names[x].name if x in names else str(x) for x in vals]
    return [str(x) for x in vals]


def autofill_grep_fields(msg):
    # (package, activity, domains, other fields) of an AUTOFILL_WITH_GOOGLE event: the session's app and
    # activity, the detected forms' domains, and the event's scalar fields as name=value
    pkg = act = "-"
    domains, rest = [], []
    for fd, v in msg.ListFields():
        t = fd.message_type.name if fd.message_type else None
        if t == "SessionContext":
            pkg, act = v.app.package_name or "-", v.activity.class_name or "-"
        elif t == "DetectedForm":
            forms = v if fd.label == fd.LABEL_REPEATED else [v]
            domains += [f.domain for f in forms if f.domain]
            # the detected types of each form's fields
            rest.append("%s_fields=%s"%(fd.name, "|".join(",".join(n for fld in f.field for n in autofill_value_names(
                fld.DESCRIPTOR.fields_by_name["field_type"], fld.field_type)) or "-" for f in forms)))
        elif t is None:
            rest.append("%s=%s"%(fd.name, "|".join(autofill_value_names(fd, v))))
    return pkg, act, domains, rest


def decode_autofill_pb(bb, verbose=True, terse=False, Grep=True, debug=False):
    # AUTOFILL_WITH_GOOGLE log source: Google Play services' Autofill service metrics, with the foreground app and activity
    if debug:
        fname='/tmp/autofill_bytes'
        f = open(fname, 'wb')
        f.write(bb)
        f.close()
    try:
        decoded = decode_named("Autofill_LogEntry", "autofill_named.proto", bb)
        grep=""
        if Grep:
            try:
                ev = message_class("Autofill_LogEntry", "autofill_named.proto")()
                ev.MergeFromString(bb)
                events = ev.autofill_event.ListFields()  # one event field, numbered as eventId
                if events:
                    name = events[0][0].name
                    pkg, act, domains, rest = autofill_grep_fields(events[0][1])
                else:
                    name, pkg, act, domains, rest = "eventId=%s"%(ev.eventId if ev.HasField("eventId") else "-"), "-", "-", [], []
                grep="+++AUTOFILL %s %s %s %s %s %s\n"%(ev.currentTimeMillis, pkg, act, "|".join(domains) or "-", name, " ".join(rest))
            except Exception as e:
                print("***ERROR AUTOFILL grep: ",e)
        return grep+decoded
    except DecodeNamedError as e:
        if verbose:
            print("***ERROR AUTOFILL: ",e)
        return "Failed"


def _primes_enum(msg, field):
    v = getattr(msg, field)
    e = msg.DESCRIPTOR.fields_by_name[field].enum_type.values_by_number.get(v)
    return e.name if e is not None else str(v)

@functools.lru_cache(maxsize=None)
def _primes_hashed_names():
    # {hash: name} for the names in primes_hashed_names.txt; Primes' hash (bidz.a()) is the first 8 bytes of the
    # name's MD5, so a name that can be guessed can be looked up
    names = {}
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "primes_hashed_names.txt"), encoding="utf-8") as f:
        for line in f:
            name = line.rstrip("\n")
            if name and not name.startswith("# "):
                names[int.from_bytes(hashlib.md5(name.encode("utf-8")).digest()[:8], "big")] = name
    return names

def _primes_unhash(h):
    # the name behind a Primes hash, or None
    return _primes_hashed_names().get(h & (2**64 - 1))

def _primes_grep(m):
    # "metric types" plus "key=value" summaries of a SystemHealthMetric, for the +++PRIMES grep line
    common = ("application_info", "device_info", "sampling_parameters", "metric_extension", "accountable_component",
              "constant_event_name", "custom_event_name", "hashed_custom_event_name")
    kinds = [fd.name for fd, _v in m.ListFields() if fd.name not in common]
    info = []
    if m.constant_event_name:
        info.append("name=%s" % m.constant_event_name)
    if m.HasField("hashed_custom_event_name"):
        name = _primes_unhash(m.hashed_custom_event_name)
        info.append('hashed_name="%s"' % name if name is not None else "hashed_name=%016x" % m.hashed_custom_event_name)
    if m.accountable_component.custom_name:
        info.append("component=%s" % m.accountable_component.custom_name)
    if m.HasField("memory_usage_metric"):
        mu = m.memory_usage_metric
        info.append("memory_event=%s activity=%s rss_kb=%d" % (_primes_enum(mu, "memory_event_code"), mu.activity_name or "-",
                                                             mu.memory_stats.android_memory_stats.vm_rss_kb))
    if m.HasField("timer_metric"):
        info.append("duration_ms=%d" % m.timer_metric.duration_ms)
    if m.HasField("primes_trace"):
        tr = m.primes_trace
        root = (tr.span[0].constant_name or _primes_unhash(tr.span[0].hashed_name)) if tr.span else None
        info.append("trace=%s spans=%d%s" % (_primes_enum(tr, "trace_type"), len(tr.span), "(" + root + ")" if root else ""))
        if tr.HasField("startup_metric"):
            st = tr.startup_metric
            acts = "|".join(a.activity_name for a in (st.first_activity, st.second_activity) if a.activity_name) or "-"
            info.append("startup=%s startup_ms=%d fully_drawn_ms=%d activities=%s" % (_primes_enum(st, "startup_type"),
                        st.startup_ms, st.app_fully_drawn_ms, acts))
    if m.HasField("jank_metric"):
        j = m.jank_metric
        info.append("jank_frames=%d/%d duration_ms=%d" % (j.jank_frame_count, j.rendered_frame_count, j.duration_ms))
    if m.HasField("network_usage_metric"):
        # a hashed path is shown as its recovered parts after the domain, an unrecovered part as <hash>
        paths = [n.constant_rpc_path or n.request_path or
                 (n.domain + "".join("/" + (_primes_unhash(h) or "<%016x>" % h) for h in n.hashed_rpc_path) if n.hashed_rpc_path else n.domain) or "-"
                 for n in m.network_usage_metric.network_event_usage]
        info.append("requests=%s" % "|".join(paths))
    if m.HasField("crash_metric"):
        c = m.crash_metric
        info.append("crash=%s exception=%s activity=%s thread=%s" % (_primes_enum(c, "crash_type"), c.exception_class_name or "-",
                                                                   c.active_activity_name or "-", c.thread_name or "-"))
    if m.HasField("primes_stats"):
        info.append("primes_event=%s" % _primes_enum(m.primes_stats, "primes_event"))
    if m.HasField("battery_usage_metric"):
        b = m.battery_usage_metric.battery_stats_diff
        info.append("battery=%s->%s duration_ms=%d" % (_primes_enum(b, "start_info"), _primes_enum(b, "end_info"), b.duration_ms))
    if m.HasField("application_exit_metric"):
        info.append("exits=%s" % ("|".join("%s:%s" % (x.process_name, _primes_enum(x, "reason"))
                                          for x in m.application_exit_metric.application_exit_info) or "-"))
    if m.HasField("ui_thread_hang"):
        h = m.ui_thread_hang
        info.append("ui_thread_blocked_ms=%d" % (h.blocked_for_ms or h.total_blocked_ms))
    if m.HasField("package_metric"):
        info.append("data_size=%d" % m.package_metric.data_size)
    return ",".join(kinds) or "-", " ".join(info)

def decode_primes_pb(bb, verbose=True, terse=False, Grep=True, debug=False, source="PRIMES"):
    # *_PRIMES log sources: performance metrics from Google's Primes library (memory, timers, app startup, jank,
    # network requests, crashes, battery), one SystemHealthMetric per event
    if debug:
        fname='/tmp/primes_bytes'
        f = open(fname, 'wb')
        f.write(bb)
        f.close()
    try:
        ev = message_class("Primes_LogEntry", "primes_named.proto")()
        ev.MergeFromString(bb)
    except Exception:
        ev = None
    if ev is None or not ev.HasField("currentTimeMillis"):
        # every LogEvent has its event time; without it these bytes are not one event (e.g. try_decode_pb_array's
        # first try with the whole length-delimited logEntry array, which this broad schema would otherwise accept)
        if verbose:
            print("***ERROR PRIMES: not a LogEvent")
        return "Failed"
    try:
        decoded = decode_named("Primes_LogEntry", "primes_named.proto", bb)
        grep=""
        if Grep:
            try:
                m = ev.system_health_metric
                kinds, info = _primes_grep(m)
                grep="+++PRIMES %s %s %s %s %s %s\n"%(ev.currentTimeMillis, source, m.application_info.application_package_name or "-",
                    m.application_info.application_version_name or "-", kinds, info)
            except Exception as e:
                print("***ERROR PRIMES grep: ",e)
        return grep+decoded
    except DecodeNamedError as e:
        if verbose:
            print("***ERROR PRIMES: ",e)
        return "Failed"


@functools.lru_cache(maxsize=None)
def _westworld_counter_names():
    # {hash: name} for the names in westworld_counters_names.txt; a Clearcut counter's name hash (tpj.a()) is the
    # first 8 bytes of the name's MD5
    names = {}
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "westworld_counters_names.txt"), encoding="utf-8") as f:
        for line in f:
            name = line.rstrip("\n")
            if name and not name.startswith("# "):
                names[int.from_bytes(hashlib.md5(name.encode("utf-8")).digest()[:8], "big")] = name
    return names

def decode_westworld_counters_pb(bb, verbose=True, terse=False, Grep=True, debug=False):
    # WESTWORLD_COUNTERS log source: GMS's statsd uploader (Westworld) counting its own operations (alarms, fetches
    # and uploads of statsd reports and metadata) with Clearcut's Counters, one snapshot per event
    if debug:
        fname='/tmp/westworld_counters_bytes'
        f = open(fname, 'wb')
        f.write(bb)
        f.close()
    try:
        ev = message_class("WestworldCounters_LogEntry", "westworld_counters_named.proto")()
        ev.MergeFromString(bb)
    except Exception:
        ev = None
    if ev is None or not ev.HasField("currentTimeMillis"):
        # not one LogEvent (e.g. try_decode_pb_array's first try with the whole length-delimited logEntry array)
        if verbose:
            print("***ERROR WESTWORLD_COUNTERS: not a LogEvent")
        return "Failed"
    try:
        decoded = decode_named("WestworldCounters_LogEntry", "westworld_counters_named.proto", bb)
        grep=""
        if Grep:
            try:
                if ev.HasField("internal_log_event"):
                    # the Clearcut log store's own boot / clock-change marker, with no counters
                    info = "internal_log_event=%s"%ev.DESCRIPTOR.fields_by_name["internal_log_event"].enum_type.values_by_number[ev.internal_log_event].name
                else:
                    # name=count for a plain counter, name[bucket]=count for each bucket of a histogram; an unrecovered
                    # name is shown as its hash
                    counts = []
                    for c in ev.counters.counter:
                        name = _westworld_counter_names().get(c.name_hash, "%016x"%c.name_hash)
                        for b in c.bucket:
                            counts.append("%s%s=%d"%(name, "[%d]"%b.bucket if b.bucket else "", b.count))
                    info = "start_elapsed_realtime_ms=%d %s"%(ev.counters.start_elapsed_realtime_ms, " ".join(counts) or "-")
                grep="+++WESTWORLD_COUNTERS %s %s\n"%(ev.currentTimeMillis, info)
            except Exception as e:
                print("***ERROR WESTWORLD_COUNTERS grep: ",e)
        return grep+decoded
    except DecodeNamedError as e:
        if verbose:
            print("***ERROR WESTWORLD_COUNTERS: ",e)
        return "Failed"


# the Google app's (com.google.android.googlequicksearchbox) log sources, each with its <Source>_LogEntry in agsa_named.proto
AGSA_SOURCES = ("AGSA_APA", "AGSA_PROACTIVE_ASSISTANT", "AGSA_ASSISTANT", "AGSA_GOOGLE_APP", "AGSA_ASSISTANT_INTERACTOR",
                "AGSA_ASSISTANT_AUTO", "AGSA_INFRASTRUCTURE", "AGSA_OMNI", "AGSA_LEGACY", "AGSA_MDD_ANDROID")
_agsa_flow_names = None

def _agsa_flow_name(table, product, value):
    # name of a flow type or flow step (agsa_flow_names.json, read from the APK's flow logging enums) or the number
    global _agsa_flow_names
    if _agsa_flow_names is None:
        import json
        with open(os.path.join(mypath, "agsa_flow_names.json")) as f:
            _agsa_flow_names = json.load(f)
    return _agsa_flow_names[table].get(str(product), {}).get(str(value), str(value))

def _agsa_value(fd, v):
    if fd.enum_type is not None:
        e = fd.enum_type.values_by_number.get(v)
        return e.name if e is not None else str(v)
    if fd.type == fd.TYPE_STRING:
        return repr(v)
    if fd.type == fd.TYPE_BYTES:
        return repr(v[:32])
    return str(v)

def _agsa_leaves(m, prefix="", skip=()):
    # name=value for each scalar in m (but fields named in skip), nested messages flattened as a.b=value
    out = []
    for fd, v in m.ListFields():
        if fd.name in skip:
            continue
        name = prefix + fd.name
        for x in (v if fd.label == fd.LABEL_REPEATED else [v]):
            if fd.message_type is not None:
                out += _agsa_leaves(x, name + ".")
            else:
                out.append("%s=%s" % (name, _agsa_value(fd, x)))
    return out

def _agsa_grep(ev):
    # what an AGSA event records, for its +++AGSA_ grep line
    cl, ce = ev.agsa_client_log, ev.agsa_client_log.client_event
    pa = ce.product_log_context.product_and_account
    info = ["event=%s" % _agsa_value(ev.DESCRIPTOR.fields_by_name["eventId"], ev.eventId) if ev.HasField("eventId") else "event=-",
            "product=%s" % _agsa_value(pa.DESCRIPTOR.fields_by_name["product"], pa.product) if pa.HasField("product") else "product=-",
            "account=%s" % _agsa_value(pa.DESCRIPTOR.fields_by_name["account_state"], pa.account_state) if pa.HasField("account_state") else "account=-"]
    if ce.HasField("app_flow"):
        fl = ce.app_flow
        steps = [_agsa_flow_name("flow_steps", r.ids.info.product or fl.product, r.ids.info.record_id) for r in fl.record]
        info.append("flow=%s status=%s duration_ms=%d steps=%s" % (_agsa_flow_name("flow_types", fl.product, fl.flow_type),
                    _agsa_value(fl.DESCRIPTOR.fields_by_name["status"], fl.status),
                    fl.duration.seconds * 1000 + fl.duration.nanos // 1000000, "|".join(steps) or "-"))
        exts = []
        for r in fl.record:
            for x in _agsa_leaves(r.extensions):
                if x not in exts:
                    exts.append(x)
        if exts:
            info.append("flow_data=" + ",".join(exts))
    if ev.HasField("veProducerByteString"):
        ve = ev.veProducerByteString
        ve_type = lambda e: _agsa_value(e.DESCRIPTOR.fields_by_name["ve_type"], e.ve_type)
        info.append("ve=%s" % (",".join(ve_type(e) for e in ve.visual_element) or "-"))
        exts = []
        for e in ve.visual_element:
            for x in _agsa_leaves(e, skip=("ve_type", "index", "child_index")):
                if x not in exts:
                    exts.append(x)
        if exts:
            info.append("ve_data=" + ",".join(exts))
        if ve.interactions.interaction:
            info.append("interactions=%s" % ",".join("%s:%s" % (_agsa_value(i.DESCRIPTOR.fields_by_name["type"], i.type), ve_type(i.target.ved))
                                                     for i in ve.interactions.interaction))
    # the event's other fields
    other = _agsa_leaves(ce, skip=("current_time_millis", "elapsed_realtime_millis", "elapsed_realtime_nanos", "app_flow",
                                   "product_log_context"))
    other += _agsa_leaves(cl, skip=("nid_cookie", "client_event", "app_version"))
    if other:
        info.append("data=" + ",".join(dict.fromkeys(other)))
    if cl.HasField("nid_cookie"):
        info.append("nid_cookie")
    return " ".join(info)

def decode_agsa_pb(bb, verbose=True, terse=False, Grep=True, debug=False, source="AGSA_APA"):
    # AGSA_* log sources: the Google app's (Search, Assistant, At a Glance, ...) client events: app flows (named steps
    # of a feature, with per-feature data), visual elements shown and tapped, the product, account state and NID cookie
    if debug:
        fname='/tmp/agsa_bytes'
        f = open(fname, 'wb')
        f.write(bb)
        f.close()
    entry = "".join(w.capitalize() for w in source.split("_")) + "_LogEntry"
    try:
        decoded = decode_named(entry, "agsa_named.proto", bb)
        grep=""
        if Grep:
            try:
                ev = message_class(entry, "agsa_named.proto")()
                ev.MergeFromString(bb)
                grep="+++%s %s %s\n"%(source, ev.currentTimeMillis, _agsa_grep(ev))
            except Exception as e:
                print("***ERROR %s grep: "%source,e)
        return grep+decoded
    except DecodeNamedError as e:
        if verbose:
            print("***ERROR %s: "%source,e)
        return "Failed"


def printAtom(tt, a, strhash, westworld):
    if a is not None:
        for t in makeIter(tt):
            printAtomInfo(t, a, strhash, westworld)


def printAtomInfo(t, a, strhash, westworld):
    try:
        #print(a)
        atoms=stats_log_pb2.frameworks_dot_proto__logging_dot_stats_dot_atoms__pb2
        if fieldIsSet(a.ui_event_reported):
            u=a.ui_event_reported
            print("+++WESTWORLD_UIEVENT", t, atoms.UiEventId.Name(u.event_id), u.package_name)
        elif fieldIsSet(a.battery_level_changed):
            b=a.battery_level_changed
            print("+++WESTWORLD_BATTERY", t, b.battery_level)
        elif fieldIsSet(a.notification_reported):
            n=a.notification_reported
            print("+++WESTWORLD_NOTIFICATION", t, atoms.UiEventId.Name(n.event_id), n.package_name, n.instance_id, n.notification_id_hash, n.channel_id_hash, n.category)
        elif fieldIsSet(a.launcher_event):
            l=a.launcher_event
            if len(l.package_name)>0:
                # this check excludes purely launcher-related actions e.g. LAUNCHER_SWIPERIGHT, LAUNCHER_SWIPELEFT, LAUNCHER_TASK_DISMISS_SWIPE_UP
                print("+++WESTWORLD_LAUNCHER", t, atoms.UiEventId.Name(l.event_id), l.package_name, l.component_name, l.src_state, l.dst_state)
        elif fieldIsSet(a.launcher_snapshot):
            l=a.launcher_snapshot
            print("+++WESTWORLD_LAUNCHERSNAPSHOT", t, atoms.UiEventId.Name(l.event_id), l.package_name, l.component_name)
        elif fieldIsSet(a.settings_ui_changed):
            l=a.settings_ui_changed
            if l.action:
                print("+++WESTWORLD_SETTINGSUI", t, l.action, l.page_id, l.changed_preference_key)
        elif fieldIsSet(a.app_start_occurred):
            l=a.app_start_occurred
            print("+++WESTWORLD_APPSTART", t, l.type, l.calling_pkg_name, strhash, l.activity_name_hash, l.reason)
        # added app_usage_event_occurred 25/6/24
        elif fieldIsSet(a.app_usage_event_occurred):
            l=a.app_usage_event_occurred
            # MOVE_TO_FOREGROUND = 1; MOVE_TO_BACKGROUND = 2;
            print("+++WESTWORLD_APPUSAGE", t, l.event_type, strhash)
        elif fieldIsSet(a.setting_snapshot):
            l=a.setting_snapshot
            print("+++WESTWORLD_SETTINGSNAPSHOT", t, strhash, l.type, l.bool_value, l.int_value, l.float_value, l.str_value)
        elif fieldIsSet(a.back_gesture_reported_reported):
            l=a.back_gesture_reported_reported
            print("+++WESTWORLD_BACKGESTURE", t, l.x_location, l.start_x, l.start_y, l.end_x, l.end_y, l.package_name)
        elif fieldIsSet(a.screen_state_changed):
            l=a.screen_state_changed
            # DISPLAY_STATE_OFF = 1, DISPLAY_STATE_ON = 2, DISPLAY_STATE_DOZE = 3
            print("+++WESTWORLD_SCREENSTATE", t, l.state)
        elif fieldIsSet(a.grant_permissions_activity_button_actions):
            l=a.grant_permissions_activity_button_actions
            print("+++WESTWORLD_GRANTPERMISSION", t, l.permission_group_name,l.package_name)
        elif fieldIsSet(a.permission_grant_request_result_reported):
            l=a.permission_grant_request_result_reported
            print("+++WESTWORLD_PERMISSIONREPORT", t,l.permission_name,l.package_name, l.result)
        elif fieldIsSet(a.boot_sequence_reported):
            l=a.boot_sequence_reported
            print("+++WESTWORLD_BOOTREPORT", t,l.system_reason, l.end_time_millis)
        elif fieldIsSet(a.shutdown_sequence_reported):
            l=a.shutdown_sequence_reported
            print("+++WESTWORLD_SHUTDOWNREPORT", t,l.reboot, l.start_time_millis)
        elif fieldIsSet(a.keyguard_state_changed):
            l=a.keyguard_state_changed
            # HIDDEN = 1; SHOWN= 2;
            print("+++WESTWORLD_KEYGUARD", t, l.state)                                             
        elif fieldIsSet(a.usb_connector_state_changed):
            l=a.usb_connector_state_changed
            print("+++WESTWORLD_USB", t, l.state)   
        elif fieldIsSet(a.bluetooth_enabled_state_changed):
            l=a.bluetooth_enabled_state_changed
            print("+++WESTWORLD_BLUETOOTH", t, l.state, l.reason)                      
        elif fieldIsSet(a.bluetooth_socket_connection_state_changed):
            l=a.bluetooth_socket_connection_state_changed
            print("+++WESTWORLD_BLUETHOOTH_SOCKCONNECTIONSTATE", t, l.state)    
        # 'bluetooth_a2dp_playback_state_changed', 'bluetooth_acl_connection_state_changed', 'bluetooth_active_device_changed', 'bluetooth_activity_info', 'bluetooth_bond_state_changed', 'bluetooth_bytes_transfer', 'bluetooth_class_of_device_reported', 'bluetooth_classic_pairing_event_reported', 'bluetooth_connection_state_changed', 'bluetooth_device_failed_contact_counter_reported', 'bluetooth_device_info_reported', 'bluetooth_device_rssi_reported', 'bluetooth_device_tx_power_level_reported', 'bluetooth_enabled_state_changed', 'bluetooth_hal_crash_reason_reported', 'bluetooth_hci_timeout_reported', 'bluetooth_link_layer_connection_event', 'bluetooth_quality_report_reported', 'bluetooth_remote_version_info_reported', 'bluetooth_sco_connection_state_changed', 'bluetooth_sdp_attribute_reported', 'bluetooth_smp_pairing_event_reported', 'bluetooth_socket_connection_state_changed',                  
        elif fieldIsSet(a.network_validation_reported):
            l=a.network_validation_reported
            if fieldIsSet(l.probe_events):
                for p in makeIter(l.probe_events.probe_event):
                    success=0
                    if p.probe_type == 3: # HTTPS
                        success=p.probe_result # PR_SUCCESS = 1, PR_FAILURE = 2
                # transport_type: TT_CELLULAR = 1; TT_WIFI = 2; TT_CELLULAR_VPN = 7; TT_WIFI_VPN = 8;
                print("+++WESTWORLD_NETWORKREPORT", t, l.transport_type, success)

    except Exception as e:
        print("***ERROR printAtom failed: ",e)
        traceback.print_exc(file=sys.stdout)
        print('----')
        print(a)
        print('----')
        #sys.exit()

    # face_settings, memory usage, temperature, surfaceflinger_stats per app, uid of all apps and app installer
    # plenty of histogram data
    # boot_sequence_reported, shutdown_sequence_reported, network_validation_reported
    # network_dns_event_reported


def _fields(buf):
    # (field number, wire type, value) of each field of one message, raw; raises ValueError on bytes that are not one
    pos, out = 0, []
    while pos < len(buf):
        tag, pos = _DecodeVarint(buf, pos)
        num, wt = tag >> 3, tag & 7
        if wt == 0:
            v, pos = _DecodeVarint(buf, pos)
        elif wt == 2:
            n, pos = _DecodeVarint(buf, pos)
            v, pos = buf[pos:pos+n], pos+n
        elif wt in (1, 5):
            v, pos = buf[pos:pos+(8 if wt == 1 else 4)], pos+(8 if wt == 1 else 4)
        else:
            raise ValueError("wire type %d"%wt)
        if num == 0 or pos > len(buf):
            raise ValueError("not a message")
        out.append((num, wt, v))
    return out

def print_consent_info(logEntry):
    # the CONSENT_INFO key/value pair (LogEvent field 3) that GMS's usage reporting client adds to the events of the
    # log sources uploaded only with consent (WESTWORLD, LB_AS, DROP_BOX, ...): the consent state checked for the upload.
    # logEntry holds one LogEvent (opening with field 1, the event time) or several as <varint length><LogEvent>...
    try:
        events, pos = [], 0
        if logEntry[:1] == b"\x08":
            events = [logEntry]
        while not events and pos < len(logEntry):
            n, pos = _DecodeVarint(logEntry, pos)
            events.append(logEntry[pos:pos+n])
            pos += n
        values = []
        for e in events:
            for num, wt, kv in _fields(e):
                if num == 3 and wt == 2:
                    pair = {n: v for n, w, v in _fields(kv) if w == 2}
                    if pair.get(1) == b"CONSENT_INFO":
                        values.append(pair.get(2, b""))
    except (ValueError, IndexError, DecodeError):
        return
    for v in values:
        try:
            print("CONSENT_INFO (decoded):")
            print(decode_named("ConsentInformationWrapper", "consentinfo.proto", base64.b64decode(v)))
        except (DecodeNamedError, ValueError) as e:
            print("***ERROR CONSENT_INFO: ", e)

def grep_westworld(bytes):
    try:        
        westworld = stats_log_pb2.WestworldRequest()
        westworld.ParseFromString(bytes)
        # print interesting content in a way that's easy to grep out of log file
        for w in makeIter(westworld.statsLogMetricsReport):
            if not w.configMetricsReportList:
                return
            for c in makeIter(w.configMetricsReportList):
                # do a first walk through to get strings and calc their hashes
                strhashes = {}
                bootTimeNanos = -1
                for r in makeIter(c.reports):
                    if r.current_report_elapsed_nanos:
                        print("+++WESTWORLD_TIME",r.current_report_elapsed_nanos,r.current_report_wall_clock_nanos)
                        bootTimeNanos = (r.current_report_wall_clock_nanos - r.current_report_elapsed_nanos)
                        print("+++bootTimeNanos=",bootTimeNanos)
                    if r.strings:
                        for s in makeIter(r.strings):
                            try:
                                res = subprocess.check_output('"'+mypath+'/SMHasher" '+'"'+s+'"', shell=True, stderr=subprocess.STDOUT, text=True)
                                res = int(res.strip())
                                print("+++WESTWORLD_STRINGS", s, res)
                                strhashes[res] = s   # mapping from hash to string
                            except Exception as e:
                                print("***ERROR SMHasher failed: ",e)
                if bootTimeNanos<0:
                    print("ERROR: bootTimeNanos not set by WESTWORLD!")
                # now walk through the events
                for r in makeIter(c.reports):
                    if r.metrics:
                        for m in makeIter(r.metrics):
                            a = None; strhash=None
                            if m.event_metrics and m.event_metrics.data:
                                try:
                                    for aa in makeIter(m.event_metrics.data):
                                        if aa.aggregated_atom_info:
                                            # updated 25/6/24 to show all elapsed times not just the first one
                                            for elapsed_time in aa.aggregated_atom_info.elapsed_timestamp_nanos:
                                                # updated 5/1/24 to print wall clock nanos.  DL
                                                printAtom(elapsed_time+bootTimeNanos, aa.aggregated_atom_info.atom, None, westworld)
                                        elif aa.atom:
                                            for elapsed_time in aa.aggregated_atom_info.elapsed_timestamp_nanos:
                                                printAtom(elapsed_time+bootTimeNanos, aa.atom, None, westworld)
                                except Exception as e:
                                    print("***ERROR event metrics failed: ",e)
                                    print("---"); print(aa); print("---")
                            elif m.gauge_metrics and m.gauge_metrics.data:
                                try:
                                    for aa in makeIter(m.gauge_metrics.data):
                                        if fieldIsSet(aa.dimension_leaf_values_in_what):
                                            for bb in makeIter(aa.dimension_leaf_values_in_what):
                                                if fieldIsSet(bb.value_str_hash):
                                                    strhash = bb.value_str_hash
                                                    if strhash in strhashes.keys():
                                                        strhash = strhashes[strhash]  # map hash back to string
                                        if aa.bucket_info:
                                            for b in makeIter(aa.bucket_info):
                                                # updated 5/1/24 to print wall clock nanos.  DL
                                                if b.aggregated_atom_info:
                                                    for c in makeIter(b.aggregated_atom_info):
                                                        # updated 25/6/24 to show all elapsed times not just the first one
                                                        for elapsed_time in c.elapsed_timestamp_nanos:
                                                            printAtom(elapsed_time+bootTimeNanos, c.atom, strhash, westworld)
                                                elif b.atom:
                                                    for c in makeIter(b.atom):
                                                        for elapsed_time in b.elapsed_timestamp_nanos:
                                                            printAtom(elapsed_time+bootTimeNanos, c, strhash, westworld)
                                except Exception as e:
                                    print("***ERROR gauge metrics failed: ",e)
                                    print("---"); print(aa); print("---")
    except Exception as e:
        print("***ERROR WESTWORLD grep: ",e)

def decode_westworld(bytes, verbose=True, terse=False, grep=True, debug=False):
    try:
        if debug:
            fname='/tmp/westworld_bytes'
            f = open(fname, 'wb')
            f.write(bytes)
            f.close()
        decoded = decode_named("android.os.statsd.WestworldRequest", "stats_log.proto", bytes)
        #print(decoded)
        if grep:
            grep_westworld(bytes)
        return(decoded)
    except DecodeNamedError as e:        
        if verbose:
            print("***ERROR: ",e)
        return "Failed"


def decode_lockbox(bytes, verbose=True, terse=False, Grep=True, debug=False):
    try:
        if debug:
            fname='/tmp/lockbox_bytes'
            f = open(fname, 'wb')
            f.write(bytes)
            f.close()
        decoded = decode_named("LockboxRequest", "lockbox.proto", bytes)
        #print(decoded)
        if Grep:
            lockbox = lockbox_pb2.LockboxRequest()
            lockbox.ParseFromString(bytes)
            # print interesting content in a way that's easy to grep out of log file
            for l in lockbox.lockboxUsageReport:
                print("+++LOCKBOX", l.timestamp, lockbox.EventType.Name(l.eventType), l.packageName, l.className)
        return(decoded)
    except (DecodeNamedError, ValueError) as e:        
        if verbose:
            print("***ERROR: ",e)
        return "Failed"


def decode_AR(bytes, verbose=True, terse=False, Grep=True, debug=False):
    try:
        if debug:
            fname='/tmp/AR_bytes'
            f = open(fname, 'wb')
            f.write(bytes)
            f.close()
        decoded = decode_named("ActivityRecognitionRequest", "activity_recognition.proto", bytes)
        #print(decoded)
        if Grep:
            try: 
                AR = activity_recognition_pb2.ActivityRecognitionRequest()
                AR.ParseFromString(bytes)
                # print interesting content in a way that's easy to grep out of log file
                # (the lists are repeated fields, so each is just looped over: fieldIsSet() of one is always
                # true, which hid the CHRE and transition lists behind activityDetectedList)
                for ar in AR.activityRecognitionEvent:
                    for a in ar.activityDetectedList:
                        for aa in a.activityDetected:
                            for aaa in aa.activity:
                                print("+++ACTIVITY_RECOGNITION", aa.timeMillis, aaa.activity, aaa.confidence)
                    for a in ar.activityDetectedCHREList:
                        for aa in a.activityDetected:
                            for aaa in aa.activity:
                                if aaa.HasField("activity"):
                                    print("+++ACTIVITY_RECOGNITION_CHRE", aa.chreAbsoluteTimeInMillis, aaa.activity, aaa.confidence)
                    for t in ar.activityTransitionEvent:
                        # a transition carries no time of its own: the request's
                        print("+++ACTIVITY_RECOGNITION_TRANSITION", AR.currentTimeMillis, t.newActivity1.activity, t.newActivity1.confidence)
            except Exception as e:
                print("***ERROR AR grep: ",e)
        return(decoded)
    except DecodeNamedError as e:        
        if verbose:
            print("***ERROR: ",e)
        return "Failed"


def decode_tron(bytes, verbose=True, terse=False, debug=False):
    try:
        #f = open('/tmp/tron_bytes', 'wb')
        if debug:
            fname='/tmp/tron_bytes'
            f = open(fname, 'wb')
            f.write(bytes)
            f.close()
        #decoded = subprocess.check_output("protoc --decode=\"TronRequest\" -I='"+mypath+"' tron.proto  </tmp/tron_bytes", shell=True, stderr=subprocess.STDOUT, text=True)
        decoded = run_decoder_script("tron_decode", bytes)
        #print("TRON decoded="+decoded)
        return(decoded)
    except ScriptDecodeError as e:        
        if verbose:
            print("***ERROR: ",e)
        return "Failed"

def decode_netstats(bytes, verbose=True, terse=False, debug=False):
    try:
        if debug:
            fname='/tmp/netstats_bytes'
            f = open(fname, 'wb')
            f.write(bytes)
            f.close()
        decoded = decode_named("NetstatsRequest", "netstats.proto", bytes)
        #print(decoded)
        return(decoded)
    except DecodeNamedError as e:        
        if verbose:
            print("***ERROR: ",e)
        return "Failed"

def decode_scoobyevents(bytes, verbose=True, terse=False, Grep=True, debug=False):
    try:
        if debug:
            fname='/tmp/scoobyevents_bytes'
            f = open(fname, 'wb')
            f.write(bytes)
            f.close()
        decoded = decode_named("ScoobyEventsRequest", "scoobyevents.proto", bytes)
        #print(decoded)
        grep=""
        if (decoded is not None) and Grep:
            grep="+++SCOOBY_EVENTS ";
            res = decoded.split('\n')
            try:
                found = False
                for s in res:
                    if re.search('phoneNumber', s):
                        grep=grep+s.replace(" ", "")
                        found=True
                if not found:
                    # try alt protobuf format (events in field 1, seen in some older measurements)
                    try:
                        decoded_alt = decode_named("AltScoobyEventsRequest", "scoobyevents.proto", bytes)
                    except DecodeNamedError:
                        decoded_alt = ""
                    res_alt = decoded_alt.split('\n')
                    for s in res_alt:
                        if re.search('phoneNumber', s):
                            grep=grep+s.replace(" ", "")
                            found=True
                    if found:
                        decoded = decoded_alt
                grep=grep+"\n"
            except Exception as e:
                print("***ERROR SCOOBY_EVENTS grep: ",e)
                return "Failed"
        return grep+decoded
    except DecodeNamedError as e:
        if verbose:
            print("***ERROR: ",e)
        return "Failed"

def decode_scoobymessage(bytes, verbose=True, terse=False, Grep=True, debug=False):
    try:
        if debug:
            fname='/tmp/scoobymessageevents_bytes'
            f = open(fname, 'wb')
            f.write(bytes)
            f.close()
        decoded = decode_named("ScoobyEventsRequest", "scoobymessageevents.proto", bytes)
        #print(decoded)
        grep=""
        if (decoded is not None) and Grep:
            grep="+++SCOOBY_MESSAGE_LOG ";
            res = decoded.split('\n')
            try:
                for s in res:
                    if re.search('phoneNumber', s):
                        grep=grep+s.replace(" ", "")
                grep=grep+"\n"
            except Exception as e:
                print("***ERROR SCOOBY_MESSAGE_LOG grep: ",e)
                return "Failed"
        return grep+decoded
    except DecodeNamedError as e:
        if verbose:
            print("***ERROR: ",e)
        return "Failed"

def decode(data):
    # prints what running this script on a file holding data prints
    #print(decode_pb(data))

    try:
        logbatch = logbatch_pb2.ClearcutLoggerEvents()
        logbatch.ParseFromString(data)
        for i in range(len(logbatch.inner)):
            inner = logbatch.inner[i]
            # just output dialer events, ignore the rest
            #if inner.logSourceName == "ANDROID_DIALER":
            #    try_decode_pb_array(None, inner.logEntry, decode_dialer_pb, verbose=False)
            # just output messages events, ignore the rest
            #if inner.logSourceName == "ANDROID_MESSAGING":
            #    try_decode_pb_array(None, inner.logEntry, decode_messaging_pb, verbose=False)
            #continue
            print("logBatchInner "+str(i)+" {")
            #print("header{\n"+textwrap.indent(str(inner.header),'   ')+"}")
            print(protoToString("header", inner.header))
            if "androidID" in str(inner.header):
                androidID = True
            else:
                androidID = False
            print("currentTimeMillis: "+str(inner.currentTimeMillis))
            print("pseudonymousIdToken: "+inner.pseudonymousIdToken)
            print("elapsedTime: "+str(inner.elapsedTime))
            print("qosTier: "+str(inner.qosTier))
            print("deviceStatus{\n"+textwrap.indent(str(inner.deviceStatus),'   ')+"}")
            # print out any other fields we might have missed
            unknown = protoUnknownFieldsToString(inner)
            if len(unknown) > 0:
                print(unknown)

            if True:  #tag log source name with whether androidID is set in header
                if not androidID:
                    print("logSourceName: "+inner.logSourceName+' (anon)') 
                else:
                    print("logSourceName: "+inner.logSourceName)
            else:
                print("logSourceName: "+inner.logSourceName)
            print_consent_info(inner.logEntry)
            #try_decode_pb_array("logEntry", inner.logEntry, decode_pb)   
            if inner.logSourceName == "ANDROID_MESSAGING":
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_messaging_pb, verbose=True, debug=False) )  
            elif inner.logSourceName == "ANDROID_DIALER":
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_dialer_pb, verbose=True, debug=False))
            elif inner.logSourceName == "LATIN_IME":
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_gboard_pb, verbose=True, debug=False))
            elif inner.logSourceName == "ICING":
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_icing_pb, verbose=True, debug=False))
            elif inner.logSourceName == "CLIENT_LOGGING_PROD":
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_clientlogging_pb, verbose=True, debug=False))
            elif inner.logSourceName == "AUTOFILL_WITH_GOOGLE":
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_autofill_pb, verbose=True, debug=False))
            elif inner.logSourceName.endswith("_PRIMES"):  # ANDROID_MESSAGING_PRIMES, DIALER_ANDROID_PRIMES, GMM_PRIMES, ...
                print(try_decode_pb_array("logEntry", inner.logEntry, functools.partial(decode_primes_pb, source=inner.logSourceName), verbose=True, debug=False))
            elif inner.logSourceName in AGSA_SOURCES:
                print(try_decode_pb_array("logEntry", inner.logEntry, functools.partial(decode_agsa_pb, source=inner.logSourceName), verbose=True, debug=False))
            elif inner.logSourceName == "WESTWORLD_COUNTERS":
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_westworld_counters_pb, verbose=True, debug=False))
            elif inner.logSourceName == "WESTWORLD" or inner.logSourceName == "ANONYMOUS_WESTWORLD":
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_westworld, verbose=True, debug=False))
            elif inner.logSourceName == "LB_AS" or inner.logSourceName == "LB_CFG":
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_lockbox, verbose=True, debug=False))
            elif inner.logSourceName == "TRON":
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_tron, verbose=True, debug=False))
                #print('logEntry:')
                #res=decode_tron(inner.logEntry) 
                #if res=="Failed":
            elif inner.logSourceName == "ACTIVITY_RECOGNITION":
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_AR, verbose=True, debug=False))
            elif inner.logSourceName == "NETSTATS":
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_netstats, verbose=True, debug=False))
            elif inner.logSourceName == "SCOOBY_EVENTS":
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_scoobyevents, verbose=True, debug=False))
            elif inner.logSourceName == "SCOOBY_MESSAGE_LOG":
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_scoobymessage, verbose=True, debug=False))
            elif inner.logSourceName == "CHIME":
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_chime_pb, verbose=True, debug=False))
            elif inner.logSourceName == "ON_DEVICE_ABUSE":
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_ondeviceabuse_pb, verbose=True, debug=False))
            else:
                print(try_decode_pb_array("logEntry", inner.logEntry, decode_pb, verbose=True, debug=False))
            print("}")
    except Exception as e:
        print("***ERROR: ",e)

if __name__ == "__main__":
    if len(sys.argv)>1:
        fname=sys.argv[1]
    else:
        fname='/tmp/batch_bytes'
    f = open(fname, 'rb')
    data = f.read()
    f.close()
    decode(data)
