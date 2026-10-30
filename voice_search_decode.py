# www.google.com/m/voice-search/up and /down: the Google app's S3 protocol, which carries Assistant queries,
# Assistant settings and client sync. An up body is a 10-byte header, then S3Requests, each after a 4-byte
# big-endian length; a down body is S3Responses framed the same way, without the header. Each message is decoded
# with voice_search_named.proto (recovered from the Google app, GSA 15.5.58). Typed values inside (a type name and
# the value's bytes: Assistant params, client-op properties and arguments) are decoded after the message with the
# type voice_search_any_types.json gives for the name, gzip-compressed bytes with the type in GZIP_TYPES (or raw), and
# the Google Play services Wallet client token that TransactionsParams forwards (device identifiers, location, IP
# addresses) with wallet_client_token_named.proto.
import gzip, json, os, struct
from google.protobuf import descriptor
from decode_named import decode_named, DecodeNamedError, message_class
from decode_raw import decode_raw, DecodeRawError

PROTO = "voice_search_named.proto"
INCLUDE = os.path.dirname(os.path.realpath(__file__))
UP_HEADER = bytes.fromhex("0000c548232af5c805ff")
ANY_TYPES = json.load(open(os.path.join(INCLUDE, "voice_search_any_types.json")))  # type name -> message
# (message, bytes field) holding gzip-compressed bytes -> the message they decompress to
GZIP_TYPES = {("ClientDataHeader", "compressed_header"): "ClientDataHeader"}  # the whole header (apya.java)
# (message, bytes field) holding a message of another proto -> (message, proto)
EMBEDDED = {("TransactionsParams", "wallet_client_token"): ("WalletClientToken", "wallet_client_token_named.proto")}

def frames(data, start):
    # the length-prefixed messages from start, and where they end (short of len(data) if the last is cut off)
    out, i = [], start
    while i + 4 <= len(data):
        n = struct.unpack(">I", data[i:i + 4])[0]
        if i + 4 + n > len(data):
            break
        out.append(data[i + 4:i + 4 + n])
        i += 4 + n
    return out, i

def _decode(message, data, proto=PROTO):
    try:
        return decode_named(message, proto, data, INCLUDE)
    except DecodeNamedError as e:
        return "***ERROR %s: %s\n" % (message, e)

def _typed_values(m, path, out):
    # (path, kind, type name or None, message or None, bytes) for each typed value, gzip-compressed bytes field and
    # embedded message under m, depth first; a typed value's own message is searched too
    fields = m.ListFields()
    plain = {fd.number: v for fd, v in fields if not fd.is_extension}
    if isinstance(plain.get(1), str) and isinstance(plain.get(2), bytes) and plain[1].split("/")[-1] in ANY_TYPES:
        name = ANY_TYPES[plain[1].split("/")[-1]]
        out.append((path, "typed", plain[1], name, plain[2]))
        try:
            _typed_values(message_class(name, PROTO, INCLUDE).FromString(plain[2]), path + " > " + name, out)
        except Exception:
            pass
        return out
    for fd, v in fields:
        name = "[%s]" % fd.full_name if fd.is_extension else fd.name
        values = v if fd.label == descriptor.FieldDescriptor.LABEL_REPEATED else [v]
        for x in values:
            if fd.message_type is not None:
                _typed_values(x, path + "." + name, out)
            elif isinstance(x, bytes) and (m.DESCRIPTOR.name, fd.name) in EMBEDDED:
                out.append((path + "." + name, "embedded", None, EMBEDDED[(m.DESCRIPTOR.name, fd.name)], x))
            elif isinstance(x, bytes) and x[:2] == b"\x1f\x8b":
                out.append((path + "." + name, "gzip", None, GZIP_TYPES.get((m.DESCRIPTOR.name, fd.name)), x))
    return out

def decode_message(message, data):
    # message's decode, then its typed values, gzip-compressed bytes and embedded messages
    out = _decode(message, data)
    try:
        m = message_class(message, PROTO, INCLUDE).FromString(data)
    except Exception:
        return out
    for path, kind, type_name, name, value in _typed_values(m, message, []):
        if kind == "embedded":
            out += "%s (%s):\n%s" % (path, name[0], _decode(name[0], value, name[1]))
        elif kind == "gzip":
            try:
                value = gzip.decompress(value)
            except (OSError, EOFError) as e:
                out += "%s (gzip): ***ERROR %s\n" % (path, e)
                continue
            if name:
                out += "%s (gzip, %s):\n%s" % (path, name, _decode(name, value))
            else:
                try:
                    out += "%s (gzip, decoded raw):\n%s" % (path, decode_raw(value))
                except DecodeRawError as e:
                    out += "%s (gzip): ***ERROR %s\n" % (path, e)
        else:
            out += "%s (%s):\n%s" % (path, type_name, _decode(name, value))
    return out

def _messages(m):
    # m and every message under it, typed values' messages included
    yield m
    fields = m.ListFields()
    plain = {fd.number: v for fd, v in fields if not fd.is_extension}
    if isinstance(plain.get(1), str) and isinstance(plain.get(2), bytes) and plain[1].split("/")[-1] in ANY_TYPES:
        try:
            yield from _messages(message_class(ANY_TYPES[plain[1].split("/")[-1]], PROTO, INCLUDE).FromString(plain[2]))
        except Exception:
            pass
    for fd, v in fields:
        if fd.message_type is not None:
            for x in (v if fd.label == descriptor.FieldDescriptor.LABEL_REPEATED else [v]):
                yield from _messages(x)

def _wallet_contents(token):
    # which device identifiers, location and network details a Wallet client token holds
    try:
        t = message_class("WalletClientToken", "wallet_client_token_named.proto", INCLUDE).FromString(token)
    except Exception:
        return ["undecoded"]
    context = t.request_context.native_client_context
    ids, signals = context.risk_data.device_ids, context.risk_data.risk_signals
    present = [("imei", ids.imei), ("phone_number", ids.line1_number), ("serial", ids.serial),
               ("android_id", ids.android_id or context.android_id), ("imsi", context.imsi_prefix or context.imsi_sha1),
               ("network_location", signals.HasField("last_network_location")), ("ip_addresses", signals.ip_addresses),
               ("account_names", t.request_context.account_names)]
    return [name for name, value in present if value]

def _grep(parsed, up):
    # +++VOICE_SEARCH line: the service, the query transcript, how many earlier queries are resent with it, the
    # foreground app, how many installed apps are listed, and what the Wallet client token holds (device
    # identifiers, location, IP addresses); for a response, its text replies
    service, transcript, previous, foreground, apps, wallet, texts = "", "", 0, "", 0, None, []
    for m in parsed:
        if up and not service:
            service = m.service
        for x in _messages(m):
            name = x.DESCRIPTOR.name
            if name == "RecognitionEvent" and x.event_type == 1 and x.result.hypothesis:   # RECOGNITION_COMPLETED
                transcript = x.result.hypothesis[0].text
            elif name == "QueryContextParams":
                previous = max(previous, len(x.query_history.previous_queries))
                foreground = x.current_query.foreground_package or foreground
            elif name == "AndroidAppInfo":
                apps += 1
            elif name == "TransactionsParams" and x.wallet_client_token:
                wallet = _wallet_contents(x.wallet_client_token)
            elif name == "ShowTextArgs" and x.text:
                texts.append(x.text)
    if not up:
        return "+++VOICE_SEARCH down%s\n" % "".join(" text=%r" % t for t in texts)
    out = "+++VOICE_SEARCH up service=%s" % service
    if transcript:
        out += " transcript=%r previous_queries=%d" % (transcript, previous)
    if foreground:
        out += " foreground=%s" % foreground
    if apps:
        out += " installed_apps=%d" % apps
    if wallet is not None:
        out += " wallet_client_token=%s" % (",".join(wallet) or "-")
    return out + "\n"

def decode(data, up):
    if up and data[:len(UP_HEADER)] != UP_HEADER:
        return None
    messages, end = frames(data, len(UP_HEADER) if up else 0)
    if end != len(data) or not any(messages):
        return None
    message = "S3Request" if up else "S3Response"
    out, parsed = "", []
    for i, b in enumerate(messages):
        if b:
            out += "S3 %s %d:\n" % ("request" if up else "response", i) + decode_message(message, b)
            try:
                parsed.append(message_class(message, PROTO, INCLUDE).FromString(b))
            except Exception:
                pass
    return _grep(parsed, up) + out

def decode_up(data):
    return decode(data, True)

def decode_down(data):
    return decode(data, False)
