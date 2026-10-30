# federatedcompute-pa.googleapis.com: the HTTP protocol of Google's federated learning and analytics client
# (open-source federated compute, package google.internal.federatedcompute.v1; protos in
# federated_learning_protos/federatedcompute/). A URL is matched against the google.api.http path templates of
# the RPCs in those protos, and the request and response are decoded as that RPC's input and output types. An
# Operation's response and metadata (google.protobuf.Any), and an eligibility eval task's population eligibility
# spec when it is sent inline, are decoded after it; an error response is a google.rpc.Status.
import gzip, os, re, urllib.parse
from google.protobuf import descriptor_pb2, unknown_fields
from decode_named import decode_named, DecodeNamedError, message_class, _pool

INCLUDE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "federated_learning_protos")
PROTOS = ["federatedcompute/eligibility_eval_tasks.proto", "federatedcompute/task_assignments.proto",
          "federatedcompute/aggregations.proto", "federatedcompute/secure_aggregations.proto"]
HTTP = 72295728  # google.api.http, the MethodOptions extension giving an RPC's URL

_routes = None

def routes():
    # (path regex, RPC name, input type, output type, proto) for every RPC in PROTOS
    global _routes
    if _routes is None:
        _routes = []
        for proto in PROTOS:
            pool, _ = _pool(INCLUDE, proto)
            HttpRule = message_class("google.api.HttpRule", proto, INCLUDE)
            fd = descriptor_pb2.FileDescriptorProto.FromString(pool.FindFileByName(proto).serialized_pb)
            for service in fd.service:
                for m in service.method:
                    for f in unknown_fields.UnknownFieldSet(m.options):
                        if f.field_number != HTTP:
                            continue
                        rule = HttpRule.FromString(f.data)
                        path = getattr(rule, rule.WhichOneof("pattern"))
                        regex = re.sub(r"\\\{(\w+)(=[^}]*)?\\\}", r"(?P<\1>[^/:]+)", re.escape(path))
                        _routes.append((re.compile(regex + "$"), m.name, m.input_type.lstrip("."),
                                        m.output_type.lstrip("."), proto))
    return _routes

def match(url):
    # (RPC name, input type, output type, proto, {path parameter: value}) for url, or None
    path = urllib.parse.urlsplit(url).path
    for regex, rpc, intype, outtype, proto in routes():
        m = regex.match(path)
        if m:
            return rpc, intype, outtype, proto, {k: urllib.parse.unquote(v) for k, v in m.groupdict().items()}
    return None

def _grep(direction, rpc, params):
    return "+++FEDERATEDCOMPUTE %s %s %s\n" % (rpc, direction, " ".join("%s=%s" % kv for kv in params.items()))

def _decode(message, proto, data):
    try:
        return decode_named(message, proto, data, INCLUDE)
    except DecodeNamedError as e:
        return "***ERROR %s: %s\n" % (message, e)

def decode_request(url, data):
    m = match(url)
    if m is None:
        return None
    rpc, intype, _outtype, proto, params = m
    return _grep("request", rpc, params) + _decode(intype, proto, data)

def decode_response(url, data, status=200):
    m = match(url)
    if m is None:
        return None
    rpc, _intype, outtype, proto, params = m
    if not 200 <= status < 300:
        return _grep("response", rpc, params) + _decode("google.rpc.Status", "google/rpc/status.proto", data)
    out = _grep("response", rpc, params) + _decode(outtype, proto, data)
    if outtype == "google.longrunning.Operation":
        try:
            op = message_class(outtype, proto, INCLUDE).FromString(data)
        except Exception:
            return out
        for name in ("metadata", "response"):
            if op.HasField(name):
                any_ = getattr(op, name)
                out += "%s (%s):\n" % (name, any_.type_url) + _decode(any_.type_url.split("/")[-1], proto, any_.value)
    elif outtype.endswith(".EligibilityEvalTaskResponse"):
        try:
            spec = message_class(outtype, proto, INCLUDE).FromString(data).eligibility_eval_task.population_eligibility_spec
        except Exception:
            return out
        if spec.HasField("inline_resource"):
            inline = spec.inline_resource
            try:
                body = gzip.decompress(inline.data) if inline.compression_format == 1 else inline.data
            except (OSError, EOFError) as e:
                return out + "***ERROR population_eligibility_spec: %s\n" % e
            out += "population_eligibility_spec (inline):\n" + _decode(
                "google.internal.federated.plan.PopulationEligibilitySpec", "population_eligibility_spec.proto", body)
    return out
