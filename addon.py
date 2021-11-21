#import zlib
#import gzip
import subprocess
#from codecs import encode, decode
#import operator
import sys
import os
#import geoip2.database  # for geolocating server IP
from mitmproxy import http, io
import re

# add folder where this script is to python search path (so can find helpers)
sys.path.append(os.path.dirname(os.path.realpath(__file__)))
from decoding_helpers import decode_pb, decode_wbxml, decode_log_batch, decode_firebase_analytics, try_decode_pb_array, decode_checkin


def decode_bond(buf):
    # this uses OneDrive telemetry schema from Samsung handset, not portable
    # and needs decoder executable "onedrive" to be in directory
    unzipped = buf  # zlib.decompress(buf,32 + zlib.MAX_WBITS)
    f = open('/tmp/bond', 'wb')
    f.write(unzipped)
    f.close()
    try:
        return subprocess.check_output("./onedrive", shell=True, stderr=subprocess.STDOUT, text=True)
    except Exception as e:
        print(e)
        return "Failed"


def GetHumanReadable(size, precision=2):
    suffixes = ['B', 'KB', 'MB', 'GB', 'TB']
    suffixIndex = 0
    while size > 1024:
        suffixIndex += 1  # increment the index of the suffix
        size = size/1024.0  # apply the division
    return "%.*f%s"%(precision, size, suffixes[suffixIndex])


class PrintTrace:

    response_content_sum = 0
    request_content_sum = 0
    request_dict_sum = {}
    start_timestamp = -1

    # def __init__(self):
    #    self.f = open("tmp.mitm", "wb")
    #    self.w = io.FlowWriter(self.f)

    # def done(self):
    #    self.f.close()

    def response(self, flow:http.HTTPFlow):

        # print time when request occurred
        #print("timestamp %s"%(flow.request.timestamp_start))

        # unzip request body - not usually needed, mitmproxy takes care of this.
        #print(zlib.decompress(flow.request.raw_content,32 + zlib.MAX_WBITS))
        #f = open('temp.gz', 'w+b')
        #f.write(flow.request.raw_content)
        #f.close
        #with gzip.open('temp.gz', 'rb') as f:
        #  print(f.read())
        # return

        #print("!\http{%s}! %s" % (flow.request.method, flow.request.pretty_url))
        print("%s %s" % (flow.request.method, flow.request.pretty_url))
       
        # try to geo-locate server used in request (but its not that accurate ...)
        # with geoip2.database.Reader('GeoLite2-City_20210908/GeoLite2-City.mmdb') as reader:
        #     try:
        #         response = reader.city(flow.request.host)
        #         print("Estimated server location: ", response.country.name, response.subdivisions.most_specific.name, response.city.name)
        #     except:
        #         pass

        # settings for apple ios
        #exclude_resp = ["Content-Length", "Cache-Control", "Keep-Alive", "Date", "Server", "X-Frame-Options","Strict-Transport-Security","last-modified","Content-Type","Connection","Last-Modified","Vary","X-Cache","Via","x-amz-version-id","X-Amz-Cf-Id","Content-Encoding","content-type","content-length","cache-control","date","server","x-apple-lokamai-no-cache","x-apple-max-age","x-webobjects-loadaverage","Etag","X-Amz-Cf-Pop","content-encoding","vary","etag","Age","apple-timing-app","content-encoding","strict-transport-security","x-apple-partner","x-apple-request-store-front","x-cache","Accept-Ranges","Content-Language","Expires","expires","pragma","apple-seq","apple-tk","access-control-allow-origin","is-jetty","Content-Range","X-Content-Type-Options","Access-Control-Allow-Origin","Access-Control-Allow-Credentials","X-Content-Type-Options","X-XSS-Protection","accept-ranges","content-language","expires","via","Transfer-Encoding"]
        #exclude_req = ["Accept-Encoding", "Accept-Language", "X-Apple-I-TimeZone-Offset", "Host", "Accept","X-Apple-I-Client-Time","x-apple-tz","accept","x-apple-tz","x-apple-i-client-time","accept-language","accept-encoding","x-apple-i-timezone","x-apple-i-client-time","If-Modified-Since","x-xpple-ct-config-version","x-apple-ct-client-time","x-apple-client-versions","X-Apple-I-TimeZone","X-Apple-Tz","Range","accept-version","If-Modified-Since","x-apple-c2-metric-triggers","X-Apple-I-TimeZone","X-MMe-FMFAllowed","x-cloudkit-databasescope","x-cloudkit-environment","timestamp","os_Version","X-Apple-Download-Reason","X-Apple-Download-Identifier","x-ba-client-timestamp","x-ba-client-version","x-apple-setup-proxy-request","Connection","Content-Length","Content-Type","Cache-Control","X-MMe-Language","cache-control","content-encoding","X-Apple-I-Locale","X-Apple-Partner","X-Apple-Client-Versions","x-apple-ct-region-identifier","if-modified-since","if-none-match","x-http-method-override","If-None-Match","content-length","content-type","x-apple-i-locale","X-Apple-Languages","X-Apple-Seed","Content-Encoding"]
        #bold = ["X-Mme-Device-I", "X-Apple-I-SRL-NO", "x-apple-i-md-m", "x-apple-i-md", "cookie", "X-Apple-I-MD-M","X-Apple-I-MD","X-Mme-Device-Id","x-apple-seid","x-apple-adsid","Cookie","x-dsid","x-apple-actionsignature","x-apple-adsid","X-Apple-ADSID","X-Apple-AMD-M","X-Apple-AMD","X-Apple-ActionSignature","Device-UDID","x-apple-md-m","x-apple-amd","x-apple-amd-m"]

        # settings for android
        exclude_resp = []
        exclude_req = ["Accept-Encoding", "Connection", "Host", "Content-Encoding", "Content-Length",
                       "Content-Type", "Accept", "x-wap-profile", "accept-encoding", "content-length", 
                       "content-type", "cache-control", "date", "Content-type", "Accept-encoding", "content-encoding"]
        bold = ["x-goog-device-auth"]

        # try to pretty print interesting url query parameters and request headers
        req = flow.request.path.split("?")
        req = req[0]
        if req not in self.request_dict_sum:
            self.request_dict_sum[req] = 0
        for q in flow.request.query:
            self.request_content_sum += len(flow.request.query[q])
            self.request_dict_sum[req] += len(flow.request.query[q])
        first = True
        for h in flow.request.headers:
            self.request_content_sum += len(flow.request.headers[h])
            self.request_dict_sum[req] += len(flow.request.headers[h])
            if h in exclude_req:
                continue
            if (h in ["User-Agent", "user-agent"]) and ("Mozilla" in flow.request.headers[h] or "okhttp" in flow.request.headers[h] or "Dalvik" in flow.request.headers[h]):
                continue
            if h in bold:
                if h == "cookie" or h == "Cookie":
                    sstr = "   !\\textbf{%s}!: %s"%(h, flow.request.headers[h])
                else:
                    sstr = "   %s: !\\textbf{\\url{%s}}!"%(h, flow.request.headers[h])
            else:
                sstr = "   %s: %s"%(h, flow.request.headers[h])
            if first:
                print("Headers")
                first = False
            print(sstr)
        # print(flow.request.pretty_url)
        # print(flow.request.headers)

        # try to decode request body
        if flow.request.method == "POST":
            try:
                if "Content-Type" in flow.request.headers and flow.request.headers["Content-Type"] == "application/bond-compact-binary":
                    # assumes schema used by OneDrive on Samsung handset
                    print(decode_bond(flow.request.content))
                elif "Content-Type" in flow.request.headers and flow.request.headers["Content-Type"] == "application/vnd.syncml.dm+wbxml":
                    print(decode_wbxml(flow.request.content))
                elif flow.request.pretty_url == "https://app-measurement.com/a":
                    print(decode_firebase_analytics(flow.request.content))
                    #self.w.add(flow)
                    #exit()
                elif (flow.request.pretty_url == "https://play.googleapis.com/log/batch") or (flow.request.pretty_url=="https://play.googleapis.com/vn/log/batch"):
                    print(decode_log_batch(flow.request.content))
                    # save flow to file
                    #str = decode_log_batch(flow.request.content)
                    #print(str)
                    #if re.search(r"logSourceName: ANDROID\_MESSAGING", str):
                    #    print("***matched***")
                    #    self.w.add(flow)
                    #    exit()
                elif flow.request.pretty_url == "https://android.clients.google.com/checkin" or flow.request.pretty_url == "https://android.googleapis.com/checkin":
                    print(decode_checkin(flow.request.content, verbose=True))
                else:
                    # print(flow.request.content.decode('ascii'))
                    print(flow.request.content.decode('utf8'))
            except Exception as e: 
                #print(e)
                # got an error, try to decode as a protobuf
                buf = flow.request.content
                if False:  # don't try to decode POST body as protobuf 
                    print(buf)
                else:
                    try_decode_pb_array("POST Body", buf, decode_pb)

            self.request_content_sum += len(flow.request.content)
            self.request_dict_sum[req] += len(flow.request.content)
        if flow.response.content is None:
            size = 0
        else:
            size = len(flow.response.content)
        self.response_content_sum += size
        if self.start_timestamp < 0:
            self.start_timestamp = flow.request.timestamp_start
        print("<<< HTTP %d, %s" % (flow.response.status_code, GetHumanReadable(size)))

        # print stats in volume of content sent/received
        # print("Content to date: %d/%d, elapsed secs %d"%(self.request_content_sum,self.response_content_sum,flow.request.timestamp_start-self.start_timestamp))
        # print("data_sent,%d,%d,%d"%(self.request_content_sum,self.response_content_sum,flow.request.timestamp_start-self.start_timestamp))
        # print(sorted(self.request_dict_sum.items(), key=operator.itemgetter(1)))
        # for req in self.request_dict_sum:
        #   print("%s %d"%(req,self.request_dict_sum[req]))

        # note if response sets a cookie
        for h in flow.response.headers:
            if h in ["X-Apple-Set-Cookie", "Set-Cookie"]:
                print(" !\\textbf{%s}!: %s" % (h, flow.response.headers[h]))


addons = [PrintTrace()]
