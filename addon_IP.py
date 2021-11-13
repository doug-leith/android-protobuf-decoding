
from mitmproxy import http
import zlib
import gzip
import subprocess
from codecs import encode, decode
import operator
import sys
import os

# add folder where this script is to python search path (so can find helpers)
mydir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(mydir)
# from decoding_helpers import decode_pb, decode_wbxml, decode_log_batch, decode_firebase_analytics, try_decode_pb_array

# import geoip2.database  # for geolocating server IP
import ipinfo
access_token = '49a4d3ea98660d'
handler = ipinfo.getHandler(access_token)


class PrintTrace:

    IP_details = {}

    def response(self, flow:http.HTTPFlow):
        if flow.request.host not in self.IP_details.keys():
            self.IP_details[flow.request.host] = 1
            details = handler.getDetails(flow.request.host)
            try:
                print("%s, %s, %s, %s, %s, %s"%(flow.request.host, flow.request.pretty_host, details.country, 
                    details.region, details.city, details.loc))
            except Exception as e:
                print(e)
                sys.exit()
#       with geoip2.database.Reader(mydir+'/GeoLite2-City_20210908/GeoLite2-City.mmdb') as reader:
#            try:
#                response = reader.city(flow.request.host)
#                print(flow.request.host,', ',flow.request.pretty_host,', ', response.country.name,', ', 
#                    response.subdivisions.most_specific.name,', ', response.city.name,', ', response.location.latitude,', ', response.location.longitude)
#            except Exception as e:
#                print(flow.request.host,' ',flow.request.pretty_host,' couldnt find location ',e)
    
        return



addons = [PrintTrace()]
