import requests
import json
from data_interfaces import *
import base64
from OpenSSL import crypto


DIGICERT = "https://ct2.digicert-ct.com/log/ct/v1/get-roots"
GOOGLE_ICARUS = "https://ct.googleapis.com/icarus/ct/v1/get-roots"
SYMANTEC = "https://ct.ws.symantec.com/ct/v1/get-roots"

def parse_log_root_certs(root_certs):
    #print("\r\n Analysing Root Certs of {} ".format(log))
    print("Log has {} Trusted Root Certs \r\n".format(len(root_certs['certificates'])))
    for root_cert in root_certs['certificates']:
        crypto_x509_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, base64.b64decode(root_cert))
        print(crypto_x509_cert.get_subject().CN)




root_certs = to_json(HTTP_CLIENT.request("GET",DIGICERT).data)
parse_log_root_certs(root_certs)
# root_certs = to_json(HTTP_CLIENT.request("GET",GOOGLE_ICARUS).data)
# parse_log_root_certs("Google Icarus CT Log",root_certs)
# root_certs = to_json(HTTP_CLIENT.request("GET",SYMANTEC).data)
# parse_log_root_certs("Symantec Log",root_certs)
