# Class to to deal with CT Logs.
from data_interfaces import *
from CONSTANTS import *
import requests

# get a JSON dictionary of CT Logs from URL or a file. Currently only google supplies these.
# in future there may be other trackers we want to use
# GOOGLE JSON SCHEMA: https://www.gstatic.com/ct/log_list/log_list_schema.json

def get_ct_json_from_url(url):
    https_response = HTTP_CLIENT.request('GET',url)
    ct_json = to_json(https_response.data)

    if(https_response.status==200):
        return ct_json

def get_ct_json_from_file(file):
    ct_logs = open_file('./ct-logs',file)
    ct_json = to_json(ct_logs)
    return ct_json

def get_ct_operators(ct_dict):
    return ct_dict['operators']

def get_ct_logs(ct_dict):
    return ct_dict['logs']


def get_log_details(url):
    url = url + CT_STH_URL
    print(url)
    try:
        https_response = requests.get(url)

        if(https_response.status_code==200):
            print(https_response.text)
        else:
            print("Couldn't Retrieve STH")
            print(https_response.status_code)
    except Exception as e :
        print("Couldn't Hit a server {}".format(e.__repr__))

logs_to_test = get_ct_logs(get_ct_json_from_url("https://ct.grahamedgecombe.com/logs.json"))
get_log_details("https://ctlog.wotrus.com")
for log_to_test in logs_to_test:
    get_log_details(log_to_test['url'])
