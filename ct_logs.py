# Class to to deal with CT Logs.
from data_interfaces import *
from CONSTANTS import *

# get a JSON dictionary of CT Logs from URL or a file. Currently only google supplies these.
# in future there may be other trackers we want to use
# GOOGLE JSON SCHEMA: https://www.gstatic.com/ct/log_list/log_list_schema.json

def get_ct_json_from_url(url,file):
    https_response = HTTP_CLIENT.request('GET',url)
    ct_json = to_json(https_response.data)

    if(https_response.status==200):
        write_file_from_json_dict('./ct-logs',file,ct_json)
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
    url = "https://" + url + CT_STH_URL
    print(url)
    try:
        https_response = HTTP_CLIENT.request('GET',url)
        if(https_response.status==200):
            print(https_response.data)
        else:
            print("Couldn't Retrieve STH")
    except:
        print("Couldn't Hit a server")

# def find_logs_for_operator(operator_id, logs_dict):
#     return [element for element in logs_dict if element['id'] == operator_id]]

ctdict = get_ct_json_from_url('https://ctlog.gdca.com.cn/ct/v1/get-sth','test3')
# operators = get_ct_operators(ctdict)
# test = find_logs_for_operator(0,ctdict)
# print(type(test))
