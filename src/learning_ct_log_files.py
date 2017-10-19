import requests
import json
from datetime import datetime as dt
import ctl_cert_parser_structure as ctls
import base64

requests.packages.urllib3.disable_warnings()
grahamedgecombe_known_logs = requests.get("https://ct.grahamedgecombe.com/logs.json").json()
google_known_logs = requests.get("https://www.gstatic.com/ct/log_list/all_logs_list.json").json()


total_certs = 0
working_logs = 0
non_working_logs = 0

def log_age(url,first_last):
    entry = requests.get(url, verify=False)
    ct_entry_json = json.loads(entry.text)
    ct_metadata = ctls.MerkleTreeHeader.parse(base64.b64decode(ct_entry_json['entries'][0]['leaf_input']))
    timestamp = dt.fromtimestamp(ct_metadata.Timestamp/1000).strftime('%d-%m-%Y')
    print("\t \ Timestamp of {} Record: {} ".format(first_last,timestamp))

def log_root_certs(url):
    roots_entry = requests.get(url, verify=False)
    root_certs_json = json.loads(roots_entry.text)
    print("\t \ Number of CA Roots in Log: {}".format(len(root_certs_json['certificates'])))

def log_blocksize(url):
    log_response = requests.get(url, verify=False)
    log_blocksize_json = json.loads(log_response.text)
    print("\t \ Log Block Size: {}".format(len(log_blocksize_json['entries'])))


for log in google_known_logs['logs']:
    url = "https://{}ct/v1/get-sth".format(log['url'])
    print("Connecting to CT Log with Description: {}".format(log['description']))
    try:
        #https_response = requests.get(url)
        https_response = requests.get(url, verify=False)
        json_data = json.loads(https_response.text)
        if(https_response.status_code==200):

            print("\t \ Log Has {} Certificate Entries ".format(json_data['tree_size']))
            timestamp = dt.fromtimestamp(json_data['timestamp']/1000).strftime('%d-%m-%Y')
            print("\t \ Server NTP Date: {}".format(timestamp))

            url_last_entry = "https://{}ct/v1/get-entries?start={}&end={}".format(log['url'],json_data['tree_size']-1,json_data['tree_size']-1)
            url_first_entry ="https://{}ct/v1/get-entries?start=1&end=1".format(log['url'])
            log_age(url_first_entry,"First")
            log_age(url_last_entry,"Last")

            url_root_certs = "https://{}ct/v1/get-roots".format(log['url'])
            log_root_certs(url_root_certs)

            url_log_blocksize = "https://{}ct/v1/get-entries?start={}&end={}".format(log['url'],1,2000)
            log_blocksize(url_log_blocksize)
            print("\r\n")

            print("\t \ Verification URLS:")
            print("\t \t \ {}".format(url))
            print("\t \t \ {}".format(url_first_entry))
            print("\t \t \ {}".format(url_last_entry))
            print("\t \t \ {}".format(url_root_certs))
            print("\t \t \ {}".format(url_log_blocksize))

            print("\r\n")
            working_logs = working_logs+1
            total_certs += int(json_data['tree_size'])
        else:
            print("\t \ Couldn't Retrieve STH. HTTP Code is {} \r\n".format(https_response.status_code))
            print("\t \ Verification URLS:")
            print("\t \t \ {}".format(url))
            print("\r\n")
            non_working_logs = non_working_logs +1

    except Exception as e :
        print("\t \ Couldn't Connect to the server. Error Detail: {} \r\n".format(type(e)))
        print("\t \ Verification URLS:")
        print("\t \t \ {}".format(url))
        print("\r\n")
        non_working_logs = non_working_logs +1

print("-----------------------------")
print("Total Number of Certificate: {}".format(total_certs))
print("Number of Working Logs: {}".format(working_logs))
print("Number of Non Working Logs: {}".format(non_working_logs))
print("Number of Aged Logs (No Longer Active): {}")
