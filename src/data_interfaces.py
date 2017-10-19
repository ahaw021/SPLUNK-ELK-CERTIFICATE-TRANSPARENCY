import json
import urllib3

# DISABLE ssl warnings. We should try to make these work with a Mozilla Cert Bundle
# Set Timeout to 2 seconds so we don't slow down the script for non responsive servers

urllib3.disable_warnings()
HTTP_CLIENT = urllib3.PoolManager(timeout=5.0)

def write_file(path,name,data):
    file = open(path+"/"+name,'w')
    file.write(data)
    file.close

def write_file_from_json_dict(path,name,data):
    file = open(path+"/"+name,'w')
    file.write(json.dumps(data))
    file.close

def append_file(path,name,data):
    file = open(path+"/"+name,'a')
    file.write(data)
    file.close

def open_file(path,name):
    file = open(path+"/"+name,'r')
    return file.read()

def to_json(json_string):
    json_dict = json.loads(json_string)
    return json_dict

# def http_get(url):
