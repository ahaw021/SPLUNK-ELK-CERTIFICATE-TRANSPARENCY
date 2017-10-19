#URL of Logs JSON and JSON SCHEMA
from string import Template

ALL_CT_LOGS_URL     =  "https://www.gstatic.com/ct/log_list/all_logs_list.json"
GOOGLE_CT_LOGS_URL  =  "https://www.gstatic.com/ct/log_list/log_list.json"
CT_LOGS_SCHEMA      =  "https://www.gstatic.com/ct/log_list/log_list_schema.json"

# SUFFIXES FOR URL ENDPOOINTS
# RFC: https://tools.ietf.org/html/rfc6962

#STH = Signed Tree Head. Section 4.3 of RFC
CT_STH_URL = "/ct/v1/get-sth"

# Retrieve Entries from Log. Section 4.6 of RFC
# User String Templates to Make it Easier to Do Substitutions
CT_ENTRIES = Template('/ct/v1/get-entries?start=$start&end$end')

# Retrieve Accepted Root Certificates. Section 4.7 of RFC

ACCEPTER_ROOTS="/ct/v1/get-roots"
