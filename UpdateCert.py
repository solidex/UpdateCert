import sys
import os
import datetime
import json
import requests
import config


if config.SQUASH_SSL == True:
    requests.packages.urllib3.disable_warnings()
    r = requests.Session()
    r.verify = False
else:
    r = requests.Session()

try:
    RENEWED_LINEAGE = "" # os.environ['RENEWED_LINEAGE']
except KeyError as e:
    sys.exit('ERROR: Expected shell environment variable (RENEWED_LINEAGE) doesn\'t exist.')

# CERT_FILE = RENEWED_LINEAGE + '/fullchain.pem'
# KEY_FILE = RENEWED_LINEAGE + '/privkey.pem'

CERT_FILE = '/home/paul/share/combined.crt'
KEY_FILE = '/home/paul/share/combined.key'

VERSION=datetime.datetime.now().strftime('%Y%m%d%H%M')

if config.DEBUG == True:
    print('DEBUG: New certificate to be named - ' + config.CERT_NAME + '_' + VERSION)

### LOGIN AND GET TOKEN

payload = { 'username': config.ADC_USERNAME, 'password': config.ADC_PASSWORD }
response = r.post(config.ADC_URL + '/api/user/login', json = payload )

if response.status_code == requests.codes.ok:
    json_data = json.loads(response.text)
    r.headers.update({'authorization': 'Bearer ' + json_data['token']})
else:
    print('EXIT POINT 1 - ' + response.text)
    sys.exit('ERROR: Could not successfully login to load balancer.')


### PUSH NEW CERTIFICATE TO LOAD BALANCER

payload = { 'mkey': config.CERT_NAME + '_' + VERSION, 'vdom': config.VDOM, 'type': 'CertKey' }
files = { 'cert': open(CERT_FILE, 'rb'), 'key': open(KEY_FILE,'rb') }
response = r.post(config.ADC_URL + '/api/upload/certificate_local?entire=enable', data = payload, files = files )

if response.status_code == requests.codes.ok:
    json_data = json.loads(response.text)
else:
    print('EXIT POINT 2 - ' + response.text)
    sys.exit('ERROR: Could not successfully push new certificate to load balancer.')


### GET CERTIFICATE GROUP DETAILS
def getcertificategroupdetails():
    response = r.get(config.ADC_URL + '/api/system_certificate_local_cert_group_child_group_member?vdom=' + config.VDOM + '&pkey=' + config.CERT_NAME )

    if response.status_code == requests.codes.ok:
        group_details = json.loads(response.text)
        group_details = group_details['payload']
    else:
        print('EXIT POINT 3 - ' + response.text)
        sys.exit('ERROR: Could not successfully get certificate group details.')
    return group_details

group_details = getcertificategroupdetails()

print(group_details)

### ADD CERTIFICATE TO GROUP

payload = { 'OCSP_stapling': '', 'default': 'disable', 'extra_local_cert': '', 'intermediate_cag': '', 'local_cert': config.CERT_NAME + '_' + VERSION }
response = r.post(config.ADC_URL + '/api/system_certificate_local_cert_group_child_group_member?vdom=' + config.VDOM + '&pkey=' + config.GROUP_NAME, json = payload)

if response.status_code == requests.codes.ok:
    pass
else:
    print('EXIT POINT 4 - ' + response.text)
    sys.exit('ERROR: Could not successfully add certificate to group.')


### MODIFY GROUP
## REVOKE THE DEFAULT FLAG
for i in group_details:
    if i['default'] == 'enable':
        if config.DEBUG == True:
            print('DEBUG: Disabling the default key(' + i['mkey'] +')')
        payload = { 'default': 'disable' }
        response = r.put(config.ADC_URL + '/api/system_certificate_local_cert_group_child_group_member?vdom=' + config.VDOM + '&pkey=' + config.GROUP_NAME + '&mkey=' + i['mkey'], json = payload)
        if response.status_code == requests.codes.ok:
            pass
        else:
            print('EXIT POINT 5 - ' + response.text)
            sys.exit('ERROR: Could not remove the default flag.')

group_details = getcertificategroupdetails()

## DEFINE THE NEW DEFAULT CERTIFICATE
for i in group_details:
    if i['local_cert'] == config.CERT_NAME + '_' + VERSION:
        if config.DEBUG == True:
            print('DEBUG: Enabling the default key(' + i['mkey'] +')')
        payload = { 'default': 'enable' }
        response = r.put(config.ADC_URL + '/api/system_certificate_local_cert_group_child_group_member?vdom=' + config.VDOM + '&pkey=' + config.GROUP_NAME + '&mkey=' + i['mkey'], json = payload)
        if response.status_code == requests.codes.ok:
            pass
        else:
            print('EXIT POINT 6 - ' + response.text)
            sys.exit('ERROR: Could not enable the default flag.')

group_details = getcertificategroupdetails()

## REMOVE THE DISABLED CERTIFICATES
for i in group_details:
    if i['default'] == 'disable':
        if config.DEBUG == True:
            print('DEBUG: Removing the disabled key(' + i['mkey'] +')')
        response = r.delete(config.ADC_URL + '/api/system_certificate_local_cert_group_child_group_member?vdom=' + config.VDOM + '&pkey=' + config.GROUP_NAME + '&mkey=' + i['mkey'])
        if response.status_code == requests.codes.ok:
            response = r.delete(config.ADC_URL + '/api/system_certificate_local?vdom=' + config.VDOM + '&mkey=' + i['local_cert'])
        else:
            print('EXIT POINT 7 - ' + response.text)
            sys.exit('ERROR: Could not remove the certificate from the group.')
