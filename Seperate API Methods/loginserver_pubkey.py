import urllib.request
import json
import base64

import nacl.encoding
import nacl.signing
import nacl.utils

addkey_url = "http://cs302.kiwi.land/api/loginserver_pubkey"



#Header
username = "mmir415"
password = "mmir415_339816700"
key = b'00ab2fa15db1273d0859d2fed51e386dfd63f2368bff963a750544bf90b8901d'
credentials = ('%s:%s' % (username, password))
b64_credentials = base64.b64encode(credentials.encode('ascii'))
headers = {
    'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
    'Content-Type' : 'application/json; charset=utf-8',
}

#Results after first usage
#{'pubkey': '11c8c33b6052ad73a7a29e832e97e31f416dedb7c6731a6f456f83a344488ec0', 'server_name': 'cs302.kiwi.land', 'server_time': 1558429626.8335345}

#Results after second usage
#{'pubkey': '11c8c33b6052ad73a7a29e832e97e31f416dedb7c6731a6f456f83a344488ec0', 'server_name': 'cs302.kiwi.land', 'server_time': 1558429711.8686638}
#clearly the public key is the same, so is the server name, but the server time is the same

#create request and open it into a response object
req = urllib.request.Request(url=addkey_url, headers=headers)
response = urllib.request.urlopen(req)
#read and process the received bytes

data = response.read() # read the received bytes
encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
response.close()

JSON_object = json.loads(data.decode(encoding))
print(JSON_object)
