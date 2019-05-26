import urllib.request
import json
import base64

import nacl.encoding
import nacl.signing
import nacl.utils

addkey_url = "http://cs302.kiwi.land/api/get_privatedata"



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
#{'loginserver_record': 'mmir415,(username)
#7e74f2b1978473d9943b0178f3bfe538b215f84c99bc70ccf3ca67b0e3bc13a5,(pubkey)
#1558398219.422035,(time)
#5326677c6a44df9bc95b2d62907b8bcc86b02f6c90dbbaeb4065089d66aec655f0b6e9eda3469ac09418160363cadda75c5a75577ead997b79ac6c3392722c0c'} (signature)
#The public key provided in the message should be derived from the private key used to sign the message (i.e. what is used to create X-signature HTTP header) 
 

#create request and open it into a response object
req = urllib.request.Request(url=addkey_url, headers=headers)
response = urllib.request.urlopen(req)
#read and process the received bytes

data = response.read() # read the received bytes
encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
response.close()

JSON_object = json.loads(data.decode(encoding))
print(json.dumps(JSON_object,indent=4))
