import urllib.request
import json
import base64

import nacl.encoding
import nacl.signing
import nacl.utils

import socket

host_name = socket.gethostname()
print(host_name, type(host_name))
ip = socket.gethostbyname(host_name)

print(ip)

addkey_url = "http://cs302.kiwi.land/api/list_users"



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

#create request and open it into a response object
req = urllib.request.Request(url=addkey_url, headers=headers)
response = urllib.request.urlopen(req)
#read and process the received bytes

data = response.read() # read the received bytes
encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
response.close()

JSON_object = json.loads(data.decode(encoding))
print(json.dumps(JSON_object,indent=4))

i=0
user = "amon838"
connection = 0
for x in JSON_object["users"]:
  # user = x["username"]
   if x["username"] == user:
      connection = x["connection_address"]
      break
print(user,connection)

active_users = []
for y in JSON_object["users"]:
   active_users.append(y["username"])

print(active_users)
private_key = nacl.signing.SigningKey.generate() #Private key
print(private_key)
private_key_hex = private_key.encode(encoder=nacl.encoding.HexEncoder)
private_key_hex_str = private_key_hex.decode('utf-8')
print(private_key_hex_str)
 
   #print(x["username"])
   #if x["username"] == "crol453":
       #i = 1
       #if i == 1:
           #print(x["connection_address"])
           #print(x["incoming_pubkey"])
