import urllib.request
import json
import base64
import time
import nacl.encoding
import nacl.signing
import nacl.utils

username = "mmir415"
password = "mmir415_339816700"
key = b'00ab2fa15db1273d0859d2fed51e386dfd63f2368bff963a750544bf90b8901d'
timing = str(time.time())

signing_key = nacl.signing.SigningKey(key, encoder=nacl.encoding.HexEncoder)
verify_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder)
pubkey_hex = signing_key.verify_key.encode(encoder = nacl.encoding.HexEncoder)
    
pubkey_hex_str = pubkey_hex.decode('utf-8')
   
message_bytes = bytes(pubkey_hex_str, encoding='utf-8')
signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
signature_hex_str = signed.signature.decode('utf-8')

addkey_url = "http://172.23.88.17:1337/api/ping_check"

active_users = []
all_active_users = "none"
       # try:
       #     all_active = MainApp.listusers(username,password)
       #     for y in all_active["users"]:
       #         active_users.append(y["username"])

       #     print(active_users)

        #create HTTP BASIC authorization header
credentials = ('%s:%s' % (username, password))
b64_credentials = base64.b64encode(credentials.encode('ascii'))
headers = {
    'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
    'Content-Type' : 'application/json; charset=utf-8',
    }

payload = {
    "my_time":timing,
           # "my_active_usernames"
    "connection_address":"172.23.134.246",
    "connection_location": "1",
    }
json_payload = json.dumps(payload)
byte_payload = bytes(json_payload, "utf-8")

try:
    req = urllib.request.Request(url=addkey_url, data=byte_payload, headers=headers)
    response = urllib.request.urlopen(req)
except urllib.error.HTTPError as err:
    print("Error: " + str(err.code))
else:
    data = response.read() # read the received bytes
    encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
    response.close()
    JSON_object = json.loads(data.decode(encoding))
    print(json.dumps(JSON_object,indent=4))

    response = JSON_object.get('response')
    print("Broadcast:")
    print(response)
   



