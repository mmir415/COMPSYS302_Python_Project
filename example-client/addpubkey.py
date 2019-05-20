import urllib.request
import json
import base64

import nacl.encoding
import nacl.signing
import nacl.utils

username = "mmir415"
password = "mmir415_339816700"
key = b'00ab2fa15db1273d0859d2fed51e386dfd63f2368bff963a750544bf90b8901d'

signing_key = nacl.signing.SigningKey(key, encoder=nacl.encoding.HexEncoder)

    # Serialize the verify key to send it to a third party
#verify_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder)
pubkey_hex = signing_key.verify_key.encode(encoder = nacl.encoding.HexEncoder)
    
pubkey_hex_str = pubkey_hex.decode('utf-8')

message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')
signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)

signature_hex_str = signed.signature.decode('utf-8')

addkey_url = "http://cs302.kiwi.land/api/add_pubkey"

credentials = ('%s:%s' % (username, password))
b64_credentials = base64.b64encode(credentials.encode('ascii'))
headers = {
    'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
    'Content-Type' : 'application/json; charset=utf-8',
}

payload = {
    "pubkey": pubkey_hex_str,
    "username": username,
    "signature": signature_hex_str,
}
json_payload = json.dumps(payload)
byte_payload = bytes(json_payload, "utf-8")

   
req = urllib.request.Request(url=addkey_url, data=byte_payload, headers=headers)
response = urllib.request.urlopen(req)
data = response.read() # read the received bytes
encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
response.close()

JSON_object = json.loads(data.decode(encoding))
print(JSON_object)



