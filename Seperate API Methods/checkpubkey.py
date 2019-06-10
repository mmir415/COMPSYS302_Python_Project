import urllib.request
import json
import base64

import nacl.encoding
import nacl.signing
import nacl.utils
import time

username = "mmir415"
password = "mmir415_339816700"
key = b'00ab2fa15db1273d0859d2fed51e386dfd63f2368bff963a750544bf90b8901d'
timing = str(time.time())

signing_key = nacl.signing.SigningKey(key, encoder=nacl.encoding.HexEncoder)

    # Serialize the verify key to send it to a third party
#verify_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder)
pubkey_hex = signing_key.verify_key.encode(encoder = nacl.encoding.HexEncoder)
    
pubkey_hex_str = pubkey_hex.decode('utf-8')

message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')
signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)

signature_hex_str = signed.signature.decode('utf-8')

addkey_url = "http://cs302.kiwi.land/api/check_pubkey?pubkey="+ pubkey_hex_str

credentials = ('%s:%s' % (username, password))
b64_credentials = base64.b64encode(credentials.encode('ascii'))
headers = {
    'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
    'Content-Type' : 'application/json; charset=utf-8',
}

#Result after first time use
#{'loginserver_record': 'mmir415,(username)
#7e74f2b1978473d9943b0178f3bfe538b215f84c99bc70ccf3ca67b0e3bc13a5,(pubkey)
#1558398219.422035,(time)
#5326677c6a44df9bc95b2d62907b8bcc86b02f6c90dbbaeb4065089d66aec655f0b6e9eda3469ac09418160363cadda75c5a75577ead997b79ac6c3392722c0c',(signature)
#'username': 'mmir415',
#'connection_location': '2',
#'connection_updated_at': 1558401073.5995908,
#'connection_address': '172.23.153.89'}
#payload = {
   # "username": username,
    #"signature": signature_hex_str,
    #"pubkey": pubkey_hex_str
    
#}
#json_payload = json.dumps(payload)
#byte_payload = bytes(json_payload, "utf-8")

try:   
    req = urllib.request.Request(url=addkey_url, headers=headers)
    response = urllib.request.urlopen(req)
except urllib.error.HTTPError as err:
    print("Error: " + str(err.code))
else:
    data = response.read() # read the received bytes
    encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
    response.close()

    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)



