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
server_pubkey = '11c8c33b6052ad73a7a29e832e97e31f416dedb7c6731a6f456f83a344488ec0'
target_user = "admin"

login_server_record = 'mmir415,7e74f2b1978473d9943b0178f3bfe538b215f84c99bc70ccf3ca67b0e3bc13a5,1558398219.422035,5326677c6a44df9bc95b2d62907b8bcc86b02f6c90dbbaeb4065089d66aec655f0b6e9eda3469ac09418160363cadda75c5a75577ead997b79ac6c3392722c0c'
timing = str(time.time())
ENCODING = 'utf-8'


signing_key = nacl.signing.SigningKey(key, encoder=nacl.encoding.HexEncoder)

    # Serialize the verify key to send it to a third party
#verify_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder)
pubkey_hex = signing_key.verify_key.encode(encoder = nacl.encoding.HexEncoder)
    
pubkey_hex_str = pubkey_hex.decode(ENCODING)

message = bytes("Ground Control to Major Tom",ENCODING)
server_pubkey_bytes = bytes(server_pubkey,ENCODING)

vkey = nacl.signing.VerifyKey(server_pubkey_bytes, encoder=nacl.encoding.HexEncoder)
pub_key = vkey.to_curve25519_public_key()
sealed_box = nacl.public.SealedBox(pub_key)
encrypted = sealed_box.encrypt(message, encoder=nacl.encoding.HexEncoder)
en_message = encrypted.decode('utf-8')

message_bytes = bytes(login_server_record + server_pubkey + target_user + en_message + timing, encoding=ENCODING)
signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)

signature_hex_str = signed.signature.decode(ENCODING)

addkey_url = "http://cs302.kiwi.land/api/rx_privatemessage"

credentials = ('%s:%s' % (username, password))
b64_credentials = base64.b64encode(credentials.encode('ascii'))
headers = {
    'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
    'Content-Type' : 'application/json; charset=utf-8',
}

payload = {
    "loginserver_record": login_server_record,
    "target_pubkey": server_pubkey,
    "target_username": target_user,
    "encrypted_message": en_message,
    "sender_created_at": timing,
    "signature": signature_hex_str
}
json_payload = json.dumps(payload)
byte_payload = bytes(json_payload, ENCODING)

try:   
    req = urllib.request.Request(url=addkey_url, data=byte_payload, headers=headers)
    response = urllib.request.urlopen(req)
except urllib.error.HTTPError as err:
    print("Error: " + str(err.code))
else:
    data = response.read() # read the received bytes
    encoding = response.info().get_content_charset(ENCODING) #load encoding if possible (default to utf-8)
    response.close()

    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)



