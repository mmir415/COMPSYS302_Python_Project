import urllib.request
import json
import base64

import nacl.encoding
import nacl.signing
import nacl.utils
import time
import nacl.secret
import nacl.pwhash.argon2i

username = "mmir415"
password = "mmir415_339816700"
pri_key = '00ab2fa15db1273d0859d2fed51e386dfd63f2368bff963a750544bf90b8901d'


credentials = ('%s:%s' % (username, password))
b64_credentials = base64.b64encode(credentials.encode('ascii'))
headers = {
    'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
    'Content-Type' : 'application/json; charset=utf-8',
}

password = str(3302)
byte = bytes(password, encoding = 'utf-8')
key_password = password*16
salt = bytes(key_password.encode('utf-8')[:16])
ops = nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE
mem = nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE
saltBytes = nacl.pwhash.argon2i.SALTBYTES

key = nacl.pwhash.argon2i.kdf(32,byte,salt,ops,mem)
box = nacl.secret.SecretBox(key) #safe used to encrypt/decrypt messages
private_data = {
"prikeys": ["b'00ab2fa15db1273d0859d2fed51e386dfd63f2368bff963a750544bf90b8901d"],
"blocked_pubkeys": ["...", "..."],
"blocked_usernames": ["...", "..."],
"blocked_words": ["...", "..."],
"blocked_message_signatures": ["...", "..."],
"favourite_message_signatures": ["...", "..."],
"friends_usernames": ["keva419", "mede607"]
}
json_string = json.dumps(private_data)
j_bytes= bytes(json_string, encoding = 'utf-8')

encrypted = box.encrypt(j_bytes, encoder = nacl.encoding.Base64Encoder)
private_data = encrypted.decode('utf-8')
             
login_server_record = 'mmir415,7e74f2b1978473d9943b0178f3bfe538b215f84c99bc70ccf3ca67b0e3bc13a5,1558398219.422035,5326677c6a44df9bc95b2d62907b8bcc86b02f6c90dbbaeb4065089d66aec655f0b6e9eda3469ac09418160363cadda75c5a75577ead997b79ac6c3392722c0c'
timing = str(time.time())
ENCODING = 'utf-8'


signing_key = nacl.signing.SigningKey(pri_key,encoder=nacl.encoding.HexEncoder)

    # Serialize the verify key to send it to a third party
#verify_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder)
pubkey_hex = signing_key.verify_key.encode(encoder = nacl.encoding.HexEncoder)
    
pubkey_hex_str = pubkey_hex.decode(ENCODING)



message_bytes = bytes(private_data + login_server_record + timing, encoding=ENCODING)
signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)

signature_hex_str = signed.signature.decode(ENCODING)

addkey_url = "http://cs302.kiwi.land/api/add_privatedata"

payload = {
     "loginserver_record": login_server_record,
#    "target_pubkey": server_pubkey,
#    "target_username": target_user,
#    "encrypted_message": en_message,
#    "sender_created_at": timing,
     "signature": signature_hex_str,
     "privatedata": private_data,
     #"pubkey": "............",
     "client_saved_at": timing
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



