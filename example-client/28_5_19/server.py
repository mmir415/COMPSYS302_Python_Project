import cherrypy
import urllib.request
import nacl.encoding
import nacl.signing
import nacl.utils
import base64
import time
import json
import sqlite3
import socket
#from example_client import ping

startHTML = "<html><head><title>Yacker!</title><link rel='stylesheet' href='/static/example.css' /></head><body>"
host_name = socket.gethostname()
print(host_name, type(host_name))
ip = socket.gethostbyname(host_name)
#ip = "172.23.134.246"
ip = ip + ":" + "82"
key = b'00ab2fa15db1273d0859d2fed51e386dfd63f2368bff963a750544bf90b8901d'
timing = str(time.time())


class apiList(object):
    
	#CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }      
    @cherrypy.expose              
    def rx_broadcast(self):
        received_data = json.loads(cherrypy.request.body.read().decode('utf-8'))
        print("Sender:")
        sender_logins = (received_data)["loginserver_record"]
        print (sender_logins)
        login_list = (sender_logins.split(","))
        print(login_list)
        sender_name = login_list[0]
        print(sender_name)

        message = received_data.get('message')
        print("Broadcast:")
        print(message)
        

        response = {
            'response':'ok'
        }
        response = json.dumps(response)
        return (response)

    @cherrypy.expose
    def ping_check(self):
        received_data = json.loads(cherrypy.request.body.read().decode('utf-8'))
        print("Sender:")
        sender_logins = (received_data)["connection_address"]
        print (sender_logins)       
        response = {
            'response':'ok',
            'my_time' : timing
        }
        response = json.dumps(response)
        return (response)



    @cherrypy.expose              
    def rx_privatemessage(self):
        received_data = json.loads(cherrypy.request.body.read().decode('utf-8'))
        print("Private Sender:")
        sender_logins = (received_data)["loginserver_record"]
        print (sender_logins)
        login_list = (sender_logins.split(","))
        print(login_list)
        sender_name = login_list[0]
        sender_pubkey = login_list[1]
        print(sender_name)

        en_message = received_data.get('encrypted_message').encode('utf-8')

        signing_key = nacl.signing.SigningKey(key, encoder=nacl.encoding.HexEncoder)
        #verifykey = nacl.signing.VerifyKey(sender_pubkey, encoder=nacl.encoding.HexEncoder)
        publickey = (signing_key.to_curve25519_private_key())

        sealed_box = (nacl.public.SealedBox(publickey))
        decrypted = (sealed_box.decrypt(en_message, encoder=nacl.encoding.HexEncoder))
        de_message = (decrypted.decode('utf-8'))
        #de_message = bytes(de_message,'utf-8')

        print("Private Message:")
        print(en_message)
        print(de_message)

        response = {
            'response':'ok'
        }
        response = json.dumps(response)
        #for x in  (response)["loginserver_record"]:
        
          #  try:
          #      ip_address = x.get("connection_address")
          #      print(ip_address)

        return (response)

    


   



class MainApp(object):

	#CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }       

	# If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = startHTML + "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self):
        Page = startHTML + "<h1 align = center><font color ='blue'> Welcome to Yacker!</font></h1><br/>"
        
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "Vae victus! <a href='/signout'>Sign out</a>"
            Page += '<form action="/broadcast_setup" method="post" enctype="multipart/form-data">'
            Page += 'Message: <input type="text" name="chat"/><br/>'
            #Page += 'Password: <input type="password" name="password"/>'
            Page += '<input type="submit" value="Send Broadcast"/></form>'
        except KeyError: #There is no username
            
            Page += '<div class = "w3-container w3-red"><p align = center>Click here to <a href ="login">login</a></p></div>.'
        return Page
        
    @cherrypy.expose
    def login(self, bad_attempt = 0):
        Page = startHTML 
        if bad_attempt != 0:
            Page += "<font color='red'>Invalid username/password!</font>"
            
        Page += '<form action="/signin" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br/>'
        Page += 'Password: <input type="password" name="password"/>'
        Page += '<input type="submit" value="Login"/></form>'
        return Page
    
    @cherrypy.expose    
    def sum(self, a=0, b=0): #All inputs are strings by default
        output = int(a)+int(b)
        return str(output)
        
    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = MainApp.ping(self,username, password)
        
        if (error == 0):
        # & (checked == 0)):
            cherrypy.session['username'] = username
            cherrypy.session['password'] = password
            MainApp.report(self,username,password)

           
            conn1 = sqlite3.connect("Users.db")
            c = conn1.cursor()
            # my_Key = b'00ab2fa15db1273d0859d2fed51e386dfd63f2368bff963a750544bf90b8901d'

            # c.execute("""UPDATE Users
            #  SET privatekey = '00ab2fa15db1273d0859d2fed51e386dfd63f2368bff963a750544bf90b8901d'
            #    WHERE username = 'mmir415'""")
            
            for x in  (MainApp.listusers(self,username,password))["users"]:
                #Now we do databases
                userlist = [x["connection_location"],x["connection_updated_at"],x[ "incoming_pubkey"],x[ "username"],x[ "connection_address"],x["status"]]
                try:
                     c.execute('''INSERT INTO Users(lastLocation,lastseenTime,publickey,username,ip,status)
                VALUES(?,?,?,?,?,?)''',userlist)
                except sqlite3.IntegrityError:
                    pass
                

                try:
                    
                    ip_address = x.get("connection_address")
                    print(ip_address)
                    MainApp.ping_check(self,username,password,ip_address)
                except:
                    pass
            #MainApp.listusers(self,username,password)
            conn1.commit()
            conn1.close() 
            try:
                print("Sup")
                #MainApp.private_message(self,username,password)
            except:
                print("Offline")
                pass
            
                
            MainApp.receive_message(self)
            
            
        #    pubkeyAutho()
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if username is None:
            pass
        else:
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')
    @cherrypy.expose
    def report(self,username,password):

    # Serialize the verify key to send it to a third party
            signing_key = nacl.signing.SigningKey(key, encoder=nacl.encoding.HexEncoder)
            verify_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder)
            pubkey_hex = signing_key.verify_key.encode(encoder = nacl.encoding.HexEncoder)
            credentials = ('%s:%s' % (username, password))
            b64_credentials = base64.b64encode(credentials.encode('ascii'))
            headers = {
                'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
                'Content-Type' : 'application/json; charset=utf-8',
            }
            pubkey_hex_str = pubkey_hex.decode('utf-8')

            message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')
            signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)

            signature_hex_str = signed.signature.decode('utf-8')

            addkey_url = "http://cs302.kiwi.land/api/report"

            payload = {
                "connection_location": "2",
                "connection_address":ip,
                "incoming_pubkey": pubkey_hex_str
        
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
                print(JSON_object)

    @cherrypy.expose
    def ping(self,username,password):

     # Serialize the verify key to send it to a third party
        signing_key = nacl.signing.SigningKey(key, encoder=nacl.encoding.HexEncoder)
        verify_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder)
        pubkey_hex = signing_key.verify_key.encode(encoder = nacl.encoding.HexEncoder)
    
        pubkey_hex_str = pubkey_hex.decode('utf-8')
   
        message_bytes = bytes(pubkey_hex_str, encoding='utf-8')
        signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)

        signature_hex_str = signed.signature.decode('utf-8')

        addkey_url = "http://cs302.kiwi.land/api/ping"

        #create HTTP BASIC authorization header
        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type' : 'application/json; charset=utf-8',
        }

        payload = {
            "pubkey": pubkey_hex_str,
            #"username": username,
            "signature": signature_hex_str,
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
            if (JSON_object["authentication"] == "error"):
                return 1
            else:
                print(json.dumps(JSON_object,indent=4))
                return 0

    @cherrypy.expose
    def listusers(self,username,password):
        
        addkey_url = "http://cs302.kiwi.land/api/list_users"
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
        return (JSON_object)


        #for x in JSON_object["users"]:
        #    print(x["username"])

    @cherrypy.expose
    def ping_check(self,username,password,ip_address):
        # Serialize the verify key to send it to a third party
        signing_key = nacl.signing.SigningKey(key, encoder=nacl.encoding.HexEncoder)
        verify_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder)
        pubkey_hex = signing_key.verify_key.encode(encoder = nacl.encoding.HexEncoder)
    
        pubkey_hex_str = pubkey_hex.decode('utf-8')
   
        message_bytes = bytes(pubkey_hex_str, encoding='utf-8')
        signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)

        signature_hex_str = signed.signature.decode('utf-8')

        addkey_url = "http://"+ip_address+"/api/ping_check"

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
            


    @cherrypy.expose    
    def get_privatedata(self,username,password):

        addkey_url = "http://cs302.kiwi.land/api/get_privatedata"
        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type' : 'application/json; charset=utf-8',
        }
    
    #create request and open it into a response object

    #read and process the received bytes

    #create request and open it into a response object
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
            if JSON_object["privatedata"] == "7e74f2b1978473d9943b0178f3bfe538b215f84c99bc70ccf3ca67b0e3bc13a5":
                print(json.dumps(JSON_object,indent=4))
                return JSON_object["privatedata"]

            else:
                return 1

    @cherrypy.expose
    def broadcast_setup(self,chat):
        Page = startHTML
        cherrypy.session['chat'] = chat
        username = cherrypy.session['username']
        password = cherrypy.session['password']
        for x in  (MainApp.listusers(self,username,password))["users"]:
            try:
                ip_address = x.get("connection_address")
            #ip_address = "172.23.94.203:1234"
            #ip_address = "127.0.0.1:2243"
                print(ip_address)
                MainApp.broadcast(self,username,ip_address,password,chat)

            except:
                pass
        
        Page += "Successfully broadcasted, " + cherrypy.session['username'] + "!<br/>"
        raise cherrypy.HTTPRedirect('/signout')
        #Page += "Vae victus! <a href='/signout'>Sign out</a>"
     
        

    @cherrypy.expose
    def broadcast(self,username,ip_address,password,chat):
        timing = str(time.time())
        ENCODING = 'utf-8'
        # cherrypy.session['chat'] = chat
        # username = cherrypy.session['username']
        # password = cherrypy.session['password']

        login_server_record = 'mmir415,7e74f2b1978473d9943b0178f3bfe538b215f84c99bc70ccf3ca67b0e3bc13a5,1558398219.422035,5326677c6a44df9bc95b2d62907b8bcc86b02f6c90dbbaeb4065089d66aec655f0b6e9eda3469ac09418160363cadda75c5a75577ead997b79ac6c3392722c0c'
        signing_key = nacl.signing.SigningKey(key, encoder=nacl.encoding.HexEncoder)

        # Serialize the verify key to send it to a third party
    #verify_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder)
        pubkey_hex = signing_key.verify_key.encode(encoder = nacl.encoding.HexEncoder)
        
        pubkey_hex_str = pubkey_hex.decode(ENCODING)

        message = chat

        message_bytes = bytes(login_server_record + message + timing, encoding=ENCODING)
        signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)

        signature_hex_str = signed.signature.decode(ENCODING)

        addkey_url = "http://"+ip_address+"/api/rx_broadcast"
        #addkey_url = "http://172.23.75.25/api/rx_broadcast"

        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type' : 'application/json; charset=utf-8',
        }

        payload = {
            "loginserver_record": login_server_record,
            "message": message,
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

            # received_data = json.loads(cherrypy.request.body.read().decode('utf-8'))
            response = JSON_object.get('response')
            print("Broadcast:")
            print(response)

            # response = {
            # 'response : ok'
            # }

            # response = json.dumps(response)
            # print(response)
    def private_message(self,username,password):
        #DMing Tomas
        #server_pubkey = '67e5107702196a80bff43b46c25531bc7f0cbbb44db5d24bd89077387abc73b6'
       # target_user = "tant836"
       # target_ip = "172.24.5.136:1234"

       #DMing Myself
        server_pubkey = "7e74f2b1978473d9943b0178f3bfe538b215f84c99bc70ccf3ca67b0e3bc13a5"
        target_user = "mmir415"
        target_ip = "172.23.134.246:80"

        login_server_record = 'mmir415,7e74f2b1978473d9943b0178f3bfe538b215f84c99bc70ccf3ca67b0e3bc13a5,1558398219.422035,5326677c6a44df9bc95b2d62907b8bcc86b02f6c90dbbaeb4065089d66aec655f0b6e9eda3469ac09418160363cadda75c5a75577ead997b79ac6c3392722c0c'
        timing = str(time.time())
        ENCODING = 'utf-8'


        signing_key = nacl.signing.SigningKey(key, encoder=nacl.encoding.HexEncoder)

            # Serialize the verify key to send it to a third party
        #verify_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder)
        pubkey_hex = signing_key.verify_key.encode(encoder = nacl.encoding.HexEncoder)
            
        pubkey_hex_str = pubkey_hex.decode(ENCODING)

        message = bytes("What pie would you like?",ENCODING)
        #message = bytes((chr(128184)),ENCODING)

        server_pubkey_bytes = bytes(server_pubkey,ENCODING)

        vkey = nacl.signing.VerifyKey(server_pubkey_bytes, encoder=nacl.encoding.HexEncoder)
        pub_key = vkey.to_curve25519_public_key()
        sealed_box = nacl.public.SealedBox(pub_key)
        encrypted = sealed_box.encrypt(message, encoder=nacl.encoding.HexEncoder)
        en_message = encrypted.decode('utf-8')

        message_bytes = bytes(login_server_record + server_pubkey + target_user + en_message + timing, encoding=ENCODING)
        signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)

        signature_hex_str = signed.signature.decode(ENCODING)

        addkey_url = "http://"+target_ip+"/api/rx_privatemessage"

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




    @cherrypy.expose
    def receive_message(self):
        print("Sending message")


    
# def authoriseUserLogin(username, password):
#     print("Log on attempt from {0}:{1}".format(username, password))
#     #ping(username,password)
#     pubhexstr = (MainApp.get_privatedata(username = username,password = password))
#     # report(username,password)
#     return (MainApp.ping(username,password))



###
### Functions only after here
###
def pubkeyAutho():
    signing_key = nacl.signing.SigningKey.generate()

    username = cherrypy.session['username']
    password = cherrypy.session['password']

    # Serialize the verify key to send it to a third party
    verify_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex = signing_key.verify_key_hex.encode(encoder = nac1.encoding.HexEncoder)
    
    pubkey_hex_str = pubkey_hex.decode('utf-8')

    message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')
    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)

    signature_hex_str = signed.signature.decode('utf-8')

    addkey_url = "http://cs302.kiwi.land/api/add_pubkey?pubkey="+pubkey_hex_str

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



   # try:
   #     req = urllib.request.Request(addkey_url, data=byte_payload, headers=headers)
   #    response = urllib.request.urlopen(req)
   #     data = response.read() # read the received bytes
   #     encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
   #     response.close()

   # except urllib.error.HTTPError as error:
    
   #     print(error.read())
   #     exit()

   # JSON_object = json.loads(data.decode(encoding))
   # if (JSON_object["response"] == "ok"):
   #     print("PUBKEY SUCC")
   #     cherrypy.session['signing_key'] = signing_key
   #     return 0
   # else:
   #     print ("Fail")
   #     return 1pubk
# @cherrypy.expose
# def listusers(username,password):
    
#     addkey_url = "http://cs302.kiwi.land/api/list_users"
#     credentials = ('%s:%s' % (username, password))
#     b64_credentials = base64.b64encode(credentials.encode('ascii'))
#     headers = {
#         'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
#         'Content-Type' : 'application/json; charset=utf-8',
#     }

#     #create request and open it into a response object
#     req = urllib.request.Request(url=addkey_url, headers=headers)
#     response = urllib.request.urlopen(req)
#     #read and process the received bytes

#     data = response.read() # read the received bytes
#     encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
#     response.close()

#     JSON_object = json.loads(data.decode(encoding))
#     print(json.dumps(JSON_object,indent=4))


# @cherrypy.expose    
# def get_privatedata(username,password):

#     addkey_url = "http://cs302.kiwi.land/api/get_privatedata"
#     credentials = ('%s:%s' % (username, password))
#     b64_credentials = base64.b64encode(credentials.encode('ascii'))
#     headers = {
#         'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
#         'Content-Type' : 'application/json; charset=utf-8',
#     }
 
# #create request and open it into a response object

# #read and process the received bytes

# #create request and open it into a response object
#     try:
#         req = urllib.request.Request(url=addkey_url, headers=headers)
#         response = urllib.request.urlopen(req)

#     except urllib.error.HTTPError as err:
#         print("Error: " + str(err.code))
#     else:
#         data = response.read() # read the received bytes
#         encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
#         response.close()

#         JSON_object = json.loads(data.decode(encoding))
#         if JSON_object["privatedata"] == "7e74f2b1978473d9943b0178f3bfe538b215f84c99bc70ccf3ca67b0e3bc13a5":
#             print(json.dumps(JSON_object,indent=4))
#             return JSON_object["privatedata"]

#         else:
#             return 1

# @cherrypy.expose
# def broadcast(username,password):
#     timing = str(time.time())
#     ENCODING = 'utf-8'

#     login_server_record = 'mmir415,7e74f2b1978473d9943b0178f3bfe538b215f84c99bc70ccf3ca67b0e3bc13a5,1558398219.422035,5326677c6a44df9bc95b2d62907b8bcc86b02f6c90dbbaeb4065089d66aec655f0b6e9eda3469ac09418160363cadda75c5a75577ead997b79ac6c3392722c0c'
#     signing_key = nacl.signing.SigningKey(key, encoder=nacl.encoding.HexEncoder)

#     # Serialize the verify key to send it to a third party
# #verify_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder)
#     pubkey_hex = signing_key.verify_key.encode(encoder = nacl.encoding.HexEncoder)
    
#     pubkey_hex_str = pubkey_hex.decode(ENCODING)

#     message = "Hello there"

#     message_bytes = bytes(login_server_record + message + timing, encoding=ENCODING)
#     signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)

#     signature_hex_str = signed.signature.decode(ENCODING)

#     addkey_url = "http://172.23.155.225:80/api/rx_broadcast"

#     credentials = ('%s:%s' % (username, password))
#     b64_credentials = base64.b64encode(credentials.encode('ascii'))
#     headers = {
#         'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
#         'Content-Type' : 'application/json; charset=utf-8',
#     }

#     payload = {
#         "loginserver_record": login_server_record,
#         "message": message,
#         "sender_created_at": timing,
#         "signature": signature_hex_str
#     }
#     json_payload = json.dumps(payload)
#     byte_payload = bytes(json_payload, ENCODING)

#     try:   
#         req = urllib.request.Request(url=addkey_url, data=byte_payload, headers=headers)
#         response = urllib.request.urlopen(req)
#     except urllib.error.HTTPError as err:
#         print("Error: " + str(err.code))
#     else:
#         data = response.read() # read the received bytes
#         encoding = response.info().get_content_charset(ENCODING) #load encoding if possible (default to utf-8)
#         response.close()

#         JSON_object = json.loads(data.decode(encoding))
#         print(JSON_object)

#         # received_data = json.loads(cherrypy.request.body.read().decode('utf-8'))
#         response = JSON_object.get('response')
#         print("Broadcast:")
#         print(response)

#         # response = {
#         # 'response : ok'
#         # }

#         # response = json.dumps(response)
#         # print(response)

# @cherrypy.expose
# def receive_message(self):
#     print("receiving message")


# @cherrypy.expose
# def report(username,password):

#     # Serialize the verify key to send it to a third party
#     signing_key = nacl.signing.SigningKey(key, encoder=nacl.encoding.HexEncoder)
#     verify_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder)
#     pubkey_hex = signing_key.verify_key.encode(encoder = nacl.encoding.HexEncoder)
#     credentials = ('%s:%s' % (username, password))
#     b64_credentials = base64.b64encode(credentials.encode('ascii'))
#     headers = {
#         'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
#         'Content-Type' : 'application/json; charset=utf-8',
#     }
#     pubkey_hex_str = pubkey_hex.decode('utf-8')

#     message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')
#     signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)

#     signature_hex_str = signed.signature.decode('utf-8')

#     addkey_url = "http://cs302.kiwi.land/api/report"

#     payload = {
#         "connection_location": "2",
#         "connection_address": "172.23.155.225",
#         "incoming_pubkey": pubkey_hex_str
    
#     }
#     json_payload = json.dumps(payload)
#     byte_payload = bytes(json_payload, "utf-8")

#     try:   
#         req = urllib.request.Request(url=addkey_url, data=byte_payload, headers=headers)
#         response = urllib.request.urlopen(req)
#     except urllib.error.HTTPError as err:
#         print("Error: " + str(err.code))
#     else:
#         data = response.read() # read the received bytes
#         encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
#         response.close()

#         JSON_object = json.loads(data.decode(encoding))
#         print(JSON_object)





    
   # if ((username.lower() == "user") and (password.lower() == "password") or (username.lower() == "mmir415") and (password.lower() == "mmir415_339816700") ):
  
     #   print("Success")
    #return 0
   # else:
   #     print("Failure")
   #     return 1
