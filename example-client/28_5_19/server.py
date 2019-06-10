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
import threading
from jinja2 import Environment,FileSystemLoader
import nacl.secret
import nacl.pwhash.argon2i
import binascii
#from example_client import ping

startHTML = "<html><head><title>Yakker!</title><link rel='stylesheet' href='/static/example.css' /></head><body>"
viro = Environment(loader=FileSystemLoader(searchpath = "html_files"))
host_name = socket.gethostname()
print(host_name, type(host_name))
#ip = socket.gethostbyname(host_name)
#ip = "192.168.1.15"
s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
try:
    s.connect(('1.1.1.1',1))
    IP = s.getsockname()[0]
except:
    IP = "172.23.134.246"
finally:
    s.close()

#ip = socket.gethostbyname(host_name)
ip = IP
#ip = "172.23.134.246"
ip = ip + ":" + "10010"
key = b'00ab2fa15db1273d0859d2fed51e386dfd63f2368bff963a750544bf90b8901d'
timing = str(time.time())




class apiList(object):
    username = None
    hex_priv_key = None
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
        sender_pubkey = login_list[1]
        server_time = login_list[2]
        sender_signature = received_data["signature"]
        print(sender_name)
        sender_created_at = received_data["sender_created_at"]

        message = received_data.get('message').encode('utf-8')

        sender_list = [sender_name,message,sender_pubkey,server_time,sender_signature,sender_created_at]
        conn5 = sqlite3.connect("Users.db")
        c = conn5.cursor()
        
        try:
            c.execute('''INSERT INTO Broadcasts(username,message,sender_public_key,server_time,signature,sender_created_at)
                VALUES(?,?,?,?,?,?)''',sender_list)
        except sqlite3.IntegrityError:
            pass
        print("Broadcast:")
        print(message)
        conn5.commit()
        conn5.close()

        

        response = {
            'response':'ok'
        }
        response = json.dumps(response)
        return (response)

    # @cherrypy.expose
    # def ping_check(self):
    #     received_data = json.loads(cherrypy.request.body.read().decode('utf-8'))
    #     print("Sender:")
    #     sender_logins = (received_data)["connection_address"]
    #     print (sender_logins)       
    #     response = {
    #         'response':'ok',
    #         'my_time' : timing
    #     }
    #     response = json.dumps(response)
    #     return (response)



    @cherrypy.expose              
    def rx_privatemessage(self):
        received_data = json.loads(cherrypy.request.body.read().decode('utf-8'))

        #Everything between here and en_message is to display who it is, and needs clean up
        print("Private Sender:")
        

        en_message = received_data.get('encrypted_message').encode('utf-8')
        current_user = str(apiList.username)
        print(current_user)

        # current_user = cherrypy.session['username']
        # conn4 = sqlite3.connect("Users.db")
        # c = conn4.cursor()
        

        #priv_hex_key = cherrypy.session['hex_priv_key']
        
        # print(cherrypy.session['username'])
        # print(cherrypy.session['hex_priv_key'])
        # c.execute("""SELECT privatekey FROM Users WHERE username =?""",(current_user,))
        # for row in c.fetchall():
        #     priv_hex_key = (row[0])
        #     priv_hex_key = bytes(priv_hex_key,'utf-8')

        # conn4.commit()
        # conn4.close()
        
        
        signing_key = nacl.signing.SigningKey(apiList.hex_priv_key, encoder=nacl.encoding.HexEncoder)
        #verifykey = nacl.signing.VerifyKey(sender_pubkey, encoder=nacl.encoding.HexEncoder)
        publickey = (signing_key.to_curve25519_private_key())

        sealed_box = (nacl.public.SealedBox(publickey))
        decrypted = (sealed_box.decrypt(en_message, encoder=nacl.encoding.HexEncoder))
        de_message = (decrypted.decode('utf-8'))
        #de_message = bytes(de_message,'utf-8')
        sender_logins = (received_data)["loginserver_record"]
        print (sender_logins)
        login_list = (sender_logins.split(","))
        print(login_list)
        sender_name = login_list[0]
        sender_pubkey = login_list[1]
        sender_pubkey = login_list[1]
        server_time = login_list[2]
        sender_signature = received_data["signature"]
        print(sender_name)
        sender_created_at = received_data["sender_created_at"]
        print(sender_name)


        sender_list = [sender_name,de_message,sender_pubkey,server_time,sender_signature,sender_created_at]
        conn5 = sqlite3.connect("Users.db")
        c = conn5.cursor()
        
        try:
            c.execute('''INSERT INTO 'Private Messages' (username,message,sender_public_key,server_time,signature,sender_created_at)
                VALUES(?,?,?,?,?,?)''',sender_list)
        except sqlite3.IntegrityError:
            pass
        conn5.commit()
        conn5.close()

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
    username = None
    password = None

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
        
        Page = viro.get_template("index.html")
        return Page.render(session=cherrypy.session)
        # Page = startHTML + "<h1 align = center><font color ='blue'> Welcome to Yakker!</font></h1><br/>"
        
        # try:
        #     Page += "Hello " + cherrypy.session['username'] + "!<br/>"
        #     Page += "Vae victus! <a href='/signout'>Sign out</a>"
        #     Page += '<form action="/broadcast_setup" method="post" enctype="multipart/form-data">'
        #     Page += 'Message: <input type="text" name="chat"/><br/>'
        #     #Page += 'Password: <input type="password" name="password"/>'
        #     Page += '<input type="submit" value="Send Broadcast"/></form><br/>'

        #     Page += '<form action="/message_setup" method="post" enctype="multipart/form-data">'
        #     Page += 'Username: <input type="text" name="target_username"/><br/>'
        #     Page += 'Message: <input type="text" name="secret_message"/>'
        #     Page += '<input type="submit" value="Send Message"/></form><br/>'
            
        # except KeyError: #There is no username
        #     Page += '<img itemprop="contentURL" src="http://www.uidownload.com/files/765/758/365/speech-bubble-icon-free-vector.jpg" alt="Speech Bubble Icon Free Vector screenshot" width="160" height="200" class="center"><br/>'
        #     Page += '<div class = "w3-container w3-red"><p align = center><font color ="white">Click here to <a href ="login">login</a></font></p></div>.'
        # else:
        #     tmpl viro.get_template('index.html')
        #     return tmpl.render(username=username)
        # return Page
        
    @cherrypy.expose
    def login(self, bad_attempt = 0):
        #Do the below when you're better at jinja
        # if bad_attempt != 0:
        #     Page = viro.get_template("index.html")
        #     Page += "<font color='red'>Invalid username/password!</font>"
        # else:
        #     Page = viro.get_template("login.html")
        #     return Page.render(session=cherrypy.session)

        Page = startHTML 
        if bad_attempt != 0:
            Page += "<font color='red'>Invalid username/password/encrypted password!</font>"
            
        Page += '<form action="/signin" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br/>'
        Page += 'Password: <input type="password" name="password"/><br/>'
        Page += '<input type="submit" value="Login"/></form>'
        return Page
    
    @cherrypy.expose
    def broadcasts(self):
        broadcasts = self.broadcast_log()
        Page = viro.get_template("broadcasts.html")
        return Page.render(broadcasts = broadcasts )
    
    @cherrypy.expose
    def messages(self):
        messages = self.private_log()
        Page = viro.get_template("messages.html")
        return Page.render(messages = messages)

    @cherrypy.expose    
    def sum(self, a=0, b=0): #All inputs are strings by default
        output = int(a)+int(b)
        return str(output)

    @cherrypy.expose
    def messaging(self):
        users = self.users_log()
        Page = viro.get_template("login.html")
        return Page.render(session=cherrypy.session,users = users)

    # @cherrypy.expose
    # def message_successful(self):
    #     Page = viro.get_template("login.html")
    #     return Page.render(session=cherrypy.session)


        
    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        checking_user = username
        checking_password = password
        conn1 = sqlite3.connect("Users.db")
        c = conn1.cursor()
        current_user = username
        api_key = load_new_api_key(self,checking_user,checking_password)
        print(api_key)
        if api_key == 1:
        
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')
        else:
            api_key_header =API_header(api_key,username)
            print(api_key_header)
            private_key = nacl.signing.SigningKey.generate() #Private key
            # c.execute("""UPDATE Users SET
            #     privatekey =? 
            #     WHERE username =? AND privatekey IS NULL""",(str(private_key),str(current_user)))
                
            # c.execute("""SELECT privatekey FROM Users WHERE username =?""",(current_user,))
            # hex_priv_key = "none"
            # for row in c.fetchall():
            #     hex_priv_key = (row[0])
            hex_priv_key = MainApp.get_privatedata(self,username,password)
            if hex_priv_key == 1:
                raise cherrypy.HTTPRedirect('/login?bad_attempt=1')
            else:
                cherrypy.session['hex_priv_key'] = hex_priv_key
              
                print(hex_priv_key)
                print("CHECK RIGHT HERE")
                print(hex_priv_key)
                error = MainApp.ping(self,username, password,hex_priv_key,api_key_header)
            #hex_priv_key = bytes(hex_priv_key,'utf-8')
            #error = MainApp.ping(self,username, password,hex_priv_key)
            
                if (error == 0):
            # & (checked == 0)):
                    cherrypy.session['username'] = username
                    cherrypy.session['password'] = password
                    cherrypy.session['hex_priv_key'] = hex_priv_key
                    apiList.username = username
                    apiList.hex_priv_key = hex_priv_key
                    MainApp.username = username
                    MainApp.password = password

                    br = cherrypy.process.plugins.BackgroundTask(60,lambda: MainApp.report(self,username,password,hex_priv_key))

                    br.start()

                    bl = cherrypy.process.plugins.BackgroundTask(30,lambda : MainApp.listusers(self,username,password))
                    bl.start()
                    

                    print("Users log below")
                    print(MainApp.users_log(self))
                    print("Users log finished")
                    

                    
                    for x in  (MainApp.listusers(self,username,password))["users"]:
                        #Now we do databases
                        ip_addresses = x["connection_address"]
                        try:
                            wb = cherrypy.process.plugins.BackgroundTask(200,lambda: MainApp.ping_check(self,username,password,ip_addresses,hex_priv_key))
                            wb.start()
                        except:
                            print("Couldn't connect")
                            pass
                        userlist = [x["connection_location"],x["connection_updated_at"],x[ "incoming_pubkey"],x[ "username"],x[ "connection_address"],x["status"]]
                        try:
                            c.execute('''INSERT INTO Users(lastLocation,lastseenTime,publickey,username,ip,status)
                        VALUES(?,?,?,?,?,?)''',userlist)
                        except sqlite3.IntegrityError:
                            pass

                        #print(hex_priv_key)
                            
                        
                        # wb.run()
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
                    raise cherrypy.HTTPRedirect('/messaging')
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
    def report(self,username,password,hex_priv_key):

    # Serialize the verify key to send it to a third party
            signing_key = nacl.signing.SigningKey(hex_priv_key, encoder=nacl.encoding.HexEncoder)
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
    def ping(self,username,password,hex_priv_key,api_key_header):

     # Serialize the verify key to send it to a third party
        hex_priv_key = str(hex_priv_key)
        hex_priv_key = bytes(hex_priv_key,'utf-8')
        print(hex_priv_key)
        signing_key = nacl.signing.SigningKey(hex_priv_key, encoder=nacl.encoding.HexEncoder)
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
        headers = api_key_header

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

        #print(json.dumps(JSON_object,indent=4))
        return (JSON_object)


        #for x in JSON_object["users"]:
        #    print(x["username"])

    @cherrypy.expose
    def ping_check(self,username,password,ip_address,hex_priv_key):
        # Serialize the verify key to send it to a third party
        signing_key = nacl.signing.SigningKey(hex_priv_key, encoder=nacl.encoding.HexEncoder)
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

        # username = "keva419"
        # password = "KimberleyEvans-Parker_576292546"


        
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
        

        #encrypted_data = "MJV2FB1Lic7tPoeIzoW+5G9r3hPH9wemE408eMY50dG2Kiu/N3DkcRhpNEyI78tRLOJqMVKbgpo7Y58QsLNlkgm42zph1BzQpcUchvVmaTinUTJ6XgFlEJHnDerWF7ygP7VxZtCS95KKmILRnfBx+OQxcCzwoG5xnDFq"

        #plaintext = box.decrypt(encrypted_data,encoder = nacl.encoding.Base64Encoder)

        #data = plaintext.decode('utf-8')
        #print(data)

        #create request and open it into a response object
        req = urllib.request.Request(url=addkey_url, headers=headers)
        response = urllib.request.urlopen(req)
        #read and process the received bytes

        data_in = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()

        JSON_object = json.loads(data_in.decode(encoding))
        print(json.dumps(JSON_object,indent=4))

        password = str(3302)
        byte = bytes(password, encoding = 'utf-8')
        key_password = password*16
        salt = bytes(key_password.encode('utf-8')[:16])
        ops = nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE
        mem = nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE
        saltBytes = nacl.pwhash.argon2i.SALTBYTES

        key = nacl.pwhash.argon2i.kdf(32,byte,salt,ops,mem)
        box = nacl.secret.SecretBox(key) #safe used to encrypt/decrypt messages

        encrypted_data = str((JSON_object["privatedata"]))

        try:
            plaintext = box.decrypt(encrypted_data,encoder = nacl.encoding.Base64Encoder)
        except:
            return 1
        else:

            data = plaintext.decode('utf-8')
            print(data)
            data = json.loads(data.encode(encoding))
            print(data)
            print(type(data))
            private_keys = (data["prikeys"])
            private_key = private_keys[0]
            print(private_key)
            return (private_key)
        # @cherrypy.expose
        # def threads(self):
        #     user_list = MainApp.listusers(self,cherrypy.session['username'],cherrypy.session['password'])

        #     for user in user_list:
        #             ip_address = user_list["connection_address"]
        #             thread = threading.Thread(target=broadcast,args=(cherrypy.session['username'],ip_address,cherrypy.session['password'],cherrypy.session['chat'],cherrypy.session['hex_private_key']))
        #             print(ip_address)
        #             thread.start()
                    #MainApp.broadcast(self,username,ip_address,password,chat,hex_private_key)
            
    @cherrypy.expose
    def getloginserver_record(self, username,password):
        addkey_url = "http://cs302.kiwi.land/api/get_loginserver_record"



        #Header
        # username = "keva419"
        # password = "KimberleyEvans-Parker_576292546"
        #key = b'00ab2fa15db1273d0859d2fed51e386dfd63f2368bff963a750544bf90b8901d'
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
        server_record = (json.dumps(JSON_object,indent=4))
        print(server_record)
        for key in sorted(JSON_object.values()):
            login_server = key
            print (key)
            break
   
        print("sup")
        print(login_server)
        return login_server

    @cherrypy.expose
    def broadcast_setup(self,chat):
        Page = startHTML
        cherrypy.session['chat'] = chat
        username = cherrypy.session['username']
        password = cherrypy.session['password']
        active_user = username
        hex_private_key = cherrypy.session['hex_priv_key']
        # conn2 = sqlite3.connect("Users.db")
        # c = conn2.cursor()
        # c.execute("""SELECT privatekey FROM Users WHERE username =?""",(active_user,))
        # for row in c.fetchall():
        #     hex_private_key = (row[0])
        #     conn2.commit()
        #     conn2.close() 
        hex_private_key = bytes(hex_private_key,'utf-8')
        print("YO")
        print(hex_private_key)
        for x in  (MainApp.listusers(self,username,password))["users"]:

            try:
                ip_address = x["connection_address"]
                thread = threading.Thread(target=MainApp.broadcast,args=(self,username,ip_address,password,chat, hex_private_key))
                print(ip_address)
                thread.start()
            except:
                pass
        #for x in  (MainApp.listusers(self,username,password))["users"]:
            # try:
            #     ip_address = x.get("connection_address")
            #     print(ip_address)
            #     MainApp.broadcast(self,username,ip_address,password,chat,hex_private_key)
            # except:
            #     pass
           
        
        Page += "Successfully broadcasted, " + cherrypy.session['username'] + "!<br/>"
        raise cherrypy.HTTPRedirect('/messaging')
        #Page += "Vae victus! <a href='/signout'>Sign out</a>"
     
        

    @cherrypy.expose
    def broadcast(self,username,ip_address,password,chat,hex_private_key):
        timing = str(time.time())
        ENCODING = 'utf-8'
        # cherrypy.session['chat'] = chat
        # username = cherrypy.session['username']
        # password = cherrypy.session['password']

        login_server_record = self.getloginserver_record(username,password)
        signing_key = nacl.signing.SigningKey(hex_private_key, encoder=nacl.encoding.HexEncoder)

        # Serialize the verify key to send it to a third party
    #verify_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder)
        pubkey_hex = signing_key.verify_key.encode(encoder = nacl.encoding.HexEncoder)
        
        pubkey_hex_str = pubkey_hex.decode(ENCODING)

        message = chat
        if message == "":
        
            return json.dumps({"response":"empty_message"})

        message_bytes = bytes(login_server_record + message + timing, encoding=ENCODING)
        signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)

        signature_hex_str = signed.signature.decode(ENCODING)

        addkey_url = "http://"+ip_address+"/api/rx_broadcast"
        #addkey_url = "http://172.23.74.180:124/api/rx_broadcast"
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
    @cherrypy.expose
    def message_setup(self,target_username,secret_message):
        print("THIS IS RIGHT AT THE START OF THE SETUP")
        Page = startHTML
        if target_username != "" and secret_message != "":
            cherrypy.session['target_username'] = target_username
            cherrypy.session['secret_message'] = secret_message
            print("THIS IS AFTER SOME SESSION STUFF")
        else:
            raise cherrypy.HTTPRedirect('/signout')
            # try:
            #     ip_address = x.get("connection_address")
            #     print(ip_address)
            #     MainApp.broadcast(self,username,ip_address,password,chat,hex_private_key)
            # except:
            #     pass

        try:
            username = cherrypy.session['username']
            cherrypy.session['my_username'] = username
            password = cherrypy.session['password']
            hex_priv_key = cherrypy.session['hex_priv_key']
            target_ip = "none"
            hex_pub_key = "none"
            for x in  (MainApp.listusers(self,cherrypy.session['username'],cherrypy.session['password']))["users"]:
                 if x["username"] == cherrypy.session['target_username']:
                        target_ip = x["connection_address"]
                        hex_pub_key = x["incoming_pubkey"]
                        break
            print(target_ip)
            print(hex_pub_key)
            self.private_message(username,password,hex_priv_key,target_ip,cherrypy.session['target_username'],hex_pub_key,secret_message)
        #     conn6 = sqlite3.connect("Users.db")
        #     c = conn6.cursor()
        #     target_user = target_username
        #     hex_pub_key = 0
        #     ip = str("none")
            
        
        #     c.execute("""SELECT publickey,ip FROM Users WHERE username =?""",(target_user,))
        #     for row in c.fetchall():
        #         hex_pub_key = (row[0])
        #         ip = (row[1])
        #         conn6.commit()
        #         conn6.close()

        #     print(hex_pub_key)
        #     print(ip)
                # username = cherrypy.session['username']
                # password = cherrypy.session['password']
                # hex_priv_key = cherrypy.session['hex_priv_key']
                # print(type(hex_priv_key))

            
                
            #hex_priv_key = bytes(hex_priv_key,'utf-8')
            
            print("message")
        except Exception as E:
                print(E)
                Page+= "<p>This user is not online</p> <a href='/signout'>Sign out</a>"
                #pass
        raise cherrypy.HTTPRedirect('/messaging')

        
        print("hello")
                    # conn3 = sqlite3.connect("Users.db")
        # c = conn3.cursor()
        # conn3.connect("Users.db")

        # current_user = username
        # priv_hex_key = 0
        # c.execute("""SELECT privatekey FROM Users WHERE username =?""",(current_user,))
        # for row in c.fetchall():
        #     priv_hex_key = (row[0])
        # priv_hex_key = bytes(priv_hex_key,'utf-8')

        # conn3.commit()
        # conn3.close()

    
    def private_message(self,username,password,hex_priv_key,target_ip,target_username,hex_pub_key,secret_message):
        #DMing Tomas
        #server_pubkey = '67e5107702196a80bff43b46c25531bc7f0cbbb44db5d24bd89077387abc73b6'
       # target_user = "tant836"
       # target_ip = "172.24.5.136:1234"

        print("DMing Myself")
       
        server_pubkey = hex_pub_key
        #target_user = "admin"
        target_user = target_username
        
#target_user = "tden328"

        login_server_record = self.getloginserver_record(username,password)
        timing = str(time.time())
        ENCODING = 'utf-8'
        secret_message = str(secret_message)

        # conn3 = sqlite3.connect("Users.db")
        # c = conn3.cursor()
        # conn3.connect("Users.db")

        # current_user = username
        # priv_hex_key = 0
        # c.execute("""SELECT privatekey FROM Users WHERE username =?""",(current_user,))
        # for row in c.fetchall():
        #     priv_hex_key = (row[0])
        # priv_hex_key = bytes(priv_hex_key,'utf-8')

        # conn3.commit()
        # conn3.close()



        signing_key = nacl.signing.SigningKey(hex_priv_key, encoder=nacl.encoding.HexEncoder)

            # Serialize the verify key to send it to a third party
        #verify_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder)
        pubkey_hex = signing_key.verify_key.encode(encoder = nacl.encoding.HexEncoder)
            
        pubkey_hex_str = pubkey_hex.decode(ENCODING)

        message = bytes(secret_message,ENCODING)
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

    def broadcast_log(self):
            conn7 = sqlite3.connect("Users.db")
            c = conn7.cursor()
            c.execute("""SELECT * FROM Broadcasts DESC""")
            broadcasts=c.fetchall()
            broadcasts = [list(x) for x in broadcasts]
            return(broadcasts)
              
    def private_log(self):
        conn8 = sqlite3.connect("Users.db")
        c=conn8.cursor()

        c.execute("""SELECT * FROM 'Private Messages' DESC""")
        private_messages = c.fetchall()
        private_messages = [list(x) for x in private_messages]
        
        return(private_messages)

    def users_log(self):
        users = []
        print(MainApp.username)
        print(MainApp.password)
        for x in  (MainApp.listusers(self,MainApp.username,MainApp.password))["users"]:
            active_username = x["username"]
            users.append(active_username)
        alphabetical_list = users.sort()
        print(alphabetical_list)
        print(users)
        return (users)




    @cherrypy.expose
    def receive_message(self):
        print("Sending message")

@cherrypy.expose
def CheckBroadcastSignature(loginserver_record,message,timestamp,signature):
    try:
        pubkey = loginserver_record.split(',')[1]
        v_key = nacl.signing.VerifyKey(pubkey,encoder = nacl.encoding.HexEncoder)
        signature_bytes = binascii.unhexlify(signature)
        message_bytes = bytes(loginserver_record+message+timestamp,'utf-8')
        v_key.verify(message_bytes,signature_bytes)
        return True
    except Exception as e:
        print(e)
        return False

    # @cherrypy.expose
    # def getusername(self):
    #     return self.username


    
# def authoriseUserLogin(username, password):
#     print("Log on attempt from {0}:{1}".format(username, password))
#     #ping(username,password)
#     pubhexstr = (MainApp.get_privatedata(username = username,password = password))
#     # report(username,password)
#     return (MainApp.ping(username,password))



###
### Functions only after here
###
@cherrypy.expose
def load_new_api_key(self,username,password):

    addkey_url = "http://cs302.kiwi.land/api/load_new_apikey"


    #create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    try:   
        req = urllib.request.Request(url=addkey_url, headers=headers)
        response = urllib.request.urlopen(req)
    except urllib.error.HTTPError as err:
        print("Error: " + str(err.code))
        return 1
    else:
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()

        JSON_object = json.loads(data.decode(encoding))
        if JSON_object["response"] == "ok":
            return JSON_object["api_key"]
        else:
            return 1

def API_header(api_key,username):
#create HTTP API Key authorization header
    headers = {
        "X-username":username,
        "X-apikey":api_key,
        'Content-Type' : 'application/json; charset='+'utf-8'
    }
    return headers
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
