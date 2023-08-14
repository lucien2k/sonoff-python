# The domain of your component. Should be equal to the name of your component.
import logging, time, hmac, hashlib, random, base64, json, socket, requests, re, string
from datetime import timedelta

SCAN_INTERVAL = timedelta(seconds=60)
HTTP_MOVED_PERMANENTLY, HTTP_BAD_REQUEST, HTTP_UNAUTHORIZED, HTTP_NOT_FOUND = 301,400,401,404

#_LOGGER = logging.getLogger(__name__)


def gen_nonce(length=8):
    """Generate pseudorandom number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])

class Sonoff():
    # def __init__(self, hass, email, password, api_region, grace_period):
    def __init__(self, username, password, api_region, user_apikey=None, bearer_token=None, grace_period=600):

        self._username      = username
        self._password      = password
        self._api_region    = api_region
        self._wshost        = None

        self._skipped_login = 0
        self._grace_period  = timedelta(seconds=grace_period)

        self._user_apikey   = user_apikey
        self._bearer_token  = bearer_token
        self._devices       = []
        self._ws            = None
        self.appid          = 'R8Oq3y0eSZSYdKccHlrQzT1ACCOUT9Gv'

        if user_apikey and bearer_token:
            self.do_reconnect()
        else:
            self.do_login()

    def do_reconnect(self):
        self._headers = {
            'Authorization' : 'Bearer ' + self._bearer_token,
            'Content-Type'  : 'application/json;charset=UTF-8'
        }

        try:
            # get the websocket host
            if not self._wshost:
                self.set_wshost()

            self.update_devices() # to get the devices list
        except:
            self.do_login()

    def do_login(self):
        import uuid

        # reset the grace period
        self._skipped_login = 0
        
        app_details = {
            'password'  : self._password,
            'version'   : '8',
            'ts'        : int(time.time()),
            'nonce'     : gen_nonce(15),
            #'appid'     : 'oeVkj2lYFGnJu5XUtWisfW4utiN4u9Mq',
	        'appid'	    : 'R8Oq3y0eSZSYdKccHlrQzT1ACCOUT9Gv',
            'imei'      : str(uuid.uuid4()),
            'os'        : 'iOS',
            'model'     : 'iPhone10,6',
            'romVersion': '11.1.2',
            'appVersion': '3.5.3'
        }

        self._model         = 'iPhone' + random.choice(['6,1', '6,2', '7,1', '7,2', '8,1', '8,2', '8,4', '9,1', '9,2', '9,3', '9,4', '10,1', '10,2', '10,3', '10,4', '10,5', '10,6', '11,2', '11,4', '11,6', '11,8'])
        self._romVersion    = random.choice([
            '10.0', '10.0.2', '10.0.3', '10.1', '10.1.1', '10.2', '10.2.1', '10.3', '10.3.1', '10.3.2', '10.3.3', '10.3.4',
            '11.0', '11.0.1', '11.0.2', '11.0.3', '11.1', '11.1.1', '11.1.2', '11.2', '11.2.1', '11.2.2', '11.2.3', '11.2.4', '11.2.5', '11.2.6', '11.3', '11.3.1', '11.4', '11.4.1',
            '12.0', '12.0.1', '12.1', '12.1.1', '12.1.2', '12.1.3', '12.1.4', '12.2', '12.3', '12.3.1', '12.3.2', '12.4', '12.4.1', '12.4.2',
            '13.0', '13.1', '13.1.1', '13.1.2', '13.2'
        ])
        self._appVersion    = random.choice(['3.5.3', '3.5.4', '3.5.6', '3.5.8', '3.5.10', '3.5.12', '3.6.0', '3.6.1', '3.7.0', '3.8.0', '3.9.0', '3.9.1', '3.10.0', '3.11.0'])
        self._imei          = str(uuid.uuid4())

        if re.match(r'[^@]+@[^@]+\.[^@]+', self._username):
            app_details['email'] = self._username
        else:
            app_details['phoneNumber'] = self._username

        #decryptedAppSecret = b'6Nz4n0xA8s8qdxQf2GqurZj2Fs55FUvM'
        decryptedAppSecret = b'1ve5Qk9GXfUhKAn1svnKwpAlxXkMarru'

        hex_dig = hmac.new(
            decryptedAppSecret, 
            str.encode(json.dumps(app_details)), 
            digestmod=hashlib.sha256).digest()
        
        sign = base64.b64encode(hex_dig).decode()

        self._headers = {
            'Authorization' : 'Sign ' + sign,
            'Content-Type'  : 'application/json;charset=UTF-8'
        }

#        r = requests.post('https://{}-api.coolkit.cc:8080/api/user/login'.format(self._api_region), 
#            headers=self._headers, json=app_details, verify=False)
        r = requests.post('https://{}-api.coolkit.cc:8080/api/user/login'.format(self._api_region),
            headers=self._headers, json=app_details)


        resp = r.json()

        # get a new region to login
        if 'error' in resp and 'region' in resp and resp['error'] == HTTP_MOVED_PERMANENTLY:
            self._api_region    = resp['region']

            print("found new region: >>> %s <<< (you should change api_region option to this value in configuration.yaml)", self._api_region)

            # re-login using the new localized endpoint
            self.do_login()
            return

        elif 'error' in resp and resp['error'] in [HTTP_NOT_FOUND, HTTP_BAD_REQUEST]:
            # (most likely) login with +86... phone number and region != cn
            if '@' not in self._username and self._api_region != 'cn':
                self._api_region    = 'cn'
                self.do_login()

            else:
                print("Couldn't authenticate using the provided credentials!")

            return

        self._bearer_token  = resp['at']
        self._user_apikey   = resp['user']['apikey']
        self._headers.update({'Authorization' : 'Bearer ' + self._bearer_token})

        # get the websocket host
        if not self._wshost:
            self.set_wshost()

        self.update_devices() # to get the devices list 

    def set_wshost(self):
#        r = requests.post('https://%s-disp.coolkit.cc:8080/dispatch/app' % self._api_region, headers=self._headers, verify=False)
        r = requests.post('https://%s-disp.coolkit.cc:8080/dispatch/app' % self._api_region, headers=self._headers)	
        resp = r.json()

        if 'error' in resp and resp['error'] == 0 and 'domain' in resp:
            self._wshost = resp['domain']
            #print("Found websocket address: %s", self._wshost)
        else:
            raise Exception('No websocket domain')

    def is_grace_period(self):
        grace_time_elapsed = self._skipped_login * int(SCAN_INTERVAL.total_seconds()) 
        grace_status = grace_time_elapsed < int(self._grace_period.total_seconds())

        if grace_status:
            self._skipped_login += 1

        return grace_status

    def update_devices(self):

        # the login failed, nothing to update
        if not self._wshost:
            return []

        # we are in the grace period, no updates to the devices
        if self._skipped_login and self.is_grace_period():          
            print("Grace period active, no updates to the devices")            
            return self._devices

        #r = requests.get('https://{}-api.coolkit.cc:8080/api/user/device'.format(self._api_region), 
        #    headers=self._headers)
        r = requests.get('https://{}-api.coolkit.cc:8080/api/user/device?lang=en&apiKey={}&getTags=1&version=6&ts=%s&nonce=%s&appid=Uw83EKZFxdif7XFXEsrpduz5YyjP7nTl&imei=%s&os=iOS&model=%s&romVersion=%s&appVersion=%s'.format(
            self._api_region, self.get_user_apikey(), str(int(time.time())), ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8)), self._imei, self._model, self._romVersion, self._appVersion
            ), headers=self._headers)
        resp = r.json()
	#print ("response :",resp)
	#print (r.status_code)
	#print (r.content)
        if 'error' in resp and resp['error'] in [HTTP_BAD_REQUEST, HTTP_UNAUTHORIZED]:
            # @IMPROVE add maybe a service call / switch to deactivate sonoff component
            if self.is_grace_period():
                print("Grace period activated!")

                # return the current (and possible old) state of devices
                # in this period any change made with the mobile app (on/off) won't be shown in HA
                return self._devices

            print("Re-login component")
            self.do_login()
        devices = r.json()
        self._devices = devices['devicelist']
        return self._devices

    def get_devices(self, force_update = False):
        if force_update: 
            return self.update_devices()

        return self._devices

    def get_device(self, deviceid):
        for device in self.get_devices():
            if 'deviceid' in device and device['deviceid'] == deviceid:
                return device

    def get_api_region(self):
        return self._api_region

    def get_bearer_token(self):
        return self._bearer_token

    def get_user_apikey(self):
        return self._user_apikey

    def _get_ws(self):
        import ssl
        import websocket
        """Check if the websocket is setup and connected."""
        try:
            create_connection
        except:
            from websocket import create_connection

        if self._ws is None:
            try:
	        #self._ws = websocket.WebSocket(sslopt={"cert_reqs": ssl.CERT_NONE})
		#self._ws.connect('wss://{}:8080/api/ws'.format(self._wshost))
                self._ws = create_connection(('wss://{}:8080/api/ws'.format(self._wshost)), timeout=10)
                ts = time.time()
#                payload = {
#                    'action'    : "userOnline",
#                    'userAgent' : 'app',
#                    'version'   : 8,
#                    'nonce'     : gen_nonce(15),
#                    'apkVesrion': "1.8",
#                    'os'        : 'ios',
#                    'at'        : self.get_bearer_token(),
#                    'apikey'    : self.get_user_apikey(),
#                    'ts'        : str(int(time.time())),
#                    'model'     : 'iPhone10,6',
#                    'romVersion': '11.1.2',
#                    'sequence'  : str(time.time()).replace('.','')
#                }
                payload = {
                    'action': 'userOnline',
                    'at': self.get_bearer_token(),
                    'apikey': self.get_user_apikey(),
                    'userAgent': 'app',
                    'appid': self.appid,
                    'nonce': str(int(ts / 100)),
                    'ts': int(ts),
                    'version': 8,
                    'sequence': str(int(ts * 1000))
                }

                self._ws.send(json.dumps(payload))
                wsresp = self._ws.recv()
		#print (wsresp)
                #("open socket: %s", wsresp)

#            except (socket.timeout, ConnectionRefusedError, ConnectionResetError):
            except (socket.timeout):
                print('failed to create the websocket')
                self._ws = None

        return self._ws
        
    def switch(self, new_state, deviceid, outlet=None):
        """Switch on or off."""

        # we're in the grace period, no state change
        if self._skipped_login:
            print("Grace period, no state change")
            return (not new_state)

        self._ws = self._get_ws()
        
        if not self._ws:
            print('invalid websocket, state cannot be changed')
            return (not new_state)

        # convert from True/False to on/off
        if isinstance(new_state, (bool)):
            new_state = 'on' if new_state else 'off'

        device = self.get_device(deviceid)

        if outlet is not None:
            print("Switching `%s - %s` on outlet %d to state: %s", \
                device['deviceid'], device['name'] , (outlet+1) , new_state)
        else:
            print ("Switching ", device['name'], " to state: ", new_state)

        if not device:
            print('unknown device to be updated')
            return False

        # the payload rule is like this:
        #   normal device (non-shared) 
        #       apikey      = login apikey (= device apikey too)
        #
        #   shared device
        #       apikey      = device apikey
        #       selfApiKey  = login apikey (yes, it's typed corectly selfApikey and not selfApiKey :|)

        if outlet is not None:
            params = { 'switches' : device['params']['switches'] }
            params['switches'][outlet]['switch'] = new_state

        else:
            params = { 'switch' : new_state }

        payload = {
            'action'        : 'update',
            'userAgent'     : 'app',
            'params'        : params,
            'apikey'        : device['apikey'],
            'deviceid'      : str(deviceid),
            'sequence'      : str(time.time()).replace('.',''),
            'controlType'   : device['params']['controlType'] if 'controlType' in device['params'] else 4,
            'ts'            : 0
        }

        # this key is needed for a shared device
        if device['apikey'] != self.get_user_apikey():
            payload['selfApikey'] = self.get_user_apikey()

        self._ws.send(json.dumps(payload))
        wsresp = self._ws.recv()
        #_LOGGER.debug("switch socket: %s", wsresp)
	#print (wsresp)        
        self._ws.close() # no need to keep websocket open (for now)
        self._ws = None

        # set also te pseudo-internal state of the device until the real refresh kicks in
        for idx, device in enumerate(self._devices):
            if device['deviceid'] == deviceid:
                if outlet is not None:
                    self._devices[idx]['params']['switches'][outlet]['switch'] = new_state
                else:
                    self._devices[idx]['params']['switch'] = new_state


        # @TODO add some sort of validation here, maybe call the devices status 
        # only IF MAIN STATUS is done over websocket exclusively

        return new_state

