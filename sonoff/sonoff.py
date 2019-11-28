# The domain of your component. Should be equal to the name of your component.
import logging, time, hmac, hashlib, random, base64, json, socket, requests, re, uuid
from datetime import timedelta

SCAN_INTERVAL = timedelta(seconds=60)
HTTP_MOVED_PERMANENTLY, HTTP_BAD_REQUEST, HTTP_UNAUTHORIZED, HTTP_NOT_FOUND = 301,400,401,404

_LOGGER = logging.getLogger(__name__)


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
        self._appid = 'oeVkj2lYFGnJu5XUtWisfW4utiN4u9Mq'

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

        # reset the grace period
        self._skipped_login = 0
        
        app_details = {
            'password'  : self._password,
            'version'   : '6',
            'ts'        : int(time.time()),
            'nonce'     : gen_nonce(15),
            'appid'     : self._appid,
            'imei'      : str(uuid.uuid4()),
            'os'        : 'iOS',
            'model'     : 'iPhone10,6',
            'romVersion': '11.1.2',
            'appVersion': '3.5.3'
        }

        if re.match(r'[^@]+@[^@]+\.[^@]+', self._username):
            app_details['email'] = self._username
        else:
            app_details['phoneNumber'] = self._username

        decryptedAppSecret = b'6Nz4n0xA8s8qdxQf2GqurZj2Fs55FUvM'

        hex_dig = hmac.new(
            decryptedAppSecret, 
            str.encode(json.dumps(app_details)), 
            digestmod=hashlib.sha256).digest()
        
        sign = base64.b64encode(hex_dig).decode()

        self._headers = {
            'Authorization' : 'Sign ' + sign,
            'Content-Type'  : 'application/json;charset=UTF-8'
        }

        r = requests.post('https://{}-api.coolkit.cc:8080/api/user/login'.format(self._api_region), 
            headers=self._headers, json=app_details)

        resp = r.json()

        # get a new region to login
        if 'error' in resp and 'region' in resp and resp['error'] == HTTP_MOVED_PERMANENTLY:
            self._api_region    = resp['region']

            _LOGGER.warning("found new region: >>> %s <<< (you should change api_region option to this value in configuration.yaml)", self._api_region)

            # re-login using the new localized endpoint
            self.do_login()
            return

        elif 'error' in resp and resp['error'] in [HTTP_NOT_FOUND, HTTP_BAD_REQUEST]:
            # (most likely) login with +86... phone number and region != cn
            if '@' not in self._username and self._api_region != 'cn':
                self._api_region    = 'cn'
                self.do_login()

            else:
                _LOGGER.error("Couldn't authenticate using the provided credentials!")

            return

        self._bearer_token  = resp['at']
        self._user_apikey   = resp['user']['apikey']
        self._headers.update({'Authorization' : 'Bearer ' + self._bearer_token})

        # get the websocket host
        if not self._wshost:
            self.set_wshost()

        self.update_devices() # to get the devices list 

    def set_wshost(self):
        r = requests.post('https://%s-disp.coolkit.cc:8080/dispatch/app' % self._api_region, headers=self._headers)
        resp = r.json()

        if 'error' in resp and resp['error'] == 0 and 'domain' in resp:
            self._wshost = resp['domain']
            _LOGGER.info("Found websocket address: %s", self._wshost)
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
            _LOGGER.info("Grace period active")            
            return self._devices

        query_params = {
            'lang': 'en',
            'version': '6',
            'ts': int(time.time()),
            'nonce': gen_nonce(15),
            'appid': self._appid,
            'imei': str(uuid.uuid4()),
            'os': 'iOS',
            'model': 'iPhone10,6',
            'romVersion': '11.1.2',
            'appVersion': '3.5.3'
        }
        r = requests.get('https://{}-api.coolkit.cc:8080/api/user/device'.format(self._api_region),
                         params=query_params,
                         headers=self._headers)

        resp = r.json()
        if 'error' in resp and resp['error'] in [HTTP_BAD_REQUEST, HTTP_UNAUTHORIZED]:
            # @IMPROVE add maybe a service call / switch to deactivate sonoff component
            if self.is_grace_period():
                _LOGGER.warning("Grace period activated!")

                # return the current (and possible old) state of devices
                # in this period any change made with the mobile app (on/off) won't be shown in HA
                return self._devices

            _LOGGER.info("Re-login component")
            self.do_login()

        self._devices = resp.get('devicelist', [])
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
        """Check if the websocket is setup and connected."""
        try:
            create_connection
        except:
            from websocket import create_connection

        if self._ws is None:
            try:
                self._ws = create_connection(('wss://{}:8080/api/ws'.format(self._wshost)), timeout=10)

                payload = {
                    'action'    : "userOnline",
                    'userAgent' : 'app',
                    'version'   : 6,
                    'nonce'     : gen_nonce(15),
                    'apkVesrion': "1.8",
                    'os'        : 'ios',
                    'at'        : self.get_bearer_token(),
                    'apikey'    : self.get_user_apikey(),
                    'ts'        : str(int(time.time())),
                    'model'     : 'iPhone10,6',
                    'romVersion': '11.1.2',
                    'sequence'  : str(time.time()).replace('.','')
                }

                self._ws.send(json.dumps(payload))
                wsresp = self._ws.recv()
                # _LOGGER.error("open socket: %s", wsresp)

            except (socket.timeout, ConnectionRefusedError, ConnectionResetError):
                _LOGGER.error('failed to create the websocket')
                self._ws = None

        return self._ws
        
    def switch(self, new_state, deviceid, outlet=None):
        """Switch on or off."""

        # we're in the grace period, no state change
        if self._skipped_login:
            _LOGGER.info("Grace period, no state change")
            return (not new_state)

        self._ws = self._get_ws()
        
        if not self._ws:
            _LOGGER.warning('invalid websocket, state cannot be changed')
            return (not new_state)

        # convert from True/False to on/off
        if isinstance(new_state, (bool)):
            new_state = 'on' if new_state else 'off'

        device = self.get_device(deviceid)

        if outlet is not None:
            _LOGGER.debug("Switching `%s - %s` on outlet %d to state: %s", \
                device['deviceid'], device['name'] , (outlet+1) , new_state)
        else:
            _LOGGER.debug("Switching `%s` to state: %s", deviceid, new_state)

        if not device:
            _LOGGER.error('unknown device to be updated')
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
        # _LOGGER.debug("switch socket: %s", wsresp)
        
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

