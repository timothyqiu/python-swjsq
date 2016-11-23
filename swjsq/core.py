from __future__ import absolute_import

import collections
import logging
import json
import time
import hashlib
import atexit

from swjsq._compat import binary_type, text_type
from swjsq._compat import URLError
from swjsq.exceptions import APIError, LoginError, SWJSQError, UpgradeError
from swjsq.http import get as http_get
from swjsq.rsa import rsa_encrypt
from swjsq.utils import get_mac

logger = logging.getLogger(__name__)


RSA_MOD = u'AC69F5CCC8BDE47CD3D371603748378C9CFAD2938A6B021E0E191013975AD683F5CBF9ADE8BD7D46B4D2EC2D78AF146F1DD2D50DC51446BB8880B8CE88D476694DFC60594393BEEFAA16F5DBCEBE22F89D640F5336E42F587DC4AFEDEFEAC36CF007009CCCE5C1ACB4FF06FBA69802A8085C2C54BADD0597FC83E6870F1E36FD'
RSA_PUBEXP = u'010001'

PROTOCOL_VERSION = 108
FALLBACK_MAC = '00:00:00:00:00:00'
FALLBACK_INTERFACE = u'119.147.41.210:80'

TYPE_NORMAL_ACCOUNT = 0
TYPE_NUM_ACCOUNT = 1


class Session(object):
    def __init__(self, login_response):
        self.raw = login_response

    @property
    def user_id(self):
        return self.raw.get(u'userID')

    @property
    def session_id(self):
        return self.raw.get(u'sessionID')

    @property
    def can_upgrade(self):
        if self.raw.get(u'isVip'):
            return True
        if self.raw.get(u'payId') in [5, 702]:
            return True
        return False

    @property
    def is_subaccount(self):
        return self.raw.get('isSubAccount', False)


class Bandwidth(object):
    BandwidthDetail = collections.namedtuple(u'BandwidthDetail',
                                             u'upstream downstream')

    def __init__(self, response):
        self.raw = response

    @property
    def can_upgrade(self):
        return self.raw.get(u'can_upgrade', False)

    @property
    def dial_account(self):
        return self.raw.get(u'dial_account')

    @property
    def original(self):
        detail = self.raw[u'bandwidth']  # FIXME: what if no such field?
        return self.BandwidthDetail(detail[u'upstream'], detail[u'downstream'])

    @property
    def max(self):
        detail = self.raw[u'max_bandwidth']  # FIXME: what if no such field?
        return self.BandwidthDetail(detail[u'upstream'], detail[u'downstream'])

    @property
    def province_name(self):
        return self.raw.get(u'province_name')

    @property
    def sp_name(self):
        return self.raw.get(u'sp_name')


class XunleiClient(object):
    def __init__(self, business_type, client_version, rsa_key=None):
        self.session = None
        self.business_type = business_type
        self.client_version = client_version
        self.rsa_pubexp, self.rsa_mod = rsa_key or (RSA_PUBEXP, RSA_MOD)

    @property
    def peer_id(self):
        peer_id = getattr(self, '_peer_id', None)
        if peer_id is None:
            mac = get_mac() or FALLBACK_MAC
            peer_id = mac.replace(':', '').upper() + '004V'
            setattr(self, '_peer_id', peer_id)
        return peer_id

    def _json_http_req(self, url, params=None, body=None, headers=None,
                       max_tries=3, encoding=None):
        encoding = encoding or u'utf-8'
        response = http_get(url, params, body, headers, max_tries)
        return json.loads(response.decode(encoding))

    def _xunlei_request(self, payload):
        headers = {
            u'Content-Type': u'',
            u'Connection': u'Keep-Alive',
            u'Accept-Encoding': u'gzip',
            u'User-Agent': (
                u'android-async-http/xl-acc-sdk/version-1.6.1.177600'
            ),
        }
        url = u'https://login.mobile.reg2t.sandai.net:443/'
        return self._json_http_req(url, body=payload,
                                   headers=headers, encoding=u'gbk')

    def login(self, uname, pwd_md5, login_type=TYPE_NORMAL_ACCOUNT,
              verify_key=None, verify_code=None):
        verify_key = verify_key or u''
        verify_code = verify_code or u''

        # just generate a 32-bit string
        fake_device_id = hashlib.md5(("%s23333" % pwd_md5).encode('utf-8')).hexdigest()

        # sign = div.10?.device_id + md5(sha1(packageName + businessType + md5(a protocolVersion specific GUID)))
        device_sign = "div100.%s%s" % (fake_device_id, hashlib.md5(
            hashlib.sha1(
                ("%scom.xunlei.vip.swjsq68700d1872b772946a6940e4b51827e8af" % fake_device_id).encode('utf-8')
            ).hexdigest().encode('utf-8')
        ).hexdigest())

        if isinstance(uname, binary_type):
            username = uname.decode('utf-8')
        elif not isinstance(uname, text_type):
            username = text_type(uname)
        else:
            username = uname

        payload = json.dumps({
            u'protocolVersion': PROTOCOL_VERSION,  # 109
            u'sequenceNo': 1000001,
            u'platformVersion': 1,
            u'sdkVersion': 177550,  # 177600
            u'peerID': self.peer_id,
            u'businessType': self.business_type,
            u'clientVersion': self.client_version,
            u'devicesign': device_sign,
            u'isCompressed': 0,
            u'cmdID': 1,
            u'userName': username,
            u'passWord': rsa_encrypt(self.rsa_pubexp, self.rsa_mod, pwd_md5),
            u'loginType': login_type,
            u'sessionID': u'',
            u'verifyKey': verify_key,
            u'verifyCode': verify_code,
            u'appName': u'ANDROID-com.xunlei.vip.swjsq',
            u'rsaKey': {
                u'e': self.rsa_pubexp,
                u'n': self.rsa_mod,
            },
            u'extensionList': u'',
        })

        # TODO: Verification code handling
        # If "errorCode" is 6, "errorDescUrl" contains URL of the verification
        # code image. Access the URL and we can get the image, and the
        # "VERIFY_KEY" from cookie. Next time we send the login request, fill
        # in the "verifyKey" and "verifyCode".
        response = self._xunlei_request(payload)

        code = response.get(u'errorCode')
        if code != 0:
            message = response.get(u'errorDesc')
            logger.debug(u'Login failed: (%d) %s', code, message or 'Unknown')
            raise LoginError(code, message)

        logger.debug(u'isVip:%s payId:%s payName:%s',
                     response.get(u'isVip'),
                     response.get(u'payId'), response.get(u'payName'))

        self.session = Session(response)

        return self.session

    def renew(self):
        payload = json.dumps({
            u'protocolVersion': PROTOCOL_VERSION,
            u'sequenceNo': 1000000,
            u'platformVersion': 1,
            u'peerID': self.peer_id,
            u'businessType': self.business_type,
            u'clientVersion': self.client_version,
            u'isCompressed': 0,
            u'cmdID': 11,
            u'userID': self.session.user_id,
            u'sessionID': self.session.session_id,
        })
        response = self._xunlei_request(payload)

        code = response.get(u'errorCode')
        if code != 0:
            message = response.get(u'errorDesc')
            logger.debug(u'Renew failed: (%d) %s', code, message or u'Unknown')
            raise LoginError(code, message)

        return response


class SWJSQClient(XunleiClient):
    def __init__(self):
        business_type = 68  # Constant. Probably for SWJSQ
        client_version = "2.0.3.4"
        super(SWJSQClient, self).__init__(business_type, client_version)

        self.api_url = self._get_api_url()
        logger.debug(u'API URL: %s', self.api_url)

    def _get_api_url(self):
        # Try to connect to the first available query portal server
        PORTAL_URLS = [
            u'http://api.portal.swjsq.vip.xunlei.com:81/v2/queryportal',
            u'http://api2.portal.swjsq.vip.xunlei.com:81/v2/queryportal',
        ]
        for url in PORTAL_URLS:
            try:
                portal = self._json_http_req(url, max_tries=1)
            except URLError:
                pass
            else:
                break
        else:
            logger.warn(u'queryportal failed: no portal server available')
            return FALLBACK_INTERFACE

        errno = portal.get(u'errno')
        if errno != 0:
            message = portal.get(u'message', u'Unknown')
            logger.warn(u'queryportal failed: (%d) %s', errno, message)
            return FALLBACK_INTERFACE

        try:
            ip = portal[u'interface_ip']
            port = portal[u'interface_port']
        except KeyError as e:
            logger.warn(u'queryportal format error: %s', e)
            return FALLBACK_INTERFACE

        return u'{0}:{1}'.format(ip, port)

    def _execute(self, cmd, extras=None):
        # for 'bandwidth' command, `userid` and `sessionid` are not mandatory
        params = {
            u'client_type': u'android-swjsq-{0}'.format(self.client_version),
            u'peerid': self.peer_id,
            u'time_and': time.time() * 1000,
            u'client_version': u'androidswjsq-{0}'.format(self.client_version),
            u'userid': self.session.user_id,
            u'sessionid': self.session.session_id,
            u'os': u'android-5.0.1.23SmallRice',
        }
        if extras:
            params.update(extras)

        url = u'http://{0}/v2/{1}'.format(self.api_url, cmd)
        headers = {
            u'Content-Type': u'',
            u'Connection': u'Keep-Alive',
            u'Accept-Encoding': u'gzip',
            u'User-Agent': (
                u'Dalvik/2.1.0 '
                u'(Linux; U; Android 5.0.1; SmallRice Build/LRX22C)'
            ),
        }
        response = self._json_http_req(url, params=params, headers=headers)

        errno = response.get('errno')
        if errno:
            message = response.get('richmessage')
            if not message:
                message = response.get('message')
            raise APIError(cmd, errno, message)

        return response

    def get_bandwidth(self):
        response = self._execute(u'bandwidth')
        bandwidth = Bandwidth(response)

        KB_PER_MB = 1024
        logger.info(u'To Upgrade: %s%s Down %dM -> %dM, Up %dM -> %dM',
                    bandwidth.province_name, bandwidth.sp_name,
                    bandwidth.original.downstream / KB_PER_MB,
                    bandwidth.max.downstream / KB_PER_MB,
                    bandwidth.original.upstream / KB_PER_MB,
                    bandwidth.max.upstream / KB_PER_MB)
        return bandwidth

    def upgrade(self, bandwidth):
        extras = {
            u'user_type': 1,
            u'dial_account': bandwidth.dial_account,
        }
        response = self._execute(u'upgrade', extras=extras)
        logger.info(u'Upgrade done: Down %dM, Up %dM',
                    response[u'bandwidth'][u'downstream'],
                    response[u'bandwidth'][u'upstream'])
        return response

    def recover(self, bandwidth):
        extras = {
            u'dial_account': bandwidth.dial_account,
        }
        return self._execute(u'recover', extras=extras)

    def heartbeat(self):
        return self._execute(u'keepalive')


def fast_d1ck(client, password_hash):
    if client.session.is_subaccount:
        raise UpgradeError(u'Subaccount cannot upgrade')

    if not client.session.can_upgrade:
        logger.warn(u'You are probably not Xunlei VIP')

    bandwidth = client.get_bandwidth()
    if not bandwidth.can_upgrade:
        logger.error(u'Does not support upgrading.')
        raise UpgradeError(u'Bandwidth cannot upgrade')

    def _atexit_func():
        logger.info(u'Sending recover request')
        try:
            client.recover(bandwidth)
        except KeyboardInterrupt:
            logger.info(u'Secondary ctrl+c pressed, exiting')
        else:
            logger.info(u'Recover done. exiting')

    atexit.register(_atexit_func)
    i = 0
    while True:
        try:
            # i=1~17 keepalive, renew session, i++
            # i=18 (3h) re-upgrade, i:=0
            # i=100 login, i:=36
            if i == 100:
                try:
                    client.login(client.session.user_id,
                                 password_hash,
                                 TYPE_NUM_ACCOUNT)
                except SWJSQError:
                    logger.error('login_xunlei failed')
                i = 18

            if i % 18 == 0:  # 3h
                logger.info('Initializing upgrade')
                if i:  # not first time
                    client.recover(bandwidth)
                    time.sleep(5)
                _ = client.upgrade(bandwidth)
                i = 0
            else:
                try:
                    client.renew()
                except SWJSQError:
                    logger.error('renew_xunlei failed')
                    i = 100
                    continue
                _ = client.heartbeat()

            logger.debug('%s', _)
        except APIError as e:
            logger.error('APIError %s: (%d) %s', e.command, e.errno, e.message)
            if e.errno == 513:  # not exist channel: re-upgrade
                i = 100
                continue
            elif e.errno in (717, 718):  # account auth session failed
                i = 100  # The App also asks to relogin
                continue
            elif e.errno == 812:
                logger.info('Already upgraded, continuing')
                i = 0
            else:
                time.sleep(300)
        except Exception:
            logger.exception('Unexpected')

        i += 1
        time.sleep(600)  # 10 min
