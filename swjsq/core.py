from __future__ import absolute_import
from __future__ import print_function

import logging
import os
import re
import json
import time
import hashlib
import binascii
import ssl
import atexit

from swjsq._compat import PY3
from swjsq._compat import binary_type, text_type
from swjsq._compat import iterbytes, iteritems, range
from swjsq._compat import request, URLError
from swjsq.exceptions import APIError, LoginError, SWJSQError

logger = logging.getLogger(__name__)


# xunlei use self-signed certificate; on py2.7.9+
if hasattr(ssl, '_create_unverified_context') and hasattr(ssl, '_create_default_https_context'):
    ssl._create_default_https_context = ssl._create_unverified_context

rsa_mod = 0xAC69F5CCC8BDE47CD3D371603748378C9CFAD2938A6B021E0E191013975AD683F5CBF9ADE8BD7D46B4D2EC2D78AF146F1DD2D50DC51446BB8880B8CE88D476694DFC60594393BEEFAA16F5DBCEBE22F89D640F5336E42F587DC4AFEDEFEAC36CF007009CCCE5C1ACB4FF06FBA69802A8085C2C54BADD0597FC83E6870F1E36FD
rsa_pubexp = 0x010001

BUSINESS_TYPE = 68  # Constant. Probably for SWJSQ
APP_VERSION = "2.0.3.4"
PROTOCOL_VERSION = 108
FALLBACK_MAC = '000000000000'
FALLBACK_INTERFACE = u'119.147.41.210:80'
XUNLEI_LOGIN_URL = u'https://login.mobile.reg2t.sandai.net:443/'

if not PY3:
    rsa_pubexp = long(rsa_pubexp)


try:
    from Crypto.PublicKey import RSA
except ImportError:
    # slow rsa
    logger.warn('pycrypto not found, using pure-python implemention')
    rsa_result = {}

    def cached(func):
        def _(s):
            if s in rsa_result:
                _r = rsa_result[s]
            else:
                _r = func(s)
                rsa_result[s] = _r
            return _r
        return _

    # https://github.com/mengskysama/XunLeiCrystalMinesMakeDie/blob/master/run.py
    def modpow(b, e, m):
        result = 1
        while (e > 0):
            if e & 1:
                result = (result * b) % m
            e = e >> 1
            b = (b * b) % m
        return result

    def binary_to_int(binary):
        str_int = 0
        for c in iterbytes(binary):
            str_int = str_int << 8
            str_int += c
        return str_int

    @cached
    def rsa_encode(payload):
        if not isinstance(payload, binary_type):
            raise TypeError(u'payload should be of binary type')
        result = modpow(binary_to_int(payload), rsa_pubexp, rsa_mod)
        return u'{0:0256X}'.format(result)  # length should be 1024bit, hard coded here
else:
    cipher = RSA.construct((rsa_mod, rsa_pubexp))

    def rsa_encode(payload):
        if not isinstance(payload, binary_type):
            raise TypeError(u'payload should be of binary type')
        _ = binascii.hexlify(cipher.encrypt(payload, None)[0]).upper()
        if PY3:
            _ = _.decode("utf-8")
        return _


TYPE_NORMAL_ACCOUNT = 0
TYPE_NUM_ACCOUNT = 1

header_xl = {
    'Content-Type': '',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'User-Agent': 'android-async-http/xl-acc-sdk/version-1.6.1.177600'
}
header_api = {
    'Content-Type': '',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 5.0.1; SmallRice Build/LRX22C)'
}


def get_mac(nic='', to_splt=':'):
    if os.name == 'nt':
        cmd = 'ipconfig /all'
        splt = '-'
    elif os.name == "posix":
        if os.path.exists('/usr/bin/ip') or os.path.exists('/bin/ip'):
            if nic:
                cmd = 'ip link show dev %s' % nic
            else:
                # Unfortunately, loopback interface always comes first
                # So we have to grep it out
                cmd = 'ip link show up | grep -v loopback'
        else:
            cmd = 'ifconfig %s' % (nic or '-a')
        splt = ':'
    else:
        return FALLBACK_MAC
    try:
        r = os.popen(cmd).read()
        if r:
            _ = re.findall('((?:[0-9A-Fa-f]{2}%s){5}[0-9A-Fa-f]{2})' % splt, r)
            if not _:
                return FALLBACK_MAC
            else:
                return _[0].replace(splt, to_splt)
    except:
        pass
    return FALLBACK_MAC


def http_req(url, headers=None, body=None, max_tries=3):
    '''Get result of HTTP request
    :param url: URL of the target
    :param headers: optional request headers as dict
    :param body: optional request body as binary type or ascii text
    :param max_tries: total count of failed tries before raising error
    :returns: body of the response as binary type
    :raises URLError: request failed even after retries
    '''
    req = request.Request(url)
    for k, v in iteritems(headers or {}):
        req.add_header(k, v)
    if isinstance(body, text_type):
        body = body.encode(u'ascii')

    sleep_increment = 2
    for i in range(1, max_tries + 1):
        try:
            resp = request.urlopen(req, data=body)
        except URLError as e:
            logger.debug(u'#%d request failed: %s', i, e)
            if i == max_tries:
                raise
            time.sleep(i * sleep_increment)
        else:
            break

    return resp.read()


def json_http_req(url, headers=None, body=None, max_tries=3, encoding=None):
    encoding = encoding or u'utf-8'

    response = http_req(url, headers, body, max_tries)

    return json.loads(response.decode(encoding))


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
        if self.get(u'payId') in [5, 702]:
            return True
        return False


def login_xunlei(uname, pwd_md5, login_type=TYPE_NORMAL_ACCOUNT,
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

    payload = json.dumps({
        u'protocolVersion': PROTOCOL_VERSION,  # 109
        u'sequenceNo': 1000001,
        u'platformVersion': 1,
        u'sdkVersion': 177550,  # 177600
        u'peerID': PEER_ID,
        u'businessType': BUSINESS_TYPE,
        u'clientVersion': APP_VERSION,
        u'devicesign': device_sign,
        u'isCompressed': 0,
        u'cmdID': 1,
        u'userName': uname.decode('utf-8'),
        u'passWord': rsa_encode(pwd_md5),
        u'loginType': login_type,
        u'sessionID': u'',
        u'verifyKey': verify_key,
        u'verifyCode': verify_code,
        u'appName': u'ANDROID-com.xunlei.vip.swjsq',
        u'rsaKey': {
            u'e': u'{:06X}'.format(rsa_pubexp),
            u'n': u'{:0256X}'.format(rsa_mod),
        },
        u'extensionList': u'',
    })

    # TODO: Verification code handling
    # If "errorCode" is 6, "errorDescUrl" contains URL of the verification
    # code image. Access the URL and we can get the image, and the
    # "VERIFY_KEY" from cookie. Next time we send the login request, fill in
    # the "verifyKey" and "verifyCode".
    response = json_http_req(XUNLEI_LOGIN_URL,
                             body=payload, headers=header_xl, encoding=u'gbk')

    code = response.get(u'errorCode')
    if code != 0:
        message = response.get(u'errorDesc')
        logger.debug(u'Login failed: (%d) %s', code, message or 'Unknown')
        raise LoginError(code, message)

    logger.debug(u'isVip:%s payId:%s payName:%s',
                 response.get(u'isVip'),
                 response.get(u'payId'), response.get(u'payName'))
    return Session(response)


def renew_xunlei(session):
    payload = json.dumps({
        u'protocolVersion': PROTOCOL_VERSION,
        u'sequenceNo': 1000000,
        u'platformVersion': 1,
        u'peerID': PEER_ID,
        u'businessType': BUSINESS_TYPE,
        u'clientVersion': APP_VERSION,
        u'isCompressed': 0,
        u'cmdID': 11,
        u'userID': session.user_id,
        u'sessionID': session.session_id,
    })
    response = json_http_req(XUNLEI_LOGIN_URL,
                             body=payload, headers=header_xl, encoding=u'gbk')

    code = response.get(u'errorCode')
    if code != 0:
        message = response.get(u'errorDesc')
        logger.debug(u'Renew failed: (%d) %s', code, message or u'Unknown')
        raise LoginError(code, message)

    return response


def portal_http_req():
    # Try to connect to the first available query portal server
    PORTAL_URLS = [
        u'http://api.portal.swjsq.vip.xunlei.com:81/v2/queryportal',
        u'http://api2.portal.swjsq.vip.xunlei.com:81/v2/queryportal',
    ]
    for url in PORTAL_URLS:
        try:
            return json_http_req(url, max_tries=1)
        except URLError:
            pass
    return None


def api_url():
    portal = portal_http_req()
    if not portal:
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

    return u'{}:{}'.format(ip, port)


def setup():
    global PEER_ID
    global API_URL
    PEER_ID = get_mac(to_splt='').upper() + '004V'
    API_URL = api_url()

    logger.debug(u'API_URL: %s', API_URL)


def api(cmd, uid, session_id='', extras=''):
    # missing dial_account, (userid), os
    url = 'http://%s/v2/%s?%sclient_type=android-swjsq-%s&peerid=%s&time_and=%d&client_version=androidswjsq-%s&userid=%s&os=android-5.0.1.23SmallRice%s' % (
            API_URL,
            cmd,
            ('sessionid=%s&' % session_id) if session_id else '',
            APP_VERSION,
            PEER_ID,
            time.time() * 1000,
            APP_VERSION,
            uid,
            ('&%s' % extras) if extras else '',
    )
    response = json_http_req(url, headers=header_api)

    errno = response.get('errno')
    if errno:
        message = response.get('richmessage')
        if not message:
            message = response.get('message')
        raise APIError(cmd, errno, message)

    return response


def fast_d1ck(uname, pwd, login_type,
              account_file_encrypted, account_file_plain, save=True):
    if uname[-2] == ':':
        logger.error('sub account can not upgrade')
        os._exit(3)

    session = login_xunlei(uname, pwd, login_type)
    logger.info('Login xunlei succeeded')

    if not session.can_upgrade:
        logger.warn(u'You are probably not Xunlei VIP')

    if save:
        try:
            os.remove(account_file_plain)
        except:
            pass
        with open(account_file_encrypted, 'w') as f:
            f.write('%s,%s' % (session.user_id, pwd))

    _ = api('bandwidth', session.user_id)
    if not _['can_upgrade']:
        logger.error('can not upgrade, so sad TAT %s', _['message'])
        os._exit(3)

    _dial_account = _['dial_account']

    logger.info(
        'To Upgrade: %s%s Down %dM -> %dM, Up %dM -> %dM',
        _['province_name'], _['sp_name'],
        _['bandwidth']['downstream']/1024,
        _['max_bandwidth']['downstream']/1024,
        _['bandwidth']['upstream']/1024,
        _['max_bandwidth']['upstream']/1024,
    )

    def _atexit_func():
        logger.info("Sending recover request")
        try:
            api('recover', session.user_id, session.session_id, extras="dial_account=%s" % _dial_account)
        except KeyboardInterrupt:
            logger.info('Secondary ctrl+c pressed, exiting')
        else:
            logger.info("Recover done. exiting")

    atexit.register(_atexit_func)
    i = 0
    while True:
        try:
            # i=1~17 keepalive, renew session, i++
            # i=18 (3h) re-upgrade, i:=0
            # i=100 login, i:=36
            if i == 100:
                try:
                    new_session = login_xunlei(uname, pwd, login_type)
                except SWJSQError:
                    logger.error('login_xunlei failed')
                else:
                    session = new_session
                i = 18

            if i % 18 == 0:  # 3h
                logger.info('Initializing upgrade')
                if i:  # not first time
                    api('recover', session.user_id, session.session_id, extras="dial_account=%s" % _dial_account)
                    time.sleep(5)
                _ = api('upgrade', session.user_id, session.session_id, extras="user_type=1&dial_account=%s" % _dial_account)
                logger.info('Upgrade done: Down %dM, Up %dM', _['bandwidth']['downstream'], _['bandwidth']['upstream'])
                i = 0
            else:
                try:
                    renew_xunlei(session)
                except SWJSQError:
                    logger.error('renew_xunlei failed')
                    i = 100
                    continue
                _ = api('keepalive', session.user_id, session.session_id)

            logger.debug('%s', _)
        except APIError as e:
            logger.error('APIError %s: (%d) %s', e.command, e.errno, e.message)
            if e.errno == 513:  # not exist channel: re-upgrade
                i = 100
                continue
            elif e.errno == 812:
                logger.info('Already upgraded, continuing')
                i = 0
            else:
                time.sleep(300)  # os._exit(4)
        except Exception:
            logger.exception('Unexpected')

        i += 1
        time.sleep(600)  # 10 min
