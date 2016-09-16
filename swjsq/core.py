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

logger = logging.getLogger(__name__)


# xunlei use self-signed certificate; on py2.7.9+
if hasattr(ssl, '_create_unverified_context') and hasattr(ssl, '_create_default_https_context'):
    ssl._create_default_https_context = ssl._create_unverified_context

rsa_mod = 0xAC69F5CCC8BDE47CD3D371603748378C9CFAD2938A6B021E0E191013975AD683F5CBF9ADE8BD7D46B4D2EC2D78AF146F1DD2D50DC51446BB8880B8CE88D476694DFC60594393BEEFAA16F5DBCEBE22F89D640F5336E42F587DC4AFEDEFEAC36CF007009CCCE5C1ACB4FF06FBA69802A8085C2C54BADD0597FC83E6870F1E36FD
rsa_pubexp = 0x010001

APP_VERSION = "2.0.3.4"
PROTOCOL_VERSION = 108
FALLBACK_MAC = '000000000000'
FALLBACK_INTERFACE = '119.147.41.210:80'

if not PY3:
    rsa_pubexp = long(rsa_pubexp)


class APIError(RuntimeError):
    def __init__(self, command, errno, message):
        self.command = command
        self.errno = errno
        self.message = message


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
            raise TypeError('payload should be of binary type')
        result = modpow(binary_to_int(payload), rsa_pubexp, rsa_mod)
        return "{0:0256X}".format(result)  # length should be 1024bit, hard coded here
else:
    cipher = RSA.construct((rsa_mod, rsa_pubexp))

    def rsa_encode(payload):
        if not isinstance(payload, binary_type):
            raise TypeError('payload should be of binary type')
        _ = binascii.hexlify(cipher.encrypt(payload, None)[0]).upper()
        if PY3:
            _ = _.decode("utf-8")
        return _


TYPE_NORMAL_ACCOUNT = 0
TYPE_NUM_ACCOUNT = 1

UNICODE_WARNING_SHOWN = False

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


def http_req(url, headers=None, body=None, encoding=u'utf-8'):
    req = request.Request(url)
    for k, v in iteritems(headers or {}):
        req.add_header(k, v)
    if isinstance(body, text_type):
        body = body.encode(u'ascii')

    max_tries = 3
    sleep_increment = 2
    for i in range(max_tries):
        try:
            resp = request.urlopen(req, data=body)
        except URLError as e:
            if i + 1 == max_tries:
                raise
            logger.debug(u'Retry: %s', e)
            time.sleep(i * sleep_increment)
        else:
            break

    ret = resp.read().decode(encoding)

    # TODO: return text type instead of different types between PY2 and PY3
    if PY3 and isinstance(ret, bytes):
        ret = str(ret)
    return ret


def login_xunlei(uname, pwd_md5, login_type=TYPE_NORMAL_ACCOUNT):
    pwd = rsa_encode(pwd_md5)
    fake_device_id = hashlib.md5(("%s23333" % pwd_md5).encode('utf-8')).hexdigest()  # just generate a 32bit string
    # sign = div.10?.device_id + md5(sha1(packageName + businessType + md5(a protocolVersion specific GUID)))
    device_sign = "div100.%s%s" % (fake_device_id, hashlib.md5(
        hashlib.sha1(
            ("%scom.xunlei.vip.swjsq68700d1872b772946a6940e4b51827e8af" % fake_device_id).encode('utf-8')
        ).hexdigest().encode('utf-8')
    ).hexdigest())
    _payload = json.dumps({
            "protocolVersion": PROTOCOL_VERSION,  # 109
            "sequenceNo": 1000001,
            "platformVersion": 1,
            "sdkVersion": 177550,  # 177600
            "peerID": MAC,
            "businessType": 68,
            "clientVersion": APP_VERSION,
            "devicesign": device_sign,
            "isCompressed": 0,
            "cmdID": 1,
            "userName": uname.decode('utf-8'),
            "passWord": pwd,
            "loginType": login_type,
            "sessionID": "",
            "verifyKey": "",
            "verifyCode": "",
            "appName": "ANDROID-com.xunlei.vip.swjsq",
            "rsaKey": {
                'e': '{:06X}'.format(rsa_pubexp),
                'n': '{:0256X}'.format(rsa_mod),
            },
            "extensionList": "",
    })
    ct = http_req('https://login.mobile.reg2t.sandai.net:443/', body=_payload, headers=header_xl, encoding='gbk')
    return json.loads(ct)


def renew_xunlei(uid, session):
    _payload = json.dumps({
        "protocolVersion": 108,
        "sequenceNo": 1000000,
        "platformVersion": 1,
        "peerID": MAC,
        "businessType": 68,
        "clientVersion": APP_VERSION,
        "isCompressed": 0,
        "cmdID": 11,
        "userID": uid,
        "sessionID": session,
    })
    ct = http_req('https://login.mobile.reg2t.sandai.net:443/', body=_payload, headers=header_xl, encoding='gbk')
    return json.loads(ct)


def api_url():
    portal = json.loads(http_req("http://api.portal.swjsq.vip.xunlei.com:81/v2/queryportal"))
    if portal['errno']:
        logger.error('get interface_ip failed, using fallback address')
        return FALLBACK_INTERFACE
    return '%s:%s' % (portal['interface_ip'], portal['interface_port'])


def setup():
    global MAC
    global API_URL
    MAC = get_mac(to_splt='').upper() + '004V'
    API_URL = api_url()


def api(cmd, uid, session_id='', extras=''):
    # missing dial_account, (userid), os
    url = 'http://%s/v2/%s?%sclient_type=android-swjsq-%s&peerid=%s&time_and=%d&client_version=androidswjsq-%s&userid=%s&os=android-5.0.1.23SmallRice%s' % (
            API_URL,
            cmd,
            ('sessionid=%s&' % session_id) if session_id else '',
            APP_VERSION,
            MAC,
            time.time() * 1000,
            APP_VERSION,
            uid,
            ('&%s' % extras) if extras else '',
    )
    response = json.loads(http_req(url, headers=header_api))

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

    dt = login_xunlei(uname, pwd, login_type)
    if 'sessionID' not in dt:
        logger.error('login failed, %s', dt['errorDesc'])
        logger.debug('%s', dt)
        os._exit(1)
    elif ('isVip' not in dt or not dt['isVip']) and ('payId' not in dt or dt['payId'] not in [5, 702]):
        # FIX ME: rewrite if with payId
        logger.warn('you are probably not xunlei vip, buy buy buy!')
        logger.debug('isVip:%s payId:%s payName:%s',
                     dt.get('isVip'), dt.get('payId'), dt.get('payName'))
        # os._exit(2)
    logger.info('Login xunlei succeeded')
    if save:
        try:
            os.remove(account_file_plain)
        except:
            pass
        with open(account_file_encrypted, 'w') as f:
            f.write('%s,%s' % (dt['userID'], pwd))

    _ = api('bandwidth', dt['userID'])
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
            api('recover', dt['userID'], dt['sessionID'], extras="dial_account=%s" % _dial_account)
        except KeyboardInterrupt:
            logger.info('Secondary ctrl+c pressed, exiting')
    atexit.register(_atexit_func)
    i = 0
    while True:
        try:
            # i=1~17 keepalive, renew session, i++
            # i=18 (3h) re-upgrade, i:=0
            # i=100 login, i:=36
            if i == 100:
                dt = login_xunlei(uname, pwd, login_type)
                i = 18
            if i % 18 == 0:  # 3h
                logger.info('Initializing upgrade')
                if i:  # not first time
                    api('recover', dt['userID'], dt['sessionID'], extras="dial_account=%s" % _dial_account)
                    time.sleep(5)
                _ = api('upgrade', dt['userID'], dt['sessionID'], extras="user_type=1&dial_account=%s" % _dial_account)
                if not _['errno']:
                    logger.info('Upgrade done: Down %dM, Up %dM', _['bandwidth']['downstream'], _['bandwidth']['upstream'])
                    i = 0
            else:
                _dt_t, _paylod_t = renew_xunlei(dt['userID'], dt['sessionID'])
                if _dt_t['errorCode']:
                    i = 100
                    continue
                _ = api('keepalive', dt['userID'], dt['sessionID'])

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
