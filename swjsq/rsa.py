from __future__ import absolute_import
from __future__ import unicode_literals

import binascii
import functools
import logging

from swjsq._compat import long, binary_type, iterbytes


logger = logging.getLogger(__name__)


def _cache_recent(f):
    '''Cache the most recent argument/result'''
    data = {
        'args': None,
        'result': None,
    }

    @functools.wraps(f)
    def wrapped(*args):
        if data.get('args') != args:
            data['args'] = args
            data['result'] = f(*args)
        return data['result']
    return wrapped


@_cache_recent
def rsa_encrypt(pubexp, mod, payload):
    '''RSA encrypt
    :param pubexp: RSA pubexp as hex string
    :param mod: RSA mod as hex string
    :param payload: binary data to be encrypted
    :returns: cipher as hex string
    :raises TypeError: if payload is not binary type
    '''
    if not isinstance(payload, binary_type):
        raise TypeError('payload should be of binary type')

    pubexp = long(pubexp, 16)
    mod = long(mod, 16)

    try:
        return _rsa_encrypt_pgcrypto(pubexp, mod, payload)
    except ImportError:
        logger.debug('pycrypto not found, using manual rsa')
        return _rsa_encrypt_python(pubexp, mod, payload)


def _rsa_encrypt_pgcrypto(pubexp, mod, payload):
    from Crypto.PublicKey import RSA

    rsa = RSA.construct((mod, pubexp))
    cipher = rsa.encrypt(payload, None)[0]

    return binascii.hexlify(cipher).decode('ascii')


# https://github.com/mengskysama/XunLeiCrystalMinesMakeDie/blob/master/run.py
def _rsa_encrypt_python(pubexp, mod, payload):
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

    cipher = modpow(binary_to_int(payload), pubexp, mod)
    return '{0:0256X}'.format(cipher)
