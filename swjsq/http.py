from __future__ import absolute_import
from __future__ import unicode_literals

import logging
import ssl
import sys
import time

from swjsq._compat import text_type
from swjsq._compat import iteritems, range
from swjsq._compat import parse, request
from swjsq._compat import URLError


logger = logging.getLogger(__name__)


def get(url, params=None, body=None, headers=None, max_tries=3):
    '''Get result of HTTP request
    :param url: URL of the target
    :param params: optional query string as dict
    :param body: optional request body as binary type or ascii text
    :param headers: optional request headers as dict
    :param max_tries: total count of failed tries before raising error
    :returns: body of the response as binary type
    :raises URLError: request failed even after retries
    '''
    if params:
        query_string = parse.urlencode(params)
        delimiter = '&' if '?' in url else '?'
        url = '{0}{1}{2}'.format(url, delimiter, query_string)

    req = request.Request(url)
    for k, v in iteritems(headers or {}):
        req.add_header(k, v)
    if isinstance(body, text_type):
        body = body.encode('ascii')

    # Xunlei uses a self-signed certificate
    # which would be rejected by default in Python 2.7.9+
    extra_options = {}
    if sys.version_info >= (2, 7, 9):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        extra_options['context'] = context

    sleep_increment = 2
    for i in range(1, max_tries + 1):
        try:
            resp = request.urlopen(req, data=body, **extra_options)
        except URLError as e:
            logger.debug('#%d request failed: %s', i, e)
            if i == max_tries:
                raise
            time.sleep(i * sleep_increment)
        else:
            break

    return resp.read()
