from __future__ import absolute_import

import functools
import itertools
import sys


PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3

if PY2:
    import __builtin__

    text_type = __builtin__.unicode
    binary_type = str

    iterbytes = functools.partial(itertools.imap, ord)

    def iteritems(d, **kwargs):
        return d.iteritems(**kwargs)

    range = __builtin__.xrange
    long = __builtin__.long

    import urllib
    import urllib2
    parse = urllib
    request = urllib2
    URLError = urllib2.URLError
else:
    import builtins

    text_type = str
    binary_type = bytes

    iterbytes = iter

    def iteritems(d, **kwargs):
        return d.items(**kwargs)

    range = builtins.range
    long = builtins.int

    import urllib.error
    import urllib.parse
    import urllib.request
    parse = urllib.parse
    request = urllib.request
    URLError = urllib.error.URLError
