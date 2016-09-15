from __future__ import absolute_import

import functools
import itertools
import sys


PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3

if PY2:
    text_type = unicode
    binary_type = str

    iterbytes = functools.partial(itertools.imap, ord)

    def iteritems(d, **kwargs):
        return d.iteritems(**kwargs)

    import __builtin__
    range = __builtin__.xrange

    import urllib2
    request = urllib2
    URLError = urllib2.URLError
else:
    text_type = str
    binary_type = bytes

    iterbytes = iter

    def iteritems(d, **kwargs):
        return d.items(**kwargs)

    import builtins
    range = builtins.range

    import urllib.request
    import urllib.error
    request = urllib.request
    URLError = urllib.error.URLError
