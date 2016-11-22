from __future__ import absolute_import
from __future__ import unicode_literals

import os
import re


def get_mac(nic=None):
    '''Gets MAC address of specific device.
    :param nic: device name as string, or None if any device is ok
    :returns: MAC address as colon separated string, or None on failure
    '''
    if os.name == 'nt':
        cmd = 'ipconfig /all'
        splt = '-'
    elif os.name == "posix":
        if os.path.exists('/usr/bin/ip') or os.path.exists('/bin/ip'):
            if nic:
                cmd = 'ip link show dev {0}'.format(nic)
            else:
                # Unfortunately, loopback interface always comes first
                # So we have to grep it out
                cmd = 'ip link show up | grep -v loopback'
        else:
            cmd = 'ifconfig {0}'.format(nic or '-a')
        splt = ':'
    else:
        return None

    try:
        output = os.popen(cmd).read()
        if not output:
            return None

        raw_pattern = r'((?:[0-9A-Fa-f]{{2}}{splt}){{5}}[0-9A-Fa-f]{{2}})'
        pattern = raw_pattern.format(splt=splt)
        matches = re.findall(pattern, output)
        if not matches:
            return None

        return matches[0].replace(splt, ':')
    except Exception:
        pass

    return None
