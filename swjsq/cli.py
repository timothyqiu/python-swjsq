from __future__ import absolute_import
from __future__ import unicode_literals

import getopt
import hashlib
import logging
import os
import sys

from swjsq._compat import PY3
from swjsq.core import APIError
from swjsq.core import fast_d1ck, setup
from swjsq.core import TYPE_NORMAL_ACCOUNT, TYPE_NUM_ACCOUNT


class NoCredentialsError(RuntimeError):
    pass


class Arguments(object):
    def __init__(self):
        self.gen_sh = True
        self.gen_ipk = True
        self.account_file_encrypted = '.swjsq.account'
        self.account_file_plain = 'swjsq.account.txt'


def show_usage():
    options = [
        ('-h, --help', 'show this help message and exit'),
        ('--no-sh', 'skip script generation'),
        ('--no-ipk', 'skip ipk generation'),
    ]

    print('usage: {} [OPTIONS]'.format(sys.argv[0]))
    print()
    print('options:')
    for opt, description in options:
        print('  {}\t{}'.format(opt, description))


def parse_args():
    try:
        long_opts = ['help', 'no-sh', 'no-ipk']
        opts, args = getopt.getopt(sys.argv[1:], 'h', long_opts)
    except getopt.GetoptError as err:
        print(err)
        show_usage()
        sys.exit(2)

    args = Arguments()

    for o, a in opts:
        if o in ('-h', '--help'):
            show_usage()
            sys.exit()
        elif o == '--no-sh':
            args.gen_sh = False
        elif o == '--no-ipk':
            args.gen_ipk = False
        else:
            assert False, 'Unhandled option'

    return args


def setup_logging():
    fh = logging.FileHandler('swjsq.log')
    fh.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)

    FMT = '%(asctime)s %(levelname)s %(message)s'
    DATE_FMT = '%Y-%m-%d %H:%M:%S'
    formatter = logging.Formatter(FMT, DATE_FMT)
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)

    logger = logging.getLogger()

    logger.addHandler(fh)
    logger.addHandler(ch)

    logger.setLevel(logging.DEBUG)


def main():
    try:
        # Arguments
        args = parse_args()

        # Setups
        setup_logging()
        setup()

        # Option defaults
        save_encrypted = True
        login_type = TYPE_NORMAL_ACCOUNT

        # Load credentials
        if os.path.exists(args.account_file_plain):
            with open(args.account_file_plain) as f:
                uid, pwd = f.read().strip().split(',')
            if PY3K:
                pwd = pwd.encode('utf-8')
            pwd_md5 = hashlib.md5(pwd).hexdigest()
        elif os.path.exists(args.account_file_encrypted):
            with open(args.account_file_encrypted) as f:
                uid, pwd_md5 = f.read().strip().split(',')
            save_encrypted = False
            login_type = TYPE_NUM_ACCOUNT
        else:
            uid = os.getenv('XUNLEI_UID')
            pwd = os.getenv('XUNLEI_PASSWD')
            if not uid or not pwd:
                raise NoCredentialsError()
            pwd_md5 = hashlib.md5(pwd).hexdigest()

        # Routine
        fast_d1ck(uid, pwd_md5, login_type,
                  save=save_encrypted,
                  gen_sh=args.gen_sh, gen_ipk=args.gen_ipk,
                  account_file_encrypted=args.account_file_encrypted,
                  account_file_plain=args.account_file_plain)
    except NoCredentialsError:
        logging.error('No credentials provided.')
    except APIError as e:
        logging.error('API Error %s: (%d) %s',
                      e.command, e.errno, e.message or 'Unknown')
    except KeyboardInterrupt:
        logging.info('Stopping')


if __name__ == '__main__':
    main()
