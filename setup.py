# vim: set fileencoding=utf-8
from setuptools import setup

from swjsq import __version__


with open('README.rst') as f:
    long_description=f.read()


url = 'https://github.com/timothyqiu/python-swjsq'
download_url = '{0}/archive/{1}.tar.gz'.format(url, __version__)

setup(
    name='swjsq',
    version=__version__,
    packages=['swjsq'],
    entry_points={
        'console_scripts': [
            'swjsq = swjsq.__main__:main',
        ],
    },
    license='MIT',
    description='A command line client for Xunlei SWJSQ (aka. 迅雷快鸟)',
    long_description=long_description,
    author='Timothy Qiu',
    author_email='timothyqiu32@gmail.com',
    url=url,
    download_url=download_url,
    keywords=['xunlei'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Internet',
        'Topic :: Utilities',
    ],
)
