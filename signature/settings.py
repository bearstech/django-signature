"""
From django-pki - Copyright (C) 2010 Daniel Kerwin <django-pki@linuxaddicted.de>

http://github.com/dkerwin/django-pki

This program and entire repository is free software; you can
redistribute it and/or modify it under the terms of the GNU
General Public License as published by the Free Software
Foundation; either version 2 of the License, or any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; If not, see <http://www.gnu.org/licenses/>.
"""


##############################################################
## PKI settings
##############################################################

import os
from django.conf import settings

PKI_APP_DIR = os.path.abspath(os.path.dirname(__file__))

# base directory for pki storage (should be writable), defaults to PKI_APP_DIR/PKI
PKI_DIR = getattr(settings, 'PKI_DIR', os.path.join(PKI_APP_DIR, 'PKI'))

# path to openssl executable
PKI_OPENSSL_BIN = getattr(settings, 'PKI_OPENSSL_BIN', '/usr/bin/openssl')

# path to generated openssl.conf
PKI_OPENSSL_CONF = getattr(settings, 'PKI_OPENSSL_CONF',
                           os.path.join(PKI_APP_DIR, 'openssl.cnf'))

# template name for openssl.conf
PKI_OPENSSL_TEMPLATE = getattr(settings, 'PKI_OPENSSL_TEMPLATE', 'pki/openssl.conf.in')

# jquery url (defaults to pki/jquery-1.3.2.min.js)
JQUERY_URL = getattr(settings, 'JQUERY_URL', 'pki/jquery-1.3.2.min.js')

# logging (TODO: syslog, handlers and formatters)
PKI_LOG = getattr(settings, 'PKI_LOG', os.path.join(PKI_DIR, 'pki.log'))
PKI_LOGLEVEL = getattr(settings, 'PKI_LOGLEVEL', 'debug')

# get other settings directly from settings.py:
ADMIN_MEDIA_PREFIX = getattr(settings, 'ADMIN_MEDIA_PREFIX')

# media url
MEDIA_URL = getattr(settings, 'MEDIA_URL')

# base url: without trailing slash. Leave empty if mounted on /
PKI_BASE_URL = getattr(settings, 'PKI_BASE_URL', '')

# self_signed_serial; The serial a self signed CA starts with. Set to 0 or 0x0 for a random number
PKI_SELF_SIGNED_SERIAL = getattr(settings, 'PKI_SELF_SIGNED_SERIAL', 0x0)

# default_country: The default country selected (2-letter country code)
PKI_DEFAULT_COUNTRY = getattr(settings, 'PKI_DEFAULT_COUNTRY', 'DE')

