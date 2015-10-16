# Copyright 2013-2015 Seagate Technology LLC.
#
# This Source Code Form is subject to the terms of the Mozilla
# Public License, v. 2.0. If a copy of the MPL was not
# distributed with this file, You can obtain one at
# https://mozilla.org/MP:/2.0/.
# 
# This program is distributed in the hope that it will be useful,
# but is provided AS-IS, WITHOUT ANY WARRANTY; including without 
# the implied warranty of MERCHANTABILITY, NON-INFRINGEMENT or 
# FITNESS FOR A PARTICULAR PURPOSE. See the Mozilla Public 
# License for more details.
# See www.openkinetic.org for more project information

#@author: Ignacio Corderi

# Logging
import logging
logging.basicConfig()

# Protocol version
from common import local

protocol_version = local.protocolVersion

from pkg_resources import get_distribution, DistributionNotFound
import os.path

try:
    _dist = get_distribution('kinetic')
    if not __file__.startswith(os.path.join(_dist.location, 'kinetic')):
        # not installed, but there is another version that *is*
        raise DistributionNotFound
except DistributionNotFound:
    __version__ = 'Please install this project with setup.py'
else:
    __version__ = _dist.version

#utils
from utils import buildRange

# clients
from greenclient import Client
from secureclient import SecureClient
from threadedclient import ThreadedClient

# common
from common import KeyRange
from common import Entry
from common import Peer

# exceptions
from common import KineticMessageException

# backward compatibility alliases
AsyncClient = Client
from kinetic.deprecated.adminclient import AdminClient
from kinetic import greenclient as client
# Fake old asyncclient module 
class AsyncClientCompat(object):
    AsyncClient = Client   
asyncclient = AsyncClientCompat()