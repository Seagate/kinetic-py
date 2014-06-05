# Copyright (C) 2014 Seagate Technology.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

#@author: Robert Cope

import unittest

from kinetic import Client
from kinetic import AdminClient
from kinetic import KineticMessageException
from base import BaseTestCase
from kinetic import common

class KineticBaseAdminTestCase(BaseTestCase):
    def setUp(self):
        super(KineticBaseAdminTestCase, self).setUp()
        self.adminClient = AdminClient("localhost", self.port)
        self.adminClient.connect()
        self.client = Client("localhost", self.port)
        self.client.connect()
        self.client.put('TestKey1', 'TestValue')

    def tearDown(self):
        self.adminClient.close()
        self.client.close()

    def test_setSecurity(self):
        acl = common.ACL()
        domain = common.Domain()
        domain.setRoles([0])  # Set the domain to just read.
        domain.setTlsRequired(False)
        acl.setIdentity(100)
        acl.setDomains([domain])
        self.adminClient.setSecurity([acl])
        #Now that we've set security, let's see if user 100 can only read.
        newClient = Client("localhost", self.port, identity=100)
        newClient.get('TestKey1')  # Should be OK.
        args = ('TestKey2', 'TestValue')
        self.assertRaises(KineticMessageException, newClient.put, *args)

