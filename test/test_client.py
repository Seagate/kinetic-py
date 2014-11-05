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

#@author: Ignacio Corderi

import unittest

from kinetic import Client
from kinetic import KeyRange
from kinetic import KineticMessageException
from base import BaseTestCase
from kinetic import common
from kinetic.baseclient import BaseClient


class KineticBasicTestCase(BaseTestCase):

    def setUp(self):
        super(KineticBasicTestCase, self).setUp()
        self.client = Client(self.host, self.port)

    def test_command_put(self):
        self.client.put(self.buildKey(0),"test_value")

    def test_put_no_version_overwrite(self):
        key = self.buildKey()
        self.client.put(key, 'value')
        self.assertEquals('value', self.client.get(key).value)
        self.client.put(key, 'value1')
        self.assertEquals('value1', self.client.get(key).value)

    def test_put_no_overwrite_with_version(self):
        key = self.buildKey()
        self.client.put(key, 'value', new_version='0')
        self.assertEquals('value', self.client.get(key).value)
        # can't set it w/o any version
        args = (key, 'value1')
        self.assertRaises(KineticMessageException, self.client.put, *args)
        # can't set new version
        kwargs = dict(new_version='1')
        self.assertRaises(KineticMessageException, self.client.put,
                          *args, **kwargs)
        # still has orig value
        self.assertEquals('value', self.client.get(key).value)
        # can overwrite with correct version
        self.client.put(key, 'value1', version='0')
        self.assertEquals('value1', self.client.get(key).value)

    def test_put_force_version_overwrite(self):
        key = self.buildKey()
        self.client.put(key, 'value', new_version='0')
        self.assertEquals('value', self.client.get(key).value)
        self.client.put(key, 'value1', force=True)
        self.assertEquals('value1', self.client.get(key).value)

    def test_command_get(self):
        self.client.get(self.buildKey(0))

    def test_command_getMetadata(self):
        self.client.getMetadata(self.buildKey(0))

    def test_command_getNext(self):
        self.client.put(self.buildKey(1),"test_value_1")
        self.client.put(self.buildKey(2),"test_value_2")
        self.client.getNext(self.buildKey(1))

    def test_command_getPrevious(self):
        self.client.put(self.buildKey(1),"test_value_1")
        self.client.put(self.buildKey(2),"test_value_2")
        self.client.getPrevious(self.buildKey(2))

    def test_command_delete(self):
        self.client.delete(self.buildKey(0))

    def test_delete_existing(self):
        self.client.put(self.buildKey(0),"test_value")
        x = self.client.delete(self.buildKey(0))
        self.assertTrue(x)

    def test_delete_non_existing(self):
        x = self.client.delete(self.baseKey + "none_existing_test_key")
        self.assertFalse(x)
        #selft.assertRaises(KeyNotFound)

    def test_put_getMetadata(self):
        value = "test_value"
        self.client.put(self.buildKey(0),value,new_version="20")
        x = self.client.getMetadata(self.buildKey(0))
        self.assertEqual(x.metadata.version, "20")

    def test_put_get(self):
        value = "test_value"
        self.client.put(self.buildKey(0),value)
        x = self.client.get(self.buildKey(0))
        self.assertEqual(value, x.value)

    def test_put_get_withVersion(self):
        value = "test_value"
        self.client.put(self.buildKey(0),value, new_version="1")
        x = self.client.get(self.buildKey(0))
        self.assertEqual(x.value, value)
        self.assertEqual(x.metadata.version, "1")

    def test_delete_nonExistent(self):
        deleted = self.client.delete(self.buildKey(0))
        self.assertEqual(deleted, False)

    def test_put_delete_incorrectVersion(self):
        value = "test_value"
        self.client.put(self.buildKey(0),value, new_version="1")
        with self.assertRaises(KineticMessageException):
            self.client.delete(self.buildKey(0), "2")
        x = self.client.get(self.buildKey(0))
        self.assertEqual(x.value, value)

    def test_put_delete_get_withVersion(self):
        self.client.put(self.buildKey(0),"test_value", new_version="1")
        deleted = self.client.delete(self.buildKey(0), "1")
        self.assertEqual(deleted, True)
        x = self.client.get(self.buildKey(0))
        self.assertEqual(x, None)

    def test_put_delete_get(self):
        self.client.put(self.buildKey(0),"test_value")
        deleted = self.client.delete(self.buildKey(0))
        self.assertEqual(deleted, True)
        x = self.client.get(self.buildKey(0))
        self.assertEqual(x, None)

    def test_getNext(self):
        self.client.put(self.buildKey(1),"test_value_1")
        yKey = self.buildKey(2)
        yValue = "test_value_2"
        self.client.put(yKey, yValue)
        x = self.client.getNext(self.buildKey(1))
        self.assertEqual(x.key, yKey)
        self.assertEqual(x.value, yValue)

    def test_getPrevious(self):
        xKey = self.buildKey(1)
        xValue = "test_value_1"
        self.client.put(xKey,xValue)
        self.client.put(self.buildKey(2),"test_value_2")
        y = self.client.getPrevious(self.buildKey(2))
        self.assertEqual(xKey, y.key)
        self.assertEqual(xValue, y.value)

    def setUpRangeTests(self):
        self.client.put(self.buildKey(1),"test_value_1")
        self.client.put(self.buildKey(2),"test_value_2")
        self.client.put(self.buildKey(3),"test_value_3")
        self.client.put(self.buildKey(4),"test_value_4")
        self.client.put(self.buildKey(5),"test_value_5")
        self.client.put(self.buildKey(6),"test_value_6")
        self.client.put(self.buildKey(7),"test_value_7")
        self.client.put(self.buildKey(8),"test_value_8")
        self.client.put(self.buildKey(9),"test_value_9")

    def test_getKeyRange_default(self):
        self.setUpRangeTests()
        expected = [self.buildKey(3),self.buildKey(4),self.buildKey(5),self.buildKey(6)]
        xs = self.client.getKeyRange(self.buildKey(3),self.buildKey(6))
        self.assertEqual(xs, expected)

    def test_getKeyRange_empty(self):
        self.setUpRangeTests()
        xs = self.client.getKeyRange(self.baseKey + "nonexisting_test_key_1",self.baseKey + "nonexisting_test_key_99")
        self.assertEqual(xs, [])

    def test_getKeyRange_exclusiveStart(self):
        self.setUpRangeTests()
        expected = [self.buildKey(4),self.buildKey(5),self.buildKey(6)]
        xs = self.client.getKeyRange(self.buildKey(3),self.buildKey(6),False,True)
        self.assertEqual(xs, expected)

    def test_getKeyRange_exclusiveEnd(self):
        self.setUpRangeTests()
        expected = [self.buildKey(3),self.buildKey(4),self.buildKey(5)]
        xs = self.client.getKeyRange(self.buildKey(3),self.buildKey(6),True,False)
        self.assertEqual(xs, expected)

    def test_getKeyRange_bounded(self):
        self.setUpRangeTests()
        expected = [self.buildKey(4),self.buildKey(5)]
        xs = self.client.getKeyRange(self.buildKey(4),self.buildKey(9),maxReturned=2)
        self.assertEqual(xs, expected)

    def test_getRange_default(self):
        self.setUpRangeTests()
        expectedKeys = [self.buildKey(1),self.buildKey(2),self.buildKey(3),self.buildKey(4),self.buildKey(5),self.buildKey(6)]
        expectedValues = ["test_value_1","test_value_2","test_value_3","test_value_4","test_value_5","test_value_6"]
        xs = self.client.getRange(self.buildKey(1),self.buildKey(6))
        i = 0
        for x in xs :
            self.assertEqual(x.key, expectedKeys[i])
            self.assertEqual(x.value, expectedValues[i])
            i += 1

    def test_value_too_big(self):
        self.assertRaises(common.KineticClientException, self.client.put, self.buildKey(1), 'x' * (common.MAX_VALUE_SIZE + 1))

    def test_key_too_big(self):
        self.assertRaises(common.KineticClientException, self.client.put, self.buildKey('x' * (common.MAX_KEY_SIZE + 1)), 'y')

    def test_noop(self):
        self.client.noop()

    def test_get_socket_options(self):
        dict_sock_options = self.client.get_socket_options()
        self.assertIsNotNone(dict_sock_options, "socket options should not be None")
        if self.client.isConnected:
            self.assertTrue(BaseClient.OPT_TCP_NODELAY in dict_sock_options)
            self.assertTrue(BaseClient.OPT_IP_TOS in dict_sock_options)
            self.assertTrue(BaseClient.OPT_SO_RCVBUF in dict_sock_options)
            self.assertTrue(BaseClient.OPT_SO_SNDBUF in dict_sock_options)

    def test_set_socket_options(self):
        val_tcp_nodelay = 0
        val_ip_tos = 3
        val_so_sndbuf = 16384
        val_so_rcvbuf = 8192

        set_options = {}
        set_options[BaseClient.OPT_TCP_NODELAY] = val_tcp_nodelay
        set_options[BaseClient.OPT_IP_TOS] = val_ip_tos
        set_options[BaseClient.OPT_SO_SNDBUF] = val_so_sndbuf
        set_options[BaseClient.OPT_SO_RCVBUF] = val_so_rcvbuf

        client = Client(self.host, self.port, socket_options=set_options)
        client.connect()
        get_options = client.get_socket_options()
        self.assertIsNotNone(get_options)
        self.assertEquals(get_options[BaseClient.OPT_TCP_NODELAY], val_tcp_nodelay)
        self.assertEquals(get_options[BaseClient.OPT_IP_TOS], val_ip_tos)
        self.assertGreaterEqual(get_options[BaseClient.OPT_SO_SNDBUF], val_so_sndbuf)
        self.assertGreaterEqual(get_options[BaseClient.OPT_SO_RCVBUF], val_so_rcvbuf)

if __name__ == '__main__':
    unittest.main()
