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

#@author: Clayg

import unittest

from kinetic import operations
from kinetic import baseclient

from base import MultiSimulatorTestCase

class P2PTestCase(MultiSimulatorTestCase):

    def test_p2p_push(self):
        source, target = self.client_map.values()
        key = self.buildKey('test')
        source.put(key, 'value')
        self.assertEqual(target.get(key), None)
        resp = source.push([key],target.hostname, target.port)
        for op in resp:
            self.assertEquals(op.key, key)
            self.assertEquals(op.status.code, op.status.SUCCESS)
        entry = target.get(key)
        self.assertEquals(entry.value, 'value')


if __name__ == '__main__':
    unittest.main()
