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

#@author: Paul Dardeau

import unittest

from kinetic import Client
from kinetic import batch
from kinetic import common
from base import BaseTestCase


class BatchTestCase(BaseTestCase):

    def setUp(self):
        super(BatchTestCase, self).setUp()
        self.client = Client(self.host, self.port)
        self.client.connect()
        self._create_new_batch()

    def _create_new_batch(self):
        self.batch = self.client.begin_batch()
        if self.batch is None:
            raise common.KineticException("unable to create batch")

    def test_batch_initial_state(self):
        is_completed = self.batch.is_completed()
        op_count = len(self.batch)
        self.batch.abort()
        self.assertFalse(is_completed)
        self.assertEquals(op_count, 0)

    def test_batch_operation_count(self):
        key1 = self.buildKey('test_batch_operation_count_1')
        key2 = self.buildKey('test_batch_operation_count_2')
        key3 = self.buildKey('test_batch_operation_count_3')
        self.batch.put(key1, '')
        self.assertEquals(len(self.batch), 1)
        self.batch.put(key2, '')
        self.assertEquals(len(self.batch), 2)
        self.batch.delete(key3)
        self.assertEquals(len(self.batch), 3)

        self.batch.abort()

    def test_batch_commit_is_completed(self):
        key1 = self.buildKey('test_batch_commit_is_completed_1')
        key2 = self.buildKey('test_batch_commit_is_completed_2')
        self.assertFalse(self.batch.is_completed())
        self.batch.put(key1, '')
        self.batch.delete(key2)
        self.assertFalse(self.batch.is_completed())
        self.batch.commit()
        self.assertTrue(self.batch.is_completed())

    def test_batch_abort_is_completed(self):
        key1 = self.buildKey('test_batch_abort_is_completed_1')
        key2 = self.buildKey('test_batch_abort_is_completed_2')
        self.assertFalse(self.batch.is_completed())
        self.batch.put(key1, '')
        self.batch.delete(key2)
        self.assertFalse(self.batch.is_completed())
        self.batch.abort()
        self.assertTrue(self.batch.is_completed())

    def test_empty_batch_abort(self):
        # abort with no operations in batch
        self.assertRaises(common.BatchAbortedException, self.batch.abort())

    def test_batch_abort(self):
        key = self.buildKey('key_should_not_exist')
        self.batch.put(key, '')
        self.batch.abort()
        self.assertEqual(self.client.get(key), None)

    def test_empty_batch_commit(self):
        # commit with no operations in batch
        self.assertRaises(common.BatchAbortedException, self.batch.commit())

    def test_batch_commit(self):
        key = self.buildKey('key_should_exist')
        self.batch.put(key, '')
        self.batch.commit()
        self.assertIsNotNone(self.client.get(key))

    def test_batch_delete_commit(self):
        # put an entry
        key = self.buildKey('test_batch_delete_commit')
        self.client.put(key, '')

        self.batch.delete(key)
        self.batch.commit()
        self.assertEqual(self.client.get(key), None)

    def test_batch_delete_abort(self):
        # put an entry
        key = self.buildKey('test_batch_delete_abort')
        self.client.put(key, '')

        self.batch.delete(key)
        self.batch.abort()
        self.assertIsNotNone(self.client.get(key))

    def test_batch_put_commit(self):
        key = self.buildKey('test_batch_put_commit')
        self.batch.put(key, '')
        self.batch.commit()
        self.assertIsNotNone(self.client.get(key))

    def test_batch_put_abort(self):
        key = self.buildKey('test_batch_put_abort')
        self.batch.put(key, '')
        self.batch.abort()
        self.assertEqual(self.client.get(key), None)

    def test_batch_multiple_put_commit(self):
        key1 = self.buildKey('test_batch_multiple_put_commit_1')
        key2 = self.buildKey('test_batch_multiple_put_commit_2')
        self.batch.put(key1, '')
        self.batch.put(key2, '')
        self.batch.commit()
        self.assertIsNotNone(self.client.get(key1))
        self.assertIsNotNone(self.client.get(key2))

    def test_batch_multiple_put_abort(self):
        key1 = self.buildKey('test_batch_multiple_put_abort_1')
        key2 = self.buildKey('test_batch_multiple_put_abort_2')
        self.batch.put(key1, '')
        self.batch.put(key2, '')
        self.batch.abort()
        self.assertEqual(self.client.get(key1), None)
        self.assertEqual(self.client.get(key2), None)

    def test_batch_multiple_delete_commit(self):
        key1 = self.buildKey('test_batch_multiple_delete_commit_1')
        key2 = self.buildKey('test_batch_multiple_delete_commit_2')
        self.client.put(key1, '')
        self.client.put(key2, '')

        self.batch.delete(key1)
        self.batch.delete(key2)
        self.batch.commit()
        self.assertEqual(self.client.get(key1), None)
        self.assertEqual(self.client.get(key2), None)

    def test_batch_multiple_delete_abort(self):
        key1 = self.buildKey('test_batch_multiple_delete_abort_1')
        key2 = self.buildKey('test_batch_multiple_delete_abort_2')
        self.client.put(key1, '')
        self.client.put(key2, '')

        self.batch.delete(key1)
        self.batch.delete(key2)
        self.batch.abort()
        self.assertIsNotNone(self.client.get(key1))
        self.assertIsNotNone(self.client.get(key2))

    def test_batch_mixed_commit(self):
        key1 = self.buildKey('test_batch_mixed_commit_1')
        key2 = self.buildKey('test_batch_mixed_commit_2')
        self.client.put(key1, '')

        self.batch.delete(key1)
        self.batch.put(key2, '')
        self.batch.commit()
        self.assertEqual(self.client.get(key1), None)
        self.assertIsNotNone(self.client.get(key2))

    def test_batch_mixed_abort(self):
        key1 = self.buildKey('test_batch_mixed_abort_1')
        key2 = self.buildKey('test_batch_mixed_abort_2')
        self.client.put(key1, '')
        
        self.batch.delete(key1)
        self.batch.put(key2, '')
        self.batch.abort()
        self.assertIsNotNone(self.client.get(key1))
        self.assertEqual(self.client.get(key2), None)

    def test_batch_reuse_after_commit(self):
        key1 = self.buildKey('test_batch_reuse_after_commit_1')
        key2 = self.buildKey('test_batch_reuse_after_commit_2')
        self.batch.put(key1, '')
        self.batch.commit()

        args = (key2, '')
        self.assertRaises(common.BatchCompletedException, self.batch.put, *args)

    def test_batch_reuse_after_abort(self):
        key = self.buildKey('test_batch_reuse_after_abort')
        self.batch.put(key, '')
        self.batch.abort()

        args = (key)
        self.assertRaises(common.BatchCompletedException, self.batch.delete, *args)


if __name__ == '__main__':
    unittest.main()

