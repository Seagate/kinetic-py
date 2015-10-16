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

import common
import logging
import operations

LOG = logging.getLogger(__name__)

class Batch(object):
    """
    The Batch class is used for grouping a set of put and/or delete operations
    so that all are committed as one unit or all of them are canceled
    (aborted).

    A Batch object is obtained by calling :func:`~baseclient.BaseClient.begin_batch`.
    Once all relevant put and delete calls are made, 'commit' should be called
    to apply all of the operations, or 'abort' to cancel (abort) them.

    A Batch object cannot be reused for subsequent batches. After the 'commit'
    or 'abort' has completed successfully, a new Batch object should be
    requested for the next batch operation.
    """


    def __init__(self, client, batch_id):
        """
        Initialize instance with Kinetic client and batch identifier.

        Args:
            client: the Kinetic client to use for batch operations.
            batch_id: the batch identifier to be used for client connection.
        """
        self._client = client
        self._batch_id = batch_id
        self._op_count = 0
        self._batch_completed = False   # to detect attempted reuse
  
    def put(self, *args, **kwargs):
        """
        Put an entry within the batch operation.

        The command is not committed until :func:`~batch.Batch.commit` is
        called and returns successfully. If a version is specified, it must
        match the one stored in the persistent storage. Otherwise, a
        KineticException is raised.

        Args:

        Kwargs:

        Raises:
            KineticException: if any internal error occurs.
        """
        if self._batch_completed:
            raise common.BatchCompletedException()

        self._op_count += 1        
        kwargs['batch_id'] = self._batch_id
        kwargs['no_ack'] = True
        
        self._client.put(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """
        Delete the entry associated with the specified key.

        The command is not committed until :func:`~batch.Batch.commit` is
        called and returns successfully. If a version is specified, it must
        match the one stored in persistent storage. Otherwise, a
        KineticException is raised.

        Args:

        Kwargs:

        Raises:
            KineticException: if any internal error occurs.
        """
        if self._batch_completed:
            raise common.BatchCompletedException()

        self._op_count += 1
        kwargs['batch_id'] = self._batch_id
        kwargs['no_ack'] = True
        
        self._client.delete(*args, **kwargs)

    def commit(self, *args, **kwargs):
        """
        Commit the current batch operation.

        When this call returned successfully, all the commands performed in the
        current batch are executed and committed to store successfully.

        Raises:
            KineticException: if any internal error occurred. The batch may
                or may not be committed. If committed, all commands are
                committed. Otherwise, no messages are committed.
            BatchAbortedException: if the commit failed. No messages within
                the batch were committed to the store. 
        """
        if self._batch_completed:
            raise common.BatchCompletedException()

        kwargs['batch_id'] = self._batch_id
        kwargs['batch_op_count'] = self._op_count
        try:
            self._client._process(operations.EndBatch(), *args, **kwargs)
            self._batch_completed = True
        except BatchAbortedException:
            self._batch_completed = True
            raise

    def abort(self, *args, **kwargs):
        """
        Abort the current batch operation.

        When this call returned successfully, all the commands queued in the
        current batch are aborted. Resources related to the current batch are
        cleaned up and released.

        Raises:
            KineticException: if any internal error occurred.
        """
        if self._batch_completed:
            raise common.BatchCompletedException()

        kwargs['batch_id'] = self._batch_id
        self._client._process(operations.AbortBatch(), *args, **kwargs)
        self._batch_completed = True

    def is_completed(self):
        """
        Return boolean indicating whether the batch is completed (either
        committed or aborted)
        """
        return self._batch_completed

    def __len__(self):
        """
        Return the number of operations that have been included in the batch.
        """
        return self._op_count

