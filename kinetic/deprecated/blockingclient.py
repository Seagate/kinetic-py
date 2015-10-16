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

from kinetic.baseclient import BaseClient
from kinetic import operations
from kinetic import kinetic_pb2 as messages
from kinetic import batch
import logging

LOG = logging.getLogger(__name__)

class BlockingClient(BaseClient):

    def __init__(self, *args, **kwargs):
        super(BlockingClient, self).__init__(*args, **kwargs)

    def _process(self, op, *args, **kwargs):
        if 'no_ack' in kwargs:
            send_no_ack = True
            del kwargs['no_ack']
        else:
            send_no_ack = False
        header,value = op.build(*args, **kwargs)
        try:
            with self:
                # update header
                self.update_header(header)
                # send message synchronously
                if send_no_ack:
                    self.send_no_ack(header, value)
                else:
                    _, cmd, value = self.send(header, value)
            if send_no_ack:
                return None
            else:
                operations._check_status(cmd)
                return op.parse(cmd, value)
        except Exception as e:
            return op.onError(e)

    def noop(self, *args, **kwargs):
        return self._process(operations.Noop(), *args, **kwargs)

    def put(self, *args, **kwargs):
        return self._process(operations.Put(), *args, **kwargs)

    def get(self, *args, **kwargs):
        return self._process(operations.Get(), *args, **kwargs)

    def getMetadata(self, *args, **kwargs):
        return self._process(operations.GetMetadata(), *args, **kwargs)

    def delete(self, *args, **kwargs):
        return self._process(operations.Delete(), *args, **kwargs)

    def getNext(self, *args, **kwargs):
        return self._process(operations.GetNext(), *args, **kwargs)

    def getPrevious(self, *args, **kwargs):
        return self._process(operations.GetPrevious(), *args, **kwargs)

    def getKeyRange(self, *args, **kwargs):
        return self._process(operations.GetKeyRange(), *args, **kwargs)

    def getRange(self, startKey, endKey, startKeyInclusive=True, endKeyInclusive=True, prefetch=64):
        return KineticRangeIter(self, startKey, endKey, startKeyInclusive, endKeyInclusive, prefetch)

    def push(self, *args, **kwargs):
        return self._process(operations.P2pPush(), *args, **kwargs)

    def pipedPush(self, *args, **kwargs):
        return self._process(operations.P2pPipedPush(), *args, **kwargs)

    def getVersion(self, *args, **kwargs):
        """
            Arguments: key -> The key you are seeking version information for.
            Returns a protobuf object with the version property that determines the pair's current version.
        """
        return self._process(operations.GetVersion(), *args, **kwargs)

    # @RequiresProtocol('2.0.3')
    def flush(self, *args, **kwargs):
        return self._process(operations.Flush(), *args, **kwargs)

    # @RequiresProtocol('3.0.6')
    def begin_batch(self, *args, **kwargs):
        next_batch_id = self.next_batch_id()
        kwargs['batch_id'] = next_batch_id
        self._process(operations.StartBatch(), *args, **kwargs)
        return batch.Batch(self, next_batch_id)

    # @RequiresProtocol('3.0.0')
    def mediaScan(self, *args, **kwargs):
        return self._process(operations.MediaScan(), *args, **kwargs)

    # @RequiresProtocol('3.0.0')
    def mediaOptimize(self, *args, **kwargs):
        return self._process(operations.MediaOptimize(), *args, **kwargs)

    def getLog(self, *args, **kwargs):
        return self._process(operations.GetLog(), *args, **kwargs)
        
    def setClusterVersion(self, *args, **kwargs):
        return self._process(operations.SetClusterVersion(), *args, **kwargs)

    def updateFirmware(self, *args, **kwargs):
        return self._process(operations.UpdateFirmware(), *args, **kwargs)

class KineticRangeIter(object):

    def __init__(self, client, startKey, endKey, startKeyInclusive,endKeyInclusive, prefetch):
        self.keys = []
        self.nextStart = startKey
        self.endKey = endKey
        self.client = client

        self.startKeyInclusive = startKeyInclusive
        self.endKeyInclusive = endKeyInclusive
        self.prefetch = prefetch
        self.prefetchOnNext = True
        self.i = -1

    def __iter__(self):
        return self

    def next(self):

        if self.prefetchOnNext: self.goPrefetchKeys()

        if len(self.keys) > 0 : #if any keys were fetched
            self.i += 1

            if self.i == len(self.keys) - 1: #if we are on the last key prefetched
                self.prefetchOnNext = True #go prefetch again next time an item is asked

                #early exit optimization, avoids extra request to server at the end
                #only works with inclusive end
                nxt = self.keys[self.i]
                if nxt == self.endKey:
                    self.keys = []
                    self.prefetchOnNext = False
                    return self.client.get(nxt)

            return self.client.get(self.keys[self.i])
        else:
            raise StopIteration

    def goPrefetchKeys(self):
        self.prefetchOnNext = False
        self.keys = self.client.getKeyRange(self.nextStart,self.endKey, self.startKeyInclusive, self.endKeyInclusive, self.prefetch)
        l = len(self.keys)

        if l > 0 :
            self.i = -1
            self.nextStart = self.keys[l-1] #move the next start to the last item received
            self.startKeyInclusive = False #from now on the start is exclusive
