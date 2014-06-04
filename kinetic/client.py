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

from baseclient import BaseClient
import operations
import kinetic_pb2 as messages
import logging

LOG = logging.getLogger(__name__)

class Client(BaseClient):

    def __init__(self, *args, **kwargs):
        super(Client, self).__init__(*args, **kwargs)

    def _process(self, op, *args, **kwargs):
        header,value = op.build(*args, **kwargs)
        try:
            with self:
                # update header
                self.update_header(header)
                # send message synchronously
                header, value = self.send(header, value)
            return op.parse(header, value)
        except Exception as e:
            return op.onError(e)

    def noop(self, *args, **kwargs):
        return self._process(operations.Noop, *args, **kwargs)

    def put(self, *args, **kwargs):
        return self._process(operations.Put, *args, **kwargs)

    def get(self, *args, **kwargs):
        return self._process(operations.Get, *args, **kwargs)

    def getMetadata(self, *args, **kwargs):
        return self._process(operations.GetMetadata, *args, **kwargs)

    def getVersion(self, *args, **kwargs):
        """
            Arguments: key -> The key you are seeking version information for.
            Returns a protobuf object with the version property that determines the pair's current version.
        """
        return self._process(operations.GetVersion, *args, **kwargs)

    def delete(self, *args, **kwargs):
        return self._process(operations.Delete, *args, **kwargs)

    def getNext(self, *args, **kwargs):
        return self._process(operations.GetNext, *args, **kwargs)

    def getPrevious(self, *args, **kwargs):
        return self._process(operations.GetPrevious, *args, **kwargs)

    def getKeyRange(self, *args, **kwargs):
        return self._process(operations.GetKeyRange, *args, **kwargs)

    def getRange(self, startKey, endKey, startKeyInclusive=True, endKeyInclusive=True, prefetch=64):
        return KineticRangeIter(self, startKey, endKey, startKeyInclusive, endKeyInclusive, prefetch)

    def push(self, *args, **kwargs):
        return self._process(operations.P2pPush, *args, **kwargs)

    def pipedPush(self, *args, **kwargs):
        return self._process(operations.P2pPipedPush, *args, **kwargs)

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
