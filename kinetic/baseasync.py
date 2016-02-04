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
#
# See www.openkinetic.org for more project information
#

#@author: Ignacio Corderi

import deprecated
from common import Entry
import common

import logging
import kinetic_pb2 as messages
import operations
import threading

LOG = logging.getLogger(__name__)

class BaseAsync(deprecated.BlockingClient):

    def __init__(self, *args, **kwargs):
        super(BaseAsync, self).__init__(*args, socket_timeout=None, **kwargs)
        self.unhandledException = lambda e: LOG.warn("Unhandled client exception. " + str(e))
        self.faulted = False
        self.error = None
        # private attributes
        self._pending = dict()
         # start background workers
        self._initialize()


    def _initialize(self): pass


    def _raise(self, e, onError=None):
        if onError:
            try:
                onError(e)
            except Exception as ue:
               e = ue
               onError = None

        if onError == None:
            try:
                self.unhandledException(e)
            except Exception as e:
                LOG.warn("Unhandled exception when handling unhandled exception. " + str(e))
                # just swallow it (the other option is faulting)


    def dispatch(self, fn, *args, **kwargs):
        fn(*args,**kwargs)


    def _fault_client(self, e):
        self.error = e
        self.faulted = True
        LOG.error("Connection {0} faulted. {1}".format(self,e))
        for _,onError,_ in self._pending.itervalues():
            try:
                onError(e)
            except Exception as e2:
                LOG.error("Unhandled exception on callers code when reporting internal error. {0}".format(e2))
        self._pending = {}


    def _async_recv(self):
        if self.faulted:
            raise common.ConnectionFaulted("Connection {0} is faulted. Can't receive message when connection is on a faulted state.".format(self))

        try:
            m, resp, value = self.network_recv()
            if m.authType == messages.Message.UNSOLICITEDSTATUS:
                if self.on_unsolicited:
                    try:
                        self.dispatch(self.on_unsolicited,resp.status)
                    except Exception as e:
                        self._raise(e)
                else:
                    LOG.warn('Unsolicited status %s received but nobody listening. %s' % (resp.status.code, resp.status.statusMessage))
            else:
                seq = resp.header.ackSequence
                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.debug("Received message with ackSequence={0} on connection {1}.".format(seq,self))
                onSuccess,_,arg = self._pending[seq]
                del self._pending[seq]
                try:
                    self.dispatch(onSuccess, m, resp, value, arg)
                except Exception as e:
                    self._raise(e)
        except Exception as e:
            if not self.isConnected:
                raise common.ConnectionClosed("Connection closed by client.")
            else:
                self._fault_client(e)


    ### Override BaseClient methods

    def send(self, command, value):
        done = threading.Event()
        class Dummy : pass
        d = Dummy()
        d.error = None
        d.result = None

        def innerSuccess(m, resp, value):
            d.result = (m, resp, value)
            done.set()

        def innerError(e):
            d.error = e
            done.set()

        self.sendAsync(command, value, innerSuccess, innerError)

        done.wait() # TODO(Nacho): should be add a default timeout?
        if d.error: raise d.error
        return d.result

    ###


    def sendAsync(self, command, value, onSuccess, onError, no_ack=False):
        if self.faulted: # TODO(Nacho): should we fault through onError on fault or bow up on the callers face?
            self._raise(common.ConnectionFaulted("Can't send message when connection is on a faulted state."), onError)
            return #skip the rest

        # fail fast on NotConnected
        if not self.isConnected: # TODO(Nacho): should we fault through onError on fault or bow up on the callers face?
            self._raise(common.NotConnected("Not connected."), onError)
            return #skip the rest

        def innerSuccess(m, response, value, *args, **kwargs):
            try:
                operations._check_status(response)
                onSuccess(m, response, value)
            except Exception as ex:
                onError(ex)
         
        def setClusterversionCallback(m, response, value, version):
            try:
                operations._check_status(response)
                onSuccess(m, response, value)
                self.cluster_version = version

            except Exception as ex:
                onError(ex)
        # get sequence
        self.update_header(command)

        if not no_ack:
            # add callback to pending dictionary
            self._pending[command.header.sequence] = (innerSuccess, onError)
            if command.body.setup.newClusterVersion:
               self._pending[command.header.sequence] = (setClusterversionCallback, onError, command.body.setup.newClusterVersion)
            else:
               self._pending[command.header.sequence] = (innerSuccess, onError, None)
        # transmit
        self.network_send(command, value)


    def _process(self, op, *args, **kwargs):
        if not self.isConnected: raise common.NotConnected("Must call connect() before sending operations.")
        return super(BaseAsync, self)._process(op, *args, **kwargs)


    def _processAsync(self, op, onSuccess, onError, *args, **kwargs):
        if not self.isConnected: raise common.NotConnected("Must call connect() before sending operations.")

        def innerSuccess(m, header, value):
            onSuccess(op.parse(header, value))

        def innerError(e):
            try:
                v = op.onError(e)
                onSuccess(v)
            except Exception as e2:
                onError(e2)

        if 'no_ack' in kwargs:
            send_no_ack = True
            del kwargs['no_ack']
        else:
            send_no_ack = False

        header, value = op.build(*args, **kwargs)
        self.sendAsync(header, value, innerSuccess, innerError, send_no_ack)


    def putAsync(self, onSuccess, onError, *args, **kwargs):
        self._processAsync(operations.Put(), onSuccess, onError, *args, **kwargs)

    def getAsync(self, onSuccess, onError, *args, **kwargs):
        self._processAsync(operations.Get(), onSuccess, onError, *args, **kwargs)

    def getMetadataAsync(self, onSuccess, onError, *args, **kwargs):
        self._processAsync(operations.GetMetadata(), onSuccess, onError, *args, **kwargs)

    def deleteAsync(self, onSuccess, onError, *args, **kwargs):
        self._processAsync(operations.Delete(), onSuccess, onError, *args, **kwargs)

    def getNextAsync(self, onSuccess, onError, *args, **kwargs):
        self._processAsync(operations.GetNext(), onSuccess, onError, *args, **kwargs)

    def getPreviousAsync(self, onSuccess, onError, *args, **kwargs):
        self._processAsync(operations.GetPrevious(), onSuccess, onError, *args, **kwargs)

    def getKeyRangeAsync(self, onSuccess, onError, *args, **kwargs):
        self._processAsync(operations.GetKeyRange(), onSuccess, onError, *args, **kwargs)

    def getVersionAsync(self, onSuccess, onError, *args, **kwargs):
        self._processAsync(operations.GetVersion(), onSuccess, onError, *args, **kwargs)

    def flushAsync(self, onSuccess, onError, *args, **kwargs):
        self._processAsync(operations.Flush(), onSuccess, onError, *args, **kwargs)

    def noopAsync(self, onSuccess, onError, *args, **kwargs):
        self._processAsync(operations.Noop(), onSuccess, onError, *args, **kwargs)

    def mediaScanAsync(self, onSuccess, onError, *args, **kwargs):
        self._processAsync(operations.MediaScan(), onSuccess, onError, *args, **kwargs)

    def mediaOptimizeAsync(self, onSuccess, onError, *args, **kwargs):
        self._processAsync(operations.MediaOptimize(), onSuccess, onError, *args, **kwargs)

    def getLogAsync(self, onSuccess, onError, *args, **kwargs):
        self._processAsync(operations.GetLog(), onSuccess, onError, *args, **kwargs)

