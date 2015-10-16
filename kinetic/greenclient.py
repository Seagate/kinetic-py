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

import logging
import eventlet
from eventlet.queue import Queue

from eventlet.green import socket
from eventlet.green.ssl import GreenSSLSocket

import baseasync
import common

LOG = logging.getLogger(__name__)

DEFAULT_POOL_SIZE = 100
DEFAULT_MAX_QUEUE_SIZE = 20
MAX_PENDING = 10

class Client(baseasync.BaseAsync):

    def __init__(self, *args, **kwargs):
        super(Client, self).__init__(*args, **kwargs)
        self.pool = eventlet.greenpool.GreenPool(DEFAULT_POOL_SIZE)
        self.reader_thread = None
        self.writer_thread = None
        self.queue = Queue(DEFAULT_MAX_QUEUE_SIZE)
        self.max_pending = MAX_PENDING
        self.closing = False

    def build_socket(self, family=socket.AF_INET):
        return socket.socket(family)
            
    def wrap_secure_socket(self, s, ssl_version):
        return GreenSSLSocket(s, ssl_version=ssl_version)
        
    def connect(self):
        super(Client, self).connect()
        self.closing = False
        self.reader_thread = eventlet.greenthread.spawn(self._reader_run)
        self.writer_thread = eventlet.greenthread.spawn(self._writer_run)

    def dispatch(self, fn, *args, **kwargs):
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug("Dispatching: Pending {0}".format(len(self._pending)))
        self.pool.spawn_n(fn,*args, **kwargs)

    def shutdown(self):
        self.closing = True
        if len(self._pending) + self.queue.qsize() == 0:
            self._end_close()

    def close(self):
        self.shutdown()
        self.wait()

    def _end_close(self):
        self.writer_thread.kill()
        self.reader_thread.kill()

        super(Client, self).close()

        self.writer_thread = None
        self.reader_thread = None

    def sendAsync(self, header, value, onSuccess, onError, no_ack=False):
        if self.closing:
            raise common.ConnectionClosed("Client is closing, can't queue more operations.")

        if self.faulted:
            self._raise(common.ConnectionFaulted("Can't send message when connection is on a faulted state."), onError)
            return #skip the rest

        # fail fast on NotConnected
        if not self.isConnected:
            self._raise(common.NotConnected("Not connected."), onError)
            return #skip the rest

        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug("Queue: {0}".format(self.queue.qsize()))
        self.queue.put((header, value, onSuccess, onError, no_ack))
        eventlet.sleep(0)

    def wait(self):
        self.queue.join()

    def send(self, header, value):
        done = eventlet.event.Event()
        class Dummy : pass
        d = Dummy()
        d.error = None
        d.result = None

        def innerSuccess(m, r, value):
            d.result = (m, r, value)
            done.send()

        def innerError(e):
            d.error = e
            done.send()

        self.sendAsync(header, value, innerSuccess, innerError)

        done.wait() # TODO(Nacho): should be add a default timeout?
        if d.error: raise d.error
        return d.result

    def _writer_run(self):
        while self.isConnected and not self.faulted:
            try:
                while len(self._pending) > self.max_pending:
                    eventlet.sleep(0)
                (header, value, onSuccess, onError, no_ack) = self.queue.get()
                super(Client, self).sendAsync(header, value, onSuccess, onError, no_ack)
            except common.ConnectionFaulted: pass
            except common.ConnectionClosed: pass
            except Exception as ex:
                self._fault_client(ex)

            # Yield execution, don't starve the reader
            eventlet.sleep(0)

    def _reader_run(self):
        while self.isConnected and not self.faulted:
            try:
                self._async_recv()
                self.queue.task_done()
                if self.closing  and len(self._pending) + self.queue.qsize() == 0:
                    self._end_close()
            except common.ConnectionFaulted: pass
            except Exception as ex:
                self._fault_client(ex)

            # Yield execution, don't starve the writer
            # eventlet.sleep(0)

            #eventlet.sleep()
