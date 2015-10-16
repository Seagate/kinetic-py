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
import thread
import threading
import Queue

from baseasync import BaseAsync
import common

LOG = logging.getLogger(__name__)

class ThreadedClient(BaseAsync):

    def __init__(self, *args, **kwargs):
        super(ThreadedClient, self).__init__(*args, **kwargs)
        self.queue = Queue.Queue()
#         if 'pool' in kwargs:
#             self.pool = kwards['pool']
#         else:
#             self.pool=None
        self.pool = None

    def connect(self):
        super(ThreadedClient, self).connect()
        self.thread = threading.Thread(target = self._run)
        self.thread.daemon = True
        self.thread.start()

        self.writer_thread = threading.Thread(target = self._writer)
        self.writer_thread.daemon = True
        self.writer_thread.start()

    def dispatch(self, fn, *args, **kwargs):
        if self.pool:
            self.pool.submit(fn,*args,**kwargs)
        else:
            fn(*args,**kwargs)

    def close(self):
        self.dispatch(super(ThreadedClient, self).close)
        self.queue.put(None)
        self.writer_thread.join()
        self.thread.join()

    def sendAsync(self, header, value, onSuccess, onError, no_ack=False):
        self.queue.put((header, value, onSuccess, onError, no_ack))

    def _writer(self):
        while self.isConnected and not self.faulted:
            try:
                item =  self.queue.get()
                if item:
                    (header, value, onSuccess, onError) = item
                    super(ThreadedClient, self).sendAsync(header, value, onSuccess, onError)
                self.queue.task_done()
            except common.ConnectionFaulted: pass
            except common.ConnectionClosed: pass
            except Exception as ex:
                self._fault_client(ex)

    def _run(self):
        while self.isConnected and not self.faulted:
            try:
                self._async_recv()
            except common.ConnectionFaulted: pass
            except common.ConnectionClosed: pass
            except Exception as ex:
                self._fault_client(ex)
