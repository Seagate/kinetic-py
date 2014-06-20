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

from common import Entry
from common import EntryMetadata
from common import KineticMessageException
import common
import kinetic_pb2 as messages
import logging

LOG = logging.getLogger(__name__)

def _buildMessage(messageType, key, data=None, version='', new_version='',
                  force=False, tag=None, algorithm=None, synchronization=None):
    m = messages.Message()
    m.command.header.messageType = messageType
    if len(key) > common.MAX_KEY_SIZE: raise common.KineticClientException("Key exceeds maximum size of {0} bytes.".format(common.MAX_KEY_SIZE))
    m.command.body.keyValue.key = key
    if data:
        if len(data) > common.MAX_VALUE_SIZE: raise common.KineticClientException("Value exceeds maximum size of {0} bytes.".format(common.MAX_VALUE_SIZE))

    if tag and algorithm:
        m.command.body.keyValue.tag = tag
        m.command.body.keyValue.algorithm = algorithm
    elif messageType == messages.Message.PUT:
        m.command.body.keyValue.tag = 'l337'
        m.command.body.keyValue.algorithm = 1 # nacho: should be change to a value over 100
    if synchronization:
        m.command.body.keyValue.synchronization = synchronization
    if version:
        m.command.body.keyValue.dbVersion = version
    if new_version:
        m.command.body.keyValue.newVersion = new_version
    if force:
        m.command.body.keyValue.force = True

    return (m,data)

class Noop(object):

    @staticmethod
    def build():
        m = messages.Message()
        m.command.header.messageType = messages.Message.NOOP
        return (m, None)

    @staticmethod
    def parse(m, value):
        Entry.fromResponse(m, value)
        return True

    @staticmethod
    def onError(e):
        raise e

class Put(object):

    @staticmethod
    def build(key, data, version="", new_version="", **kwargs):
        return _buildMessage(messages.Message.PUT, key, data, version, new_version, **kwargs)

    @staticmethod
    def parse(m, value):
        Entry.fromResponse(m, value)
        return True

    @staticmethod
    def onError(e):
        raise e

class Get(object):

    @staticmethod
    def build(key):
        return _buildMessage(messages.Message.GET, key)

    @staticmethod
    def parse(m, value):
        try:
            return Entry.fromResponse(m, value)
        except KineticMessageException as e:
            if e.code == 'NOT_FOUND':
                # return None on NOT_FOUND; 'cause dict.get
                return None
            raise

    @staticmethod
    def onError(e):
        if isinstance(e,KineticMessageException):
            if e.code and e.code == 'NOT_FOUND':
                return None
        raise e

class GetMetadata(object):

    @staticmethod
    def build(key):
        (m,_) = _buildMessage(messages.Message.GET, key)
        m.command.body.keyValue.metadataOnly = True
        return (m, None)

    @staticmethod
    def parse(m, value):
        return Get.parse(m, value)

    @staticmethod
    def onError(e):
        return Get.onError(e)

class Delete(object):

    @staticmethod
    def build(key, version="", **kwargs):
        return _buildMessage(messages.Message.DELETE, key, version=version, **kwargs)

    @staticmethod
    def parse(m, value):
        return Entry.fromResponse(m, value) and True

    @staticmethod
    def onError(e):
        if isinstance(e,KineticMessageException):
            if e.code and e.code == 'NOT_FOUND':
                return False
        raise e

class GetNext(object):

    @staticmethod
    def build(key):
        return _buildMessage(messages.Message.GETNEXT, key)

    @staticmethod
    def parse(m, value):
        return Get.parse(m, value)

    @staticmethod
    def onError(e):
        return Get.onError(e)

class GetPrevious(object):

    @staticmethod
    def build(key):
        return _buildMessage(messages.Message.GETPREVIOUS, key)

    @staticmethod
    def parse(m, value):
        return Get.parse(m, value)

    @staticmethod
    def onError(e):
        return Get.onError(e)

class GetKeyRange(object):

    @staticmethod
    def build(startKey, endKey, startKeyInclusive=True, endKeyInclusive=True, maxReturned=200):
        if len(startKey) > common.MAX_KEY_SIZE: raise common.KineticClientException("Start key exceeds maximum size of {0} bytes.".format(common.MAX_KEY_SIZE))
        if len(endKey) > common.MAX_KEY_SIZE: raise common.KineticClientException("End key exceeds maximum size of {0} bytes.".format(common.MAX_KEY_SIZE))

        m = messages.Message()
        m.command.header.messageType = messages.Message.GETKEYRANGE

        kr = m.command.body.range
        kr.startKey = startKey
        kr.endKey = endKey
        kr.startKeyInclusive = startKeyInclusive
        kr.endKeyInclusive = endKeyInclusive
        kr.maxReturned = maxReturned

        return (m, None)

    @staticmethod
    def parse(m, value):
        return [k for k in m.command.body.range.key] # key is actually a set of keys

    @staticmethod
    def onError(e):
        raise e

class P2pPush(object):

    @staticmethod
    def build(keys, hostname='localhost', port=8123, tls=False):
        m = messages.Message()
        m.command.header.messageType = messages.Message.PEER2PEERPUSH
        m.command.body.p2pOperation.peer.hostname = hostname
        m.command.body.p2pOperation.peer.port = port
        m.command.body.p2pOperation.peer.tls = tls

        operations = []
        for k in keys:
            op = None
            if isinstance(k, str):
                op = messages.Message.P2POperation.Operation(key=k)
            elif isinstance(k, common.P2pOp):
                op = messages.Message.P2POperation.Operation(key=k.key)
                if k.version:
                    op.version = k.version
                if k.newKey:
                    op.newKey = k.newKey
                if k.force:
                    op.force = k.force
            operations.append(op)

        m.command.body.p2pOperation.operation.extend(operations)

        return (m, None)

    @staticmethod
    def parse(m, value):
        if (m.command.status.code != messages.Message.Status.SUCCESS):
            raise KineticMessageException(m.command.status)
        return [op for op in m.command.body.p2pOperation.operation]

    @staticmethod
    def onError(e):
        raise e

class P2pPipedPush(object):

    @staticmethod
    def build(keys, targets):
        m = messages.Message()
        m.command.header.messageType = messages.Message.PEER2PEERPUSH
        m.command.body.p2pOperation.peer.hostname = targets[0].hostname
        m.command.body.p2pOperation.peer.port = targets[0].port
        if targets[0].tls:
            m.command.body.p2pOperation.peer.tls = targets[0].tls


        def rec(targets, op):
            if len(targets) > 0:
                target = targets[0]
                op.p2pop.peer.hostname = target.hostname
                op.p2pop.peer.port = target.port
                if target.tls:
                    op.p2pop.peer.tls = target.tls
                innerop = messages.Message.P2POperation.Operation(key=op.key)
                if op.version:
                    innerop.version = op.version
                if op.force:
                    innerop.force = op.force

                rec(targets[1:],innerop)

                op.p2pop.operation.extend([innerop])

        warn_newKey = False
        operations = []
        for k in keys:
            op = None
            if isinstance(k, str):
                op = messages.Message.P2POperation.Operation(key=k)
            elif isinstance(k, common.P2pOp):
                op = messages.Message.P2POperation.Operation(key=k.key)
                if k.version:
                    op.version = k.version
                if k.newKey:
                    warn_newKey = True
                if k.force:
                    op.force = k.force

            rec(targets[1:],op)

            operations.append(op)

        if warn_newKey:
            LOG.warn("Setting new key on piped push is not currently supported.")

        m.command.body.p2pOperation.operation.extend(operations)

        return (m, None)

    @staticmethod
    def parse(m, value):
        if (m.command.status.code != messages.Message.Status.SUCCESS):
            raise KineticMessageException(m.command.status)
        return [op for op in m.command.body.p2pOperation.operation]

    @staticmethod
    def onError(e):
        raise e

class PushKeys(object):

    @staticmethod
    def build(keys, hostname='localhost', port=8123, **kwargs):
        m = messages.Message()
        m.command.header.messageType = messages.Message.PEER2PEERPUSH
        m.command.body.p2pOperation.peer.hostname = hostname
        m.command.body.p2pOperation.peer.port = port

        m.command.body.p2pOperation.operation.extend([
            messages.Message.P2POperation.Operation(key=key) for key in keys
        ])

        return (m, None)

    @staticmethod
    def parse(m, value):
        if (m.command.status.code != messages.Message.Status.SUCCESS):
            raise KineticMessageException(m.command.status)
        return [op for op in m.command.body.p2pOperation.operation]

    @staticmethod
    def onError(e):
        raise e

class Flush(object):

    @staticmethod
    def build():
        m = messages.Message()
        m.command.header.messageType = messages.Message.FLUSHALLDATA

        return (m, None)

    @staticmethod
    def parse(m, value):
        Entry.fromResponse(m, value)
        return None


    @staticmethod
    def onError(e):
        raise e


### Admin Operations ###

class GetLog(object):

    @staticmethod
    def build(types):
        m = messages.Message()
        m.command.header.messageType = messages.Message.GETLOG

        log = m.command.body.getLog
        log.type.extend(types) #type is actually a repeatable field

        return (m, None)

    @staticmethod
    def parse(m, value):
        return m.command.body.getLog

    @staticmethod
    def onError(e):
        raise e

class Setup(object):

    @staticmethod
    def build(**kwargs):
        m = messages.Message()
        m.command.header.messageType = messages.Message.SETUP

        op = m.command.body.setup

        value = None

        if "newClusterVersion" in kwargs:
            op.newClusterVersion = kwargs["newClusterVersion"]

        if "instantSecureErase" in kwargs:
            op.instantSecureErase = kwargs["instantSecureErase"]

        if "pin" in kwargs and kwargs["pin"] is not None:
            op.pin = kwargs["pin"]

        if "setPin" in kwargs:
            op.setPin = kwargs["setPin"]

        if "firmware" in kwargs:
            op.firmwareDownload = True
            value = kwargs['firmware']

        return (m, value)

    @staticmethod
    def parse(m, value):
        Entry.fromResponse(m, value)
        return True

    @staticmethod
    def onError(e):
        raise e
