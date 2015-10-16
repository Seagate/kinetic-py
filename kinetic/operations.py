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

from common import Entry
from common import EntryMetadata
from common import KineticMessageException
import common
import kinetic_pb2 as messages
import logging
import hashlib

LOG = logging.getLogger(__name__)


def _check_status(command):
    if (command.status.code == messages.Command.Status.SUCCESS):
        return
    elif(command.status.code == messages.Command.Status.VERSION_FAILURE):
        raise common.ClusterVersionFailureException(command.status, command.header.clusterVersion)
    else:
        raise KineticMessageException(command.status)


def _buildMessage(m, messageType, key, data=None, version='', new_version='',
                  force=False, tag=None, algorithm=None, synchronization=None):
    m.header.messageType = messageType
    if len(key) > common.MAX_KEY_SIZE: raise common.KineticClientException("Key exceeds maximum size of {0} bytes.".format(common.MAX_KEY_SIZE))
    m.body.keyValue.key = key
    if data:
        if len(data) > common.MAX_VALUE_SIZE: raise common.KineticClientException("Value exceeds maximum size of {0} bytes.".format(common.MAX_VALUE_SIZE))

    if tag and algorithm:
        m.body.keyValue.tag = tag
        m.body.keyValue.algorithm = algorithm
    elif messageType == messages.Command.PUT:
        # check the data type first
        if data and (isinstance(data, str) or isinstance(data, bytes) or isinstance(data, bytearray)):
            # default to sha1
            m.body.keyValue.tag = hashlib.sha1(data).digest()
            m.body.keyValue.algorithm = common.IntegrityAlgorithms.SHA1
        else:
            m.body.keyValue.tag = 'l337'

    if (messageType == messages.Command.PUT or messageType == messages.Command.DELETE) and synchronization == None:
        synchronization = common.Synchronization.WRITEBACK

    if synchronization:
        m.body.keyValue.synchronization = synchronization
    if version:
        m.body.keyValue.dbVersion = version
    if new_version:
        m.body.keyValue.newVersion = new_version
    if force:
        m.body.keyValue.force = True

    return (m,data)


class BaseOperation(object):

    def __init__(self):
        self.m = None

    def _build(): pass

    def build(self, *args, **kwargs):
        self.m = messages.Command()

        if 'timeout' in kwargs:
            self.m.header.timeout = kwargs['timeout']
            del kwargs['timeout']

        if 'priority' in kwargs:
            self.m.header.priority = kwargs['priority']
            del kwargs['priority']

        if 'early_exit' in kwargs:
            self.m.header.earlyExit = kwargs['early_exit']
            del kwargs['early_exit']

        if 'time_quanta' in kwargs:
            self.m.header.TimeQuanta = kwargs['time_quanta']
            del kwargs['time_quanta']

        if 'batch_id' in kwargs:
            self.m.header.batchID = kwargs['batch_id']
            del kwargs['batch_id']

        return self._build(*args, **kwargs)

    def parse(self, m, value):
        return

    def onError(self, e):
        raise e

class Noop(BaseOperation):

    def _build(self):
        m = self.m
        m.header.messageType = messages.Command.NOOP
        return (m, None)


class Put(BaseOperation):

    def _build(self, key, data, version="", new_version="", **kwargs):
        return _buildMessage(self.m, messages.Command.PUT, key, data, version, new_version, **kwargs)


class Get(BaseOperation):

    def _build(self, key):
        return _buildMessage(self.m, messages.Command.GET, key)

    def parse(self, m, value):
        return Entry.fromResponse(m, value)

    def onError(self, e):
        if isinstance(e,KineticMessageException):
            if e.code and e.code == 'NOT_FOUND':
                return None
        raise e


class GetMetadata(Get):

    def _build(self, key):
        (m,_) = _buildMessage(self.m, messages.Command.GET, key)
        m.body.keyValue.metadataOnly = True
        return (m, None)


class Delete(BaseOperation):

    def _build(self, key, version="", **kwargs):
        return _buildMessage(self.m, messages.Command.DELETE, key, version=version, **kwargs)

    def parse(self, m, value):
        return True

    def onError(self, e):
        if isinstance(e,KineticMessageException):
            if e.code and e.code == 'NOT_FOUND':
                return False
        raise e


class GetNext(Get):

    def _build(self, key):
        return _buildMessage(self.m, messages.Command.GETNEXT, key)


class GetPrevious(Get):

    def _build(self, key):
        return _buildMessage(self.m, messages.Command.GETPREVIOUS, key)


class GetKeyRange(BaseOperation):

    def _build(self, startKey=None, endKey=None, startKeyInclusive=True, endKeyInclusive=True, 
        maxReturned=200, reverse=False):
        if not startKey:
            startKey = ''
        if not endKey:
            endKey = '\xFF' * common.MAX_KEY_SIZE

        if len(startKey) > common.MAX_KEY_SIZE: raise common.KineticClientException("Start key exceeds maximum size of {0} bytes.".format(common.MAX_KEY_SIZE))
        if len(endKey) > common.MAX_KEY_SIZE: raise common.KineticClientException("End key exceeds maximum size of {0} bytes.".format(common.MAX_KEY_SIZE))

        m = self.m
        m.header.messageType = messages.Command.GETKEYRANGE

        kr = m.body.range
        kr.startKey = startKey
        kr.endKey = endKey
        kr.startKeyInclusive = startKeyInclusive
        kr.endKeyInclusive = endKeyInclusive
        kr.maxReturned = maxReturned
        kr.reverse = reverse

        return (m, None)

    def parse(self, m, value):
        return [k for k in m.body.range.keys] # key is actually a set of keys


class GetVersion(BaseOperation):

    def _build(self, key):
        (m,_) = _buildMessage(self.m, messages.Command.GETVERSION, key)
        return (m, None)

    def parse(self, m, value):
        return m.body.keyValue.dbVersion

    def onError(self, e):
        if isinstance(e,KineticMessageException):
            if e.code and e.code == 'NOT_FOUND':
                return None
        raise e

class P2pPush(BaseOperation):

    def _build(self, keys, hostname='localhost', port=8123, tls=False):
        m = self.m
        m.header.messageType = messages.Command.PEER2PEERPUSH
        m.body.p2pOperation.peer.hostname = hostname
        m.body.p2pOperation.peer.port = port
        m.body.p2pOperation.peer.tls = tls

        operations = []
        for k in keys:
            op = None
            if isinstance(k, str):
                op = messages.Command.P2POperation.Operation(key=k)
            elif isinstance(k, common.P2pOp):
                op = messages.Command.P2POperation.Operation(key=k.key)
                if k.version:
                    op.version = k.version
                if k.newKey:
                    op.newKey = k.newKey
                if k.force:
                    op.force = k.force
            operations.append(op)

        m.body.p2pOperation.operation.extend(operations)

        return (m, None)

    def parse(self, m, value):
        return [op for op in m.body.p2pOperation.operation]


class P2pPipedPush(BaseOperation):

    def _build(self, keys, targets):
        m = self.m
        m.header.messageType = messages.Command.PEER2PEERPUSH
        m.body.p2pOperation.peer.hostname = targets[0].hostname
        m.body.p2pOperation.peer.port = targets[0].port
        if targets[0].tls:
            m.body.p2pOperation.peer.tls = targets[0].tls


        def rec(targets, op):
            if len(targets) > 0:
                target = targets[0]
                op.p2pop.peer.hostname = target.hostname
                op.p2pop.peer.port = target.port
                if target.tls:
                    op.p2pop.peer.tls = target.tls
                innerop = messages.Command.P2POperation.Operation(key=op.key)
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
                op = messages.Command.P2POperation.Operation(key=k)
            elif isinstance(k, common.P2pOp):
                op = messages.Command.P2POperation.Operation(key=k.key)
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

        m.body.p2pOperation.operation.extend(operations)

        return (m, None)

    def parse(self, m, value):
        return [op for op in m.body.p2pOperation.operation]


class StartBatch(BaseOperation):

    def _build(self):
        self.m.header.messageType = messages.Command.START_BATCH
        return (self.m, None)


class EndBatch(BaseOperation):

    def _build(self, **kwargs):
        # batch_op_count
        (m,_) = _buildMessage(self.m, messages.Command.END_BATCH, '')
        m.body.batch.count = kwargs['batch_op_count']
        del kwargs['batch_op_count']
        return (m, None)

    def onError(self, e):
        if isinstance(e,common.KineticException):
            if e.code and e.code == 'INVALID_BATCH':
                return common.BatchAbortedException(e.value)
        raise e

class AbortBatch(BaseOperation):

    def _build(self):
        self.m.header.messageType = messages.Command.ABORT_BATCH
        return (self.m, None)


class Flush(BaseOperation):

    def _build(self):
        m = self.m
        m.header.messageType = messages.Command.FLUSHALLDATA

        return (m, None)


### Admin Operations ###

class GetLog(BaseOperation):

    def _build(self, types, device=None):
        m = self.m
        m.header.messageType = messages.Command.GETLOG

        log = m.body.getLog
        log.types.extend(types) #type is actually a repeatable field

        if device:
            log.device.name = device

        return (m, None)

    def parse(self, m, value):
        if value:
            return (m.body.getLog, value)
        else:
            return m.body.getLog

    def onError(self, e):
        if isinstance(e,KineticMessageException):
            if e.code and e.code == 'NOT_FOUND':
                return None
        raise e


######################
#  Setup operations  #
######################
class SetClusterVersion(BaseOperation):

    def _build(self, version):
        m = self.m
        m.header.messageType = messages.Command.SETUP

        m.body.setup.newClusterVersion = version

        return (m, None)


class UpdateFirmware(BaseOperation):

    def _build(self, firmware):
        m = self.m
        m.header.messageType = messages.Command.SETUP

        m.body.setup.firmwareDownload = True

        return (m, firmware)


########################
#  Security operations #
########################
class Security(BaseOperation):

    def _build(self, acls=None, old_erase_pin=None, new_erase_pin=None, old_lock_pin=None, new_lock_pin=None):
        m = self.m
        m.header.messageType = messages.Command.SECURITY
        op = m.body.security

        if acls:
            proto_acls = []

            for acl in acls:
                proto_acl = messages.Command.Security.ACL(identity=acl.identity,
                                                          key=acl.key,
                                                          hmacAlgorithm=acl.hmacAlgorithm,
                                                          maxPriority=acl.max_priority)

                proto_domains = []

                for domain in acl.domains:
                    proto_d = messages.Command.Security.ACL.Scope(
                                TlsRequired=domain.tlsRequired)

                    proto_d.permission.extend(domain.roles)

                    if domain.offset:
                        proto_d.offset = domain.offset
                    if domain.value:
                        proto_d.value = domain.value

                    proto_domains.append(proto_d)

                proto_acl.scope.extend(proto_domains)
                proto_acls.append(proto_acl)

            op.acl.extend(proto_acls)

        if not old_lock_pin is None: op.oldLockPIN = old_lock_pin
        if not new_lock_pin is None: op.newLockPIN = new_lock_pin
        if not old_erase_pin is None: op.oldErasePIN = old_erase_pin
        if not new_erase_pin is None: op.newErasePIN = new_erase_pin

        return (m, None)


class SetACL(Security):

    def _build(self, acls):
        return super(SetACL, self)._build(acls=acls)


class SetErasePin(Security):

    def _build(self, new_pin, old_pin):
        return super(SetErasePin, self)._build(new_erase_pin=new_pin, old_erase_pin=old_pin)


class SetLockPin(Security):

    def _build(self, new_pin, old_pin):
        return super(SetLockPin, self)._build(new_lock_pin=new_pin, old_lock_pin=old_pin)


###########################
#  Background operations  #
###########################
class MediaScan(BaseOperation):

    def _build(self, startKey=None, endKey=None, startKeyInclusive=True, endKeyInclusive=True, maxReturned=200):
        if not startKey:
            startKey = ''
        if not endKey:
            endKey = '\xFF' * common.MAX_KEY_SIZE

        if len(startKey) > common.MAX_KEY_SIZE: raise common.KineticClientException("Start key exceeds maximum size of {0} bytes.".format(common.MAX_KEY_SIZE))
        if len(endKey) > common.MAX_KEY_SIZE: raise common.KineticClientException("End key exceeds maximum size of {0} bytes.".format(common.MAX_KEY_SIZE))

        m = self.m

        m.header.messageType = messages.Command.MEDIASCAN

        kr = m.body.range
        kr.startKey = startKey
        kr.endKey = endKey
        kr.startKeyInclusive = startKeyInclusive
        kr.endKeyInclusive = endKeyInclusive
        kr.maxReturned = maxReturned

        return (m, None)

    def parse(self, m, value):
        r = m.body.range
        return ([k for k in r.keys], r.endKey)


class MediaOptimize(BaseOperation):

    def _build(self, startKey=None, endKey=None, startKeyInclusive=True, endKeyInclusive=True, maxReturned=200):
        if not startKey:
            startKey = ''
        if not endKey:
            endKey = '\xFF' * common.MAX_KEY_SIZE

        if len(startKey) > common.MAX_KEY_SIZE: raise common.KineticClientException("Start key exceeds maximum size of {0} bytes.".format(common.MAX_KEY_SIZE))
        if len(endKey) > common.MAX_KEY_SIZE: raise common.KineticClientException("End key exceeds maximum size of {0} bytes.".format(common.MAX_KEY_SIZE))

        m = self.m

        m.header.messageType = messages.Command.MEDIAOPTIMIZE

        kr = m.body.range
        kr.startKey = startKey
        kr.endKey = endKey
        kr.startKeyInclusive = startKeyInclusive
        kr.endKeyInclusive = endKeyInclusive
        kr.maxReturned = maxReturned

        return (m, None)

    def parse(self, m, value):
        r = m.body.range
        return ([k for k in r.keys], r.endKey)


####################
#  Pin operations  #
####################
class BasePinOperation(BaseOperation):

    def __init__(self):
        super(BaseOperation, self).__init__()
        self.pin_op_type = None

    def _build(self):
        m = self.m
        m.header.messageType = messages.Command.PINOP
        m.body.pinOp.pinOpType = self.pin_op_type
        return (m, None)

class UnlockDevice(BasePinOperation):

    def __init__(self):
        super(UnlockDevice, self).__init__()
        self.pin_op_type = messages.Command.PinOperation.UNLOCK_PINOP


class LockDevice(BasePinOperation):

    def __init__(self):
        super(LockDevice, self).__init__()
        self.pin_op_type = messages.Command.PinOperation.LOCK_PINOP


class EraseDevice(BasePinOperation):

    def __init__(self):
        super(EraseDevice, self).__init__()
        self.pin_op_type = messages.Command.PinOperation.ERASE_PINOP


class SecureEraseDevice(BasePinOperation):

    def __init__(self):
        super(SecureEraseDevice, self).__init__()
        self.pin_op_type = messages.Command.PinOperation.SECURE_ERASE_PINOP
