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

import kinetic_pb2 as messages
import eventlet
import os

MAX_KEY_SIZE = 4*1024
MAX_VALUE_SIZE = 1024*1024

DEFAULT_CONNECT_TIMEOUT = 0.1
DEFAULT_SOCKET_TIMEOUT = 5
DEFAULT_CHUNK_SIZE = 64*1024

# Env variables
try: 
    KINETIC_CONNECT_TIMEOUT = float(os.environ.get('KINETIC_CONNECT_TIMEOUT', DEFAULT_CONNECT_TIMEOUT))
except:
    KINETIC_CONNECT_TIMEOUT = DEFAULT_CONNECT_TIMEOUT
    
local = messages.Local()

class DeferedValue():

    def __init__(self, socket, value_ln):
        self.socket = socket
        self.length = value_ln
        self._evt = eventlet.event.Event()

    def set(self):
        self._evt.send()

    def wait(self):
        self._evt.wait()


class Entry(object):

    #RPC: Note, you could build this as a class method, if you wanted the fromMessage to build
    #the subclass on a fromMessage. I suspect you always want to generate Entry objects,
    #in which case, a staticmethod is appropriate as a factory.
    @staticmethod
    def fromMessage(command, value):
        if not command: return None
        return Entry(command.body.keyValue.key, value, EntryMetadata.fromMessage(command))

    @staticmethod
    def fromResponse(response, value):
        if (response.status.code == messages.Command.Status.SUCCESS):
            return Entry.fromMessage(response, value)
        elif (response.status.code == messages.Command.Status.NOT_FOUND):
            return None
        else:
            raise KineticClientException("Invalid response status, can' build entry from response.")

    def __init__(self, key, value, metadata=None):
        self.key = key
        self.value = value
        self.metadata = metadata or EntryMetadata()

    def __str__(self):
        if self.value:
            return "{key}={value}".format(key=self.key, value=self.value)
        else:
            return self.key


class EntryMetadata(object):

    @staticmethod
    def fromMessage(command):
        if not command: return None
        return EntryMetadata(command.body.keyValue.dbVersion, command.body.keyValue.tag,
                             command.body.keyValue.algorithm)

    def __init__(self, version=None, tag=None, algorithm=None):
        self.version = version
        self.tag = tag
        self.algorithm = algorithm

    def __str__(self):
        return self.version or "None"


class KeyRange(object):

    def __init__(self, startKey, endKey, startKeyInclusive=True,
                 endKeyInclusive=True):
        self.startKey = startKey
        self.endKey = endKey
        self.startKeyInclusive = startKeyInclusive
        self.endKeyInclusive = endKeyInclusive

    def getFrom(self, client, max=1024):
        return client.getKeyRange(self.startKey, self.endKey, self.startKeyInclusive, self.endKeyInclusive, max)


class P2pOp(object):

    def __init__(self, key, version=None, newKey=None, force=None):
        self.key = key
        self.version = version
        self.newKey = newKey
        self.force = force


class Peer(object):

    def __init__(self, hostname='localhost', port=8123, tls=None):
        self.hostname = hostname
        self.port = port
        self.tls = tls

# Exceptions

class KineticException(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

class KineticClientException(KineticException):
    pass

class NotConnected(KineticClientException):
    pass

class AlreadyConnected(KineticClientException):
    pass

class ServerDisconnect(KineticClientException):
    pass

class ConnectionFaulted(KineticClientException):
    pass

class ConnectionClosed(KineticClientException):
    pass

class KineticMessageException(KineticException):

    def __init__(self, status):
        self.value = status.statusMessage
        self.status = status
        self.code = self.status.DESCRIPTOR.enum_types[0]\
                .values_by_number[self.status.code].name

    def __str__(self):
        return self.code + (': %s' % self.value if self.value else '')

class ClusterVersionFailureException(KineticMessageException):

    def __init__(self, status, cluster_version):
        super(ClusterVersionFailureException, self).__init__(status)
        self.cluster_version = cluster_version

class BatchAbortedException(KineticException):
    def __init__(self, value):
        super(BatchAbortedException, self).__init__(value)
        self.failed_operation_index = -1

class BatchCompletedException(KineticClientException):
    def __init__(self):
        super(BatchCompletedException, self).__init__('batch completed. no more operations are permitted within this batch.')

class HmacAlgorithms:
    INVALID_HMAC_ALGORITHM = -1 # Must come first, so default is invalid
    HmacSHA1 = 1 # this is the default


class Priority:
    NORMAL = 5
    LOWEST = 1
    LOWER = 3
    HIGHER = 7
    HIGHEST = 9


class ACL(object):

    DEFAULT_IDENTITY=1
    DEFAULT_KEY = "asdfasdf"

    def __init__(self, identity=DEFAULT_IDENTITY, key=DEFAULT_KEY, algorithm=HmacAlgorithms.HmacSHA1, max_priority=Priority.NORMAL):
        self.identity = identity
        self.key = key
        self.hmacAlgorithm = algorithm
        self.domains = set()
        self.max_priority = max_priority


class Domain(object):
    """
        Domain object, which corresponds to the domain object in the Java client,
        and is the Scope object in the protobuf.
    """
    def __init__(self, roles=None, tlsRequried=False, offset=None, value=None):
        if roles:
            self.roles = set(roles)
        else:
            self.roles = set()
        self.tlsRequired = tlsRequried
        self.offset = offset
        self.value = value


class Roles(object):
    """
        Role enumeration, which is the same thing as the permission field for each
        scope in the protobuf ACL list.
    """
    READ = 0
    WRITE = 1
    DELETE = 2
    RANGE = 3
    SETUP = 4
    P2POP = 5
    GETLOG = 7
    SECURITY = 8

    @classmethod
    def all(cls):
        """
            Return the set of all possible roles.
        """
        return [cls.READ, cls.WRITE, cls.DELETE, cls.RANGE, cls.SETUP, cls.P2POP, cls.GETLOG, cls.SECURITY]


class Synchronization:
    INVALID_SYNCHRONIZATION = -1
    WRITETHROUGH = 1 # Sync
    WRITEBACK = 2 # Async
    FLUSH = 3


class IntegrityAlgorithms:
    SHA1 = 1
    SHA2 = 2
    SHA3 = 3
    CRC32 = 4
    CRC64 = 5
    # 6-99 are reserverd.
    # 100-inf are private algorithms


class LogTypes:
    INVALID_TYPE = -1
    UTILIZATIONS = 0
    TEMPERATURES = 1
    CAPACITIES = 2
    CONFIGURATION = 3
    STATISTICS = 4
    MESSAGES = 5
    LIMITS = 6
    DEVICE = 7

    @classmethod
    def all(cls):
        """
            LogTypes.all takes no arguments and returns a list of all valid log magic numbers (from the protobuf definition)
            that can be retrieved using the AdminClient .getLog method. Log types avaiable are: (0-> Utilizations, 1-> Temperatures,
            2->Drive Capacity, 3-> Drive Configuration, 4->Drive usage statistics, and 5-> Drive messages). This can be passed as
            the sole argument to the AdminClient.getLog function.
        """
        return [cls.UTILIZATIONS, cls.TEMPERATURES, cls.CAPACITIES, cls.CONFIGURATION, cls.STATISTICS, cls.MESSAGES,
                cls.LIMITS]
