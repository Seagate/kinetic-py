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

import kinetic_pb2 as messages

MAX_KEY_SIZE = 4*1024
MAX_VALUE_SIZE = 1024*1024

class Entry(object):

    #RPC: Note, you could build this as a class method, if you wanted the fromMessage to build
    #the subclass on a fromMessage. I suspect you always want to generate Entry objects,
    #in which case, a staticmethod is appropriate as a factory.
    @staticmethod
    def fromMessage(header, value):
        if not header: return None
        return Entry(header.command.body.keyValue.key, value, EntryMetadata.fromMessage(header))

    @staticmethod
    def fromResponse(header, value):
        if (header.command.status.code == messages.Message.Status.SUCCESS):
            return Entry.fromMessage(header, value)
        elif (header.command.status.code == messages.Message.Status.NOT_FOUND):
            return None
        else:
            raise KineticMessageException(header.command.status)

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
    def fromMessage(msg):
        if not msg: return None
        return EntryMetadata(msg.command.body.keyValue.dbVersion, msg.command.body.keyValue.tag,
                             msg.command.body.keyValue.algorithm)

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

class ACL(object):
    #TODO: Implement offset and value restrictions, and make tlsRequired able to be set for each and every permission.
    DEFAULT_KEY = "asdfasdf"
    def __init__(self):
        self.identity = 1
        self.key = self.DEFAULT_KEY
        self.hmacAlgorithm = IntegrityAlgorithms.SHA1
        self.domains = set()

    def setDomains(self, domains):
        for d in domains:
            try:
                assert(type(d) is Domain)
            except AssertionError:
                raise TypeError('Each domain must be of type kinetic.common.Domain!')
        self.domains = set(domains)

    def setIdentity(self, newIdent):
        try:
            assert(type(newIdent) is int or type(newIdent) is long)
        except AssertionError:
            raise ValueError('New identity must be an int or long!')
        self.identity = newIdent

    def setKey(self, newKey):
        try:
            assert(type(newKey) is str)
        except AssertionError:
            raise TypeError('New user key must be a string!')
        self.key = newKey

    def setHmacAlgorithm(self, newAlgo):
        try:
            assert(newAlgo in [IntegrityAlgorithms.SHA1, IntegrityAlgorithms.SHA2, IntegrityAlgorithms.SHA3,
                               IntegrityAlgorithms.CRC32, IntegrityAlgorithms.CRC64])
        except AssertionError:
            raise TypeError('Invalid HMAC algorithm passed in! Must be declared in kinetic.common.IntegrityAlgorithms.')
        self.hmacAlgorithm = newAlgo

    def getHmacAlgorithm(self):
        return self.hmacAlgorithm

    def getDomains(self):
        return self.domains.copy()

    def getIdentity(self):
        return int(self.identity)

    def getKey(self):
        return str(self.key)

class Domain(object):
    """
        Domain object, which corresponds to the domain object in the Java client,
        and is the Scope object in the protobuf.
    """
    def __init__(self, roles=None, tlsRequried = False, offset=None, value=None):
        if roles:
            self.roles = set(roles)
        else:
            self.roles = set()
        self.tlsRequired = tlsRequried
        self.offset = offset
        self.value = value

    def setRoles(self, roles):
        newRoles = set(roles)
        for role in newRoles:
            try:
                assert(role in Roles.all())
            except AssertionError:
                raise TypeError('Invalid object passed for role! Must be declared in kinetic.common.Roles.')
        self.roles = newRoles

    def setTlsRequired(self, newState):
        try:
            assert(type(newState) is bool)
        except AssertionError:
            raise TypeError('TlsRequired must be a boolean!')
        self.tlsRequired = newState

    def setOffset(self, offset):
        try:
            assert(type(offset) is int)
        except AssertionError:
            raise TypeError('Offset must be an int!')
        self.offset = offset

    def setValue(self, value):
        #TODO: Can this be string, byte array or both? Maybe add an assert check on this...
        self.value = value

    def getValue(self):
        return self.value

    def getOffset(self):
        return self.offset

    def getRoles(self):
        return self.roles.copy()

    def getTlsRequired(self):
        return bool(self.tlsRequired)



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
    SYNC = 1
    ASYNC = 2
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
    UTILIZATIONS = 0
    TEMPERATURES = 1
    CAPACITIES = 2
    CONFIGURATION = 3
    STATISTICS = 4
    MESSAGES = 5

    @classmethod
    def all(cls):
        """
            LogTypes.all takes no arguments and returns a list of all valid log magic numbers (from the protobuf definition)
            that can be retrieved using the AdminClient .getLog method. Log types avaiable are: (0-> Utilizations, 1-> Temperatures,
            2->Drive Capacity, 3-> Drive Configuration, 4->Drive usage statistics, and 5-> Drive messages). This can be passed as
            the sole argument to the AdminClient.getLog function.
        """
        return [cls.UTILIZATIONS, cls.TEMPERATURES, cls.CAPACITIES, cls.CONFIGURATION, cls.STATISTICS, cls.MESSAGES]

