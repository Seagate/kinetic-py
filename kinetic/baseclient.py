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

import itertools
import logging
import socket
import time
from binascii import hexlify
from hashlib import sha1
import hmac
import struct
import common
import kinetic_pb2 as messages
import ssl
import operations

ss = socket

LOG = logging.getLogger(__name__)

def calculate_hmac(secret, message):
    mac = hmac.new(secret, digestmod=sha1)

    def update(entity):
        if not entity:
            return
        if hasattr(entity, 'SerializeToString'):
            entity = entity.SerializeToString()
        #converting to big endian to be compatible with java implementation.
        mac.update(struct.pack(">I", len(entity)))
        mac.update(entity)

    # always add command
    update(message.command)

    d = mac.digest()
    if LOG.isEnabledFor(logging.DEBUG):
        LOG.debug('message hmac: %s' % hexlify(d))
    return d

class BaseClient(object):

    # defaults
    HOSTNAME = 'localhost'
    PORT = 8123
    CLUSTER_VERSION = 0
    # development default
    USER_ID = 1
    CLIENT_SECRET = 'asdfasdf'

    def __init__(self, hostname=HOSTNAME, port=PORT, identity=USER_ID,
                 cluster_version=CLUSTER_VERSION, secret=CLIENT_SECRET,
                 chunk_size=common.DEFAULT_CHUNK_SIZE,
                 connect_timeout=common.DEFAULT_CONNECT_TIMEOUT,
                 socket_timeout=common.DEFAULT_SOCKET_TIMEOUT,
                 socket_address=None,
                 socket_port=0,
                 defer_read=False,
                 use_ssl=False):
        self.hostname = hostname
        self.port = port
        self.identity = identity
        self.cluster_version = cluster_version
        self.secret = secret
        self.chunk_size = chunk_size
        self._socket = None
        self._buff = ''
        self.debug = False
        self._closed = True
        self.connect_timeout = connect_timeout
        self.socket_timeout = socket_timeout
        self.socket_address = socket_address
        self.socket_port = socket_port
        self.defer_read = defer_read
        self.wait_on_read = None
        self.use_ssl = use_ssl

    @property
    def socket(self):
        if not self._socket:
            raise NotConnected()
        return self._socket

    @property
    def isConnected(self):
        return not self._closed

    def build_socket(self, family=ss.AF_INET):
       return socket.socket(family)

    def connect(self):
        if self._socket:
            raise common.AlreadyConnected("Client is already connected.")

        infos = socket.getaddrinfo(self.hostname, self.port, 0, 0, socket.SOL_TCP)
        (family,_,_,_, sockaddr) = infos[0]
        # Stage socket on a local variable first
        s = self.build_socket(family)
        if self.use_ssl:
            s = ssl.wrap_socket(s)

        s.settimeout(self.connect_timeout)
        if self.socket_address:
            LOG.debug("Client local port address bound to " + self.socket_address)
            s.bind((self.socket_address, self.socket_port))
        # if connect fails, there is nothing to clean up
        s.connect(sockaddr) # use first
        s.settimeout(self.socket_timeout)
        s.setsockopt(ss.IPPROTO_TCP, ss.TCP_NODELAY, 1)

        # We are connected now, update attributes
        self._socket = s
        self._sequence = itertools.count()
        self.connection_id = int(time.time())
        self._closed = False

        self._handshake()

    def _handshake(self):
        # Connection id handshake
        h,v = operations.Noop.build()
        self.update_header(h)
        self.network_send(h,v)
        h,v = self.network_recv()
        operations._check_status(h)

    def has_data_available(self):
        tmp = self._socket.recv(1, socket.MSG_PEEK)
        return len(tmp) > 0

    def close(self):
        self._closed = True
        if self._socket:
            try:
                self._socket.shutdown(socket.SHUT_RDWR)
                self._socket.close()
            except Exception as e: 
                LOG.warning('Socket faulted on shutdown/close for {}.'.format(e))
        self._buff = ''
        self._socket = None
        self.connection_id = None
        self._sequence = itertools.count()


    def update_header(self, message):
        """
        Updates the message header with connection specific information.
        The unique sequence is assigned by this method.

        :param message: message to be modified (message is modified in place)
        """
        header = message.command.header
        header.clusterVersion = self.cluster_version
        header.identity = self.identity
        header.connectionID = self.connection_id
        header.sequence = self._sequence.next()
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug("Header updated. Connection=%s, Sequence=%s" % (header.connectionID, header.sequence))

    def _send_delimited_v2(self, header, value):
        # build message (without value) to write
        out = header.SerializeToString()

        value_ln = 0
        if value:
            value_ln = len(value)

        # 1. write magic number
        # 2. write protobuf message message size, 4 bytes
        # 3. write attached value size, 4 bytes
        # 4. write protobuf message byte[]

        buff = struct.pack(">Bii",ord('F'), len(out), value_ln)

        # Send it all in one packet
        aux = bytearray(buff)
        aux.extend(out)
        self.socket.send(aux)

        # 5. (optional) write attached value if any
        send_op = getattr(value, "send", None)
        if callable(send_op): # if value has custom logic for sending over network, delegate
            send_op(self.socket)
        else:
            # 5 (optional) write attached value if any
            if value_ln  > 0:
                # write value
                to_send = len(value)
                i = 0
                while i < to_send:
                    nbytes = self.socket.send(value[i:i + self.chunk_size])
                    if not nbytes:
                        raise common.ServerDisconnect('Server send disconnect')
                    i += nbytes


    def network_send(self, header, value):
        """
        Sends a raw message.
        The HMAC is calculated and added to the message.
        Important: update_header must be called before sending the message.

        :param message: the message to be sent
        """
        # fail fast on NotConnected
        self.socket

        header.hmac = calculate_hmac(self.secret, header)

        if self.debug:
            print header

        self._send_delimited_v2(header, value)

        return header

    def toHexString(self, array):
        return ''.join('%02x ' % ord(byte) for byte in array)

    def bytearray_to_hex(self, array):
        return ''.join('%02x ' % byte for byte in array)

    def fast_read(self, toread):
        buf = bytearray(toread)
        view = memoryview(buf)
        while toread:
            nbytes = self.socket.recv_into(view, toread)
            if nbytes == 0:
                raise common.ServerDisconnect("Connection closed by peer")
            view = view[nbytes:]
            toread -= nbytes
        return buf

    def _recv_delimited_v2(self):
        # receive the leading 9 bytes

        if self.wait_on_read:
            self.wait_on_read.wait()
            self.wait_on_read = None

        msg = self.fast_read(9)

        magic, proto_ln, value_ln = struct.unpack_from(">bii", buffer(msg))

        if magic!= 70:
            LOG.warn("Magic number = {0}".format(magic))
            raise common.KineticClientException("Invalid Magic Value!") # 70 = 'F'

        # read proto message
        raw_proto = self.fast_read(proto_ln)

        value = None
        if value_ln > 0:
            if self.defer_read:
                # let user handle the read from socket
                value = common.DeferedValue(self.socket, value_ln)
                self.wait_on_read = value
            else:
                # normal code path, read value
                value = self.fast_read(value_ln)

        proto = messages.Message()
        proto.ParseFromString(str(raw_proto))

        if self.debug:
            print proto

        return (proto, value)

    def network_recv(self):
        """
        Receives a raw Kinetic message from the network.

        return: the message received
        """

        resp = self._recv_delimited_v2()

        # update connectionId to whatever the drive said.
        if resp[0].command.header.connectionID:
            self.connection_id = resp[0].command.header.connectionID

        return resp

    def send(self, header, value):
       self.network_send(header, value)
       resp = self.network_recv()
       return resp

    ### with statement support ###

    def __enter__(self):
        if not self.isConnected:
            self._temporaryConnection = True
            self.connect()
        else:
            self._temporaryConnection = False
        return self

    def __exit__(self, t, v, tb):
        if self._temporaryConnection:
            self.close()
        self._temporaryConnection = None

    ### Object overrides ###

    def __str__(self):
        return "{hostname}:{port}".format(hostname=self.hostname, port=self.port)

