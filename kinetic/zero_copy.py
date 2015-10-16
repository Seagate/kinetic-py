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


import traceback
import logging
import os
import select
import fcntl
import errno
import os.path
import socket
import subprocess
import ctypes
import ctypes.util
from eventlet.green import select as green_select

LOG = logging.getLogger(__name__)


def set_nonblock(fd): #pylint: disable-msg=C0103
    '''Set a file descriptor in non-blocking mode'''

    flags = fcntl.fcntl(fd, fcntl.F_GETFL, 0)
    flags |= os.O_NONBLOCK
    fcntl.fcntl(fd, fcntl.F_SETFL, flags)


def direct_transfer_select(fd_in, off_in, fd_out, off_out, length):
    LOG.debug("Transfering %s bytes from %s to %s" % (length, fd_in, fd_out))
    (pipe_r, pipe_w) = os.pipe()
    pipe_r = os.fdopen(pipe_r)
    pipe_w = os.fdopen(pipe_w,'w')
    fd_pipe_r = pipe_r.fileno()
    fd_pipe_w = pipe_w.fileno()

    LOG.debug("  source(%s) -> pipe(%s, %s) -> dest(%s)" % (fd_in, fd_pipe_w, fd_pipe_r, fd_out))

    set_nonblock(fd_in)
    set_nonblock(fd_out)
    set_nonblock(fd_pipe_r)
    set_nonblock(fd_pipe_w)

    flags = SPLICE_F_MOVE | SPLICE_F_MORE | SPLICE_F_NONBLOCK

    epoll = select.epoll() # TODO: find a proper way to check if the fd's are files
    fd_in_is_file = False
    fd_out_is_file = False

    try:
        epoll.register(fd_in, select.EPOLLIN)
    except:
        fd_in_is_file = True

    try:
        epoll.register(fd_out, select.EPOLLOUT)
    except:
        fd_out_is_file = True

    if fd_in_is_file:
        readers = [fd_pipe_r]
    else:
        readers = [fd_in, fd_pipe_r]

    if fd_out_is_file:
        writers = [fd_pipe_w]
    else:
        writers = [fd_pipe_w, fd_out]

    try:
        towrite0 = length
        towrite1 = length

        ready = []

        while towrite0 > 0 or towrite1 > 0:
            readable_set, writable_set, _ = green_select.select(readers, writers, [])

            for x in readable_set:
                ready.append(x)
                readers.remove(x)

            for x in writable_set:
                ready.append(x)
                writers.remove(x)

            # two transfer options
            if (fd_in_is_file or fd_in in ready) and (fd_pipe_w in ready):

                # transfer from source to pipe
                try:
                    done = splice.splice(fd_in, None, fd_pipe_w, None, towrite0, flags)
                    LOG.debug('> Source -> pipe %s bytes' % done)
                    towrite0 -= done
                except IOError as ioex:
                    if ioex.errno in [errno.EAGAIN, errno.EWOULDBLOCK]: continue
                    else: raise

                # reset
                if not fd_in_is_file:
                    ready.remove(fd_in)
                    readers.append(fd_in)

                ready.remove(fd_pipe_w)
                writers.append(fd_pipe_w)

            if (fd_pipe_r in ready) and (fd_out_is_file or fd_out in ready):

                # transfer from pipe to destination
                try:
                    done = splice.splice(fd_pipe_r, None, fd_out, None, towrite1, flags)
                    LOG.debug('> pipe -> dest %s bytes' % done)
                    towrite1 -= done
                except IOError as ioex:
                    if ioex.errno in [errno.EAGAIN, errno.EWOULDBLOCK]: continue
                    else: raise

                # reset
                if not fd_out_is_file:
                    ready.remove(fd_out)
                    writers.append(fd_out)

                ready.remove(fd_pipe_r)
                readers.append(fd_pipe_r)

    except Exception as ex:
        traceback.print_exc()
        raise


def direct_transfer_epoll(fd_in, off_in, fd_out, off_out, length):
    LOG.debug("Transfering %s bytes from %s to %s" % (length, fd_in, fd_out))
    (pipe_r, pipe_w) = os.pipe()
    pipe_r = os.fdopen(pipe_r)
    pipe_w = os.fdopen(pipe_w,'w')
    fd_pipe_r = pipe_r.fileno()
    fd_pipe_w = pipe_w.fileno()

    LOG.debug("  source(%s) -> pipe(%s, %s) -> dest(%s)" % (fd_in, fd_pipe_w, fd_pipe_r, fd_out))

    set_nonblock(fd_in)
    set_nonblock(fd_out)
    set_nonblock(fd_pipe_r)
    set_nonblock(fd_pipe_w)

    flags = SPLICE_F_MOVE | SPLICE_F_MORE | SPLICE_F_NONBLOCK

    try:
        towrite0 = length
        towrite1 = length

        epoll = select.epoll()
        fd_in_is_file = False
        fd_out_is_file = False

        try:
            epoll.register(fd_in, select.EPOLLIN) # handle EPOLLHUP
        except:
            fd_in_is_file = True

        try:
            epoll.register(fd_out, select.EPOLLOUT) # handle EPOLLHUP
        except:
            fd_out_is_file = True

        epoll.register(fd_pipe_r, select.EPOLLIN)
        epoll.register(fd_pipe_w, select.EPOLLOUT)


        while towrite0 > 0 or towrite1 > 0:
            events = epoll.poll()

            events_dict = {fd: evt for (fd, evt) in events}

            # two transfer options
            if (fd_in_is_file or fd_in in events_dict) and fd_pipe_w in events_dict:

                # transfer from source to pipe
                try:
                    done = splice(fd_in, None, fd_pipe_w, None, towrite0, flags)
                    LOG.debug('> Source -> pipe %s bytes' % done)
                    towrite0 -= done
                except IOError as ioex:
                    if ioex.errno in [errno.EAGAIN, errno.EWOULDBLOCK]:
                        continue

            if fd_pipe_r in events_dict and (fd_out_is_file or fd_out in events_dict):

                # transfer from pipe to destination
                try:
                    done = splice(fd_pipe_r, None, fd_out, None, towrite1, flags)
                    LOG.debug('> pipe -> dest %s bytes' % done)
                    towrite1 -= done
                except IOError as ioex:
                    if ioex.errno in [errno.EAGAIN, errno.EWOULDBLOCK]: continue
                    else: raise

        epoll.close()

    except Exception as ex:
        traceback.print_exc()
        raise


direct_transfer = direct_transfer_epoll


def forwardto(defered_value, target_fd):
    direct_transfer(defered_value.socket.fileno(), None,
                    target_fd.fileno(), None, defered_value.length)
    defered_value.set() # signal we are done reading


class ZeroCopyValue():

    def __init__(self, fd, offset, length):
        self.fd = fd
        self.offset = offset
        self.length = length

    def __len__(self): return self.length

    def send(self, socket):
        # If source is a file then offset is valid, otherwise is has to be None
        direct_transfer(self.fd.fileno(), self.offset, socket.fileno(), None, self.length)


def make_splice():
    '''Set up a splice(2) wrapper'''

    # Load libc
    libc_name = ctypes.util.find_library('c')
    libc = ctypes.CDLL(libc_name, use_errno=True)

    # Get a handle to the 'splice' call
    c_splice = libc.splice

    # These should match for x86_64, might need some tweaking for other
    # platforms...
    c_loff_t = ctypes.c_uint64
    c_loff_t_p = ctypes.POINTER(c_loff_t)

    # ssize_t splice(int fd_in, loff_t *off_in, int fd_out,
    #     loff_t *off_out, size_t len, unsigned int flags)
    c_splice.argtypes = [
        ctypes.c_int, c_loff_t_p,
        ctypes.c_int, c_loff_t_p,
        ctypes.c_size_t,
        ctypes.c_uint
    ]
    c_splice.restype = ctypes.c_ssize_t

    # Clean-up closure names. Yup, useless nit-picking.
    del libc
    del libc_name
    del c_loff_t_p

    # pylint: disable-msg=W0621,R0913
    def splice(fd_in, off_in, fd_out, off_out, len_, flags):
        '''Wrapper for splice(2)

        See the syscall documentation ('man 2 splice') for more information
        about the arguments and return value.

        `off_in` and `off_out` can be `None`, which is equivalent to `NULL`.

        If the call to `splice` fails (i.e. returns -1), an `OSError` is raised
        with the appropriate `errno`, unless the error is `EINTR`, which results
        in the call to be retried.
        '''

        c_off_in = \
            ctypes.byref(c_loff_t(off_in)) if off_in is not None else None
        c_off_out = \
            ctypes.byref(c_loff_t(off_out)) if off_out is not None else None

        # For handling EINTR...
        while True:
            res = c_splice(fd_in, c_off_in, fd_out, c_off_out, len_, flags)

            if res == -1:
                errno_ = ctypes.get_errno()

                # Try again on EINTR
                if errno_ == errno.EINTR:
                    continue

                raise IOError(errno_, os.strerror(errno_))

            return res

    return splice


# Build and export wrapper
splice = make_splice() #pylint: disable-msg=C0103
del make_splice


# From bits/fcntl.h
# Values for 'flags', can be OR'ed together
SPLICE_F_MOVE = 1
SPLICE_F_NONBLOCK = 2
SPLICE_F_MORE = 4
SPLICE_F_GIFT = 8
