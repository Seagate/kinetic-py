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

import errno
import functools
import logging
import os
import subprocess
import shutil
import socket
import tempfile
import time
import unittest

from kinetic import Client
from kinetic import buildRange

KINETIC_JAR = os.environ.get('KINETIC_JAR')
KINETIC_PORT = os.environ.get('KINETIC_PORT', 9123)
KINETIC_HOST = os.environ.get('KINETIC_HOST', 'localhost')

class SimulatorRuntimeError(RuntimeError):

    def __init__(self, stdout, stderr, returncode):
        super(SimulatorRuntimeError, self).__init__(stdout, stderr, returncode)
        # reopen file's in read mode
        self.stdout = open(stdout.name).read()
        self.stderr = open(stderr.name).read()
        self.returncode = returncode

    def __str__(self):
        return '\n'.join([
            'Simulator exited abnormally',
            'STDOUT:\n%s' % self.stdout,
            'STDERR:\n%s' % self.stderr,
            'RETURNCODE: %s' % self.returncode
        ])


def _find_kinetic_jar(jar_path=None):
    if jar_path:
        jar_path = os.path.abspath(os.path.expanduser(
            os.path.expandvars(jar_path)
        ))
    else:
        jar_path = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                # /kinetic-py/test/.
                '../../kinetic-java/kinetic-simulator/target/',
                'kinetic-simulator-0.6.0.3-SNAPSHOT-jar-with-dependencies.jar',
            )
        )
    if not os.path.exists(jar_path):
        if 'KINETIC_JAR' not in os.environ:
            raise KeyError('KINETIC_JAR environment variable is not set')
        else:
            msg = "%s: '%s'" % (os.strerror(errno.ENOENT), jar_path)
            raise IOError(errno.ENOENT, msg)
    return jar_path


class BaseTestCase(unittest.TestCase):
    """
    This is the BaseTestCase for running python test code against the
    Kinetic simulator.

    Each TestCase will independently verify a connection to a simulator
    running on localhost at the port defined by the environment variable
    KINETIC_PORT (default 9123) spawning an instance of the simulator if
    necessary.

    In the common case no simulator will currently be listening on port 9123
    and unless your override KINETIC_PORT in your environment before
    running tests - the TestCase will spawn an instance of the simulator using
    the system java runtime by pointing it at the .jar defined by the
    environment variable KINETIC_JAR.  If KINETIC_JAR is not defined it
    will go looking for it relative to this file.

    If you want to connect to an instance of the simulator you already have
    running (or a development instance that hasn't yet been packaged in a jar)
    you can `set KINETIC_PORT=8123` (or wherever the server is).

    If the .jar is not readily locatable you will get an error and need to
    ensure that the KINETIC_JAR environment variable points to the real
    path for kinetic-simulator.

    """

    @classmethod
    def _check_simulator(cls):
        if not cls.simulator:
            cls.datadir = tempfile.mkdtemp()
            cls.stdout = open(os.path.join(cls.datadir, 'simulator.log'), 'w')
            cls.stderr = open(os.path.join(cls.datadir, 'simulator.err'), 'w')
            args = ['java', '-jar', cls.jar_path, str(cls.port), cls.datadir]
            cls.simulator = subprocess.Popen(args, stdout=cls.stdout.fileno(),
                                             stderr=cls.stderr.fileno())
        if cls.simulator.poll():
            raise SimulatorRuntimeError(cls.stdout, cls.stderr, cls.simulator.returncode)

    @classmethod
    def setUpClass(cls):
        cls.client = None
        cls.baseKey = "tests/py/%s/" % cls.__name__

        cls.port = int(KINETIC_PORT)
        cls.host = KINETIC_HOST
        cls.jar_path = _find_kinetic_jar(KINETIC_JAR)
        cls.datadir = None
        cls.simulator = None
        cls.stdout = cls.stderr = None
        try:
            backoff = 0.1
            while True:
                sock = socket.socket()
                try:
                    sock.connect((cls.host, cls.port))
                except socket.error:
                    if backoff > 2:
                        raise
                else:
                    # k, we can connect
                    sock.close()
                    break
                cls._check_simulator()
                time.sleep(backoff)
                backoff *= 2  # double it!
        except:
            if hasattr(cls, 'stdout'):
                try:
                    raise SimulatorRuntimeError(cls.stdout, cls.stderr,
                                                cls.simulator.returncode)
                except:
                    # this is some dodgy shit to setup the re-raise at the bottom
                    pass
            cls.tearDownClass()
            raise

        cls.client = Client(cls.host, cls.port)
        cls.client.connect()

    @classmethod
    def tearDownClass(cls):
        # remove all keys used by this test case
        r = buildRange(cls.baseKey)
        if cls.client:
            xs = cls.client.getRange(r.startKey, r.endKey, r.startKeyInclusive, r.endKeyInclusive)
            for x in xs:
                cls.client.delete(x.key, x.metadata.version)
        else:
            print 'WARNING: no cls.client'

        if cls.simulator:
            if cls.simulator.poll() is None:
                cls.simulator.terminate()
            cls.simulator.wait()
        [f.close() for f in (cls.stdout, cls.stderr) if f]
        if cls.datadir:
            shutil.rmtree(cls.datadir)

    def tearDown(self):
        r = buildRange(self.baseKey)
        xs = self.client.getRange(r.startKey, r.endKey, r.startKeyInclusive, r.endKeyInclusive)
        for x in xs:
            self.client.delete(x.key, x.metadata.version)

    def buildKey(self, n='test'):
        # self.id returns the name of the running test
        return self.baseKey + "%s/%s" % (self.id(), str(n))

    @classmethod
    def debug_logging(cls, f):
        """
        Decorator, enables logging for the test
        """
        @functools.wraps(f)
        def wrapper(self, *args, **kwargs):
            logging.basicConfig(level=logging.DEBUG)
            logging.critical('DEBUG LOGGING FOR %s' % self.id())
            try:
                logging.disable(level=logging.NOTSET)
                return f(self, *args, **kwargs)
            finally:
                logging.disable(level=logging.CRITICAL)
        return wrapper


def start_simulators(jar_path, data_dir, *ports):
    sim_map = {}
    with open(os.devnull, 'w') as null:
        for port in ports:
            args = ['java', '-jar', jar_path, str(port),
                    os.path.join(data_dir, str(port)), str(port + 443)]
            sim_map[port] = subprocess.Popen(args, stdout=null, stderr=null)
    time.sleep(1)
    connected = []
    backoff = 0.1
    timeout = time.time() + 3
    while len(connected) < len(sim_map) and time.time() < timeout:
        for port in sim_map:
            if port in connected:
                continue
            sock = socket.socket()
            try:
                sock.connect(('localhost', port))
            except socket.error:
                time.sleep(backoff)
                backoff *= 2
            else:
                connected.append(port)
                sock.close()
    if len(connected) < len(sim_map):
        teardown_simulators(sim_map)
        raise Exception('only able to connect to %r out of %r' % (connected,
                                                                  sim_map))
    return sim_map


def teardown_simulators(sim_map):
    for proc in sim_map.values():
        try:
            proc.terminate()
        except OSError, e:
            if e.errno != errno.ESRCH:
                raise
            continue
        proc.wait()


class MultiSimulatorTestCase(unittest.TestCase):

    PORTS = (9010, 9020)

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.ports = self.PORTS
        self._sim_map = {}
        try:
            self._sim_map = start_simulators(_find_kinetic_jar(KINETIC_JAR),
                                             self.test_dir, *self.ports)
            self.client_map = {}
            for port in self.ports:
                self.client_map[port] = Client('localhost', port)
                self.client_map[port].connect()
        except Exception:
            self.tearDown()

    def tearDown(self):
        teardown_simulators(self._sim_map)
        shutil.rmtree(self.test_dir)

    def buildKey(self, key):
        return "tests/py/%s.%s/%s" % (
            self.__class__.__name__, self.id(), str(key))


if __name__ == "__main__":
    # sanity
    print _find_kinetic_jar(KINETIC_JAR)
    print int(KINETIC_PORT)
