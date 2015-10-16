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

import contextlib
import StringIO
import sys
import unittest

from kinetic import client
from kinetic import cmd

from base import BaseTestCase


class BaseCommandTestCase(BaseTestCase):

    def setUp(self):
        super(BaseCommandTestCase, self).setUp()
        self.test_key = self.buildKey('test')
        self.client = client.Client(self.host, self.port)
        self.client.connect()
        self.conn_args = '-H %s -P %s ' % (self.host, self.port)

    @contextlib.contextmanager
    def capture_stdout(self):
        _orig_stdout = sys.stdout
        sys.stdout = StringIO.StringIO()
        try:
            yield sys.stdout
        finally:
            sys.stdout = _orig_stdout

    @contextlib.contextmanager
    def capture_stdio(self):
        _orig_stdout = sys.stdout
        sys.stdout = StringIO.StringIO()
        _orig_stderr = sys.stderr
        sys.stderr = StringIO.StringIO()
        try:
            yield sys.stdout, sys.stderr
        finally:
            sys.stdout = _orig_stdout
            sys.stderr = _orig_stderr

    def run_cmd(self, args):
        with self.capture_stdout() as stdout:
            errorcode = cmd.main(self.conn_args + args)
            output = stdout.getvalue()
        return errorcode, output

class TestCommand(BaseCommandTestCase):

    def test_command_put(self):
        # make sure there's nothing there
        value = self.client.get(self.test_key)
        self.assert_(value is None)
        # add something from the command line
        args = 'put %s myvalue' % self.test_key
        errorcode = cmd.main(self.conn_args + args)
        # returns no error
        self.assertFalse(errorcode)
        # validate key is set
        entry = self.client.get(self.test_key)
        self.assertEquals('myvalue', entry.value)

    def test_command_get(self):
        # make sure there's nothing there
        value = self.client.get(self.test_key)
        self.assert_(value is None)
        # try to read value from command line
        args = 'get %s' % self.test_key
        with self.capture_stdout() as stdout:
            errorcode = cmd.main(self.conn_args + args)
            output = stdout.getvalue()
        # returns error and no output
        self.assert_(errorcode)
        self.assertEquals('', output)
        # put something there
        self.client.put(self.test_key, 'myvalue')
        # try to read value from command line
        args = 'get %s' % self.test_key
        with self.capture_stdout() as stdout:
            errorcode = cmd.main(self.conn_args + args)
            output = stdout.getvalue()
        # returns no error and value
        self.assertFalse(errorcode)
        self.assertEquals('myvalue\n', output)
        # and the data is in fact there
        entry = self.client.get(self.test_key)
        self.assertEquals('myvalue', entry.value)

    def test_command_delete(self):
        # make sure there's nothing there
        value = self.client.get(self.test_key)
        self.assert_(value is None)
        # try to remove key from command line
        args = 'delete %s' % self.test_key
        with self.capture_stdout() as stdout:
            errorcode = cmd.main(self.conn_args + args)
            output = stdout.getvalue()
        # returns error and no output
        self.assert_(errorcode)
        self.assertEquals('', output)
        # put something there
        self.client.put(self.test_key, 'myvalue')
        # try to remove key from command line
        args = 'delete %s' % self.test_key
        with self.capture_stdout() as stdout:
            errorcode = cmd.main(self.conn_args + args)
            output = stdout.getvalue()
        # returns no error and no output
        self.assertFalse(errorcode)
        self.assertEquals('', output)
        # and the data is in fact removed
        value = self.client.get(self.test_key)
        self.assert_(value is None)

    def test_command_list(self):
        # range will include test_key
        start = self.test_key[:-1]
        end = self.test_key + 'END'
        # range starts empty
        key_list = self.client.getKeyRange(start, end)
        self.assertEquals([], key_list)
        # validate empty from the command line
        args = 'list %s %s' % (start, end)
        with self.capture_stdout() as stdout:
            errorcode = cmd.main(self.conn_args + args)
            output = stdout.getvalue()
        # returns no error and no output
        self.assertFalse(errorcode)
        self.assertEquals('', output)
        # add test_key
        self.client.put(self.test_key, 'myvalue')
        # validate list from the command line
        args = 'list %s %s' % (start, end)
        with self.capture_stdout() as stdout:
            errorcode = cmd.main(self.conn_args + args)
            output = stdout.getvalue()
        # returns no error and list of keys
        self.assertFalse(errorcode)
        self.assertEquals('%s\n' % self.test_key, output)

    def test_list_prefix(self):
        # because the cmd output uses text/line based delimiters it's hard to
        # reason about keynames with a new line in them in this test
        bad_characters = [ord(c) for c in ('\n', '\r')]
        keys = [self.test_key + chr(ord_) for ord_ in range(200) if ord_ not
                in bad_characters]
        for i, key in enumerate(keys):
            self.client.put(key, 'myvalue.%s' % i)
        args = 'list %s' % self.test_key
        with self.capture_stdout() as stdout:
            errorcode = cmd.main(self.conn_args + args)
            output = stdout.getvalue()
        # returns no error and list of keys
        self.assertFalse(errorcode)
        output_keys = output.splitlines()
        self.assertEquals(len(keys), len(output_keys))
        self.assertEquals(keys, output_keys)
        # add the prefix key
        self.client.put(self.test_key, 'mystart')
        with self.capture_stdout() as stdout:
            errorcode = cmd.main(self.conn_args + args)
            output = stdout.getvalue()
        # returns no error and list of keys
        self.assertFalse(errorcode)
        output_keys = output.splitlines()
        self.assertEquals(len(keys) + 1, len(output_keys))
        self.assertEquals(self.test_key, output_keys[0])
        # add something just "after" the prefix
        end_key = self.test_key[-1] + chr(ord(self.test_key[-1]) + 1)
        self.client.put(end_key, 'myend')
        with self.capture_stdout() as stdout:
            errorcode = cmd.main(self.conn_args + args)
            output = stdout.getvalue()
        # returns no error and list of keys
        self.assertFalse(errorcode)
        output_keys = output.splitlines()
        self.assertEquals(len(keys) + 1, len(output_keys))
        self.assert_(end_key not in output_keys)

    def test_command_next(self):
        # make sure there's nothing there
        value = self.client.get(self.test_key)
        self.assert_(value is None)
        # try to read value from command line
        args = 'next %s' % self.test_key[:-1]
        with self.capture_stdout() as stdout:
            errorcode = cmd.main(self.conn_args + args)
            output = stdout.getvalue()
        # if simulator is empty, there's no output
        if not output:
            # returns error and no output
            self.assertEquals('', output)
            self.assertTrue(errorcode)
        else:
            self.assertFalse(errorcode)
        # put something there
        self.client.put(self.test_key, 'myvalue')
        # try a short offset to value from command line
        args = 'next %s' % self.test_key[:-1]
        with self.capture_stdout() as stdout:
            errorcode = cmd.main(self.conn_args + args)
            output = stdout.getvalue()
        # returns no error and data
        self.assertFalse(errorcode)
        self.assertEquals('myvalue\n', output)
        # try a longer offset to value from command line
        args = 'next %s' % self.test_key[0]
        with self.capture_stdout() as stdout:
            errorcode = cmd.main(self.conn_args + args)
            output = stdout.getvalue()
        # returns no error and data
        self.assertFalse(errorcode)
        self.assertEquals('myvalue\n', output)
        # try a next right on top of value from command line
        args = 'next %s' % self.test_key
        with self.capture_stdout() as stdout:
            errorcode = cmd.main(self.conn_args + args)
            output = stdout.getvalue()
        # if simulator is empty, there's no output
        if not output:
            # returns error and no output
            self.assert_(errorcode)
            self.assertEquals('', output)
        else:
            self.assertFalse(errorcode)
        # and past value from command line
        args = 'next %sXXX' % self.test_key
        with self.capture_stdout() as stdout:
            errorcode = cmd.main(self.conn_args + args)
            output = stdout.getvalue()
        # if simulator is empty, there's no output
        if not output:
            # returns error and no output
            self.assert_(errorcode)
            self.assertEquals('', output)
        else:
            self.assertFalse(errorcode)

    def test_command_next_verbose(self):
        # put something there
        self.client.put(self.test_key, 'myvalue')
        # try a short offset to value from command line
        args = '-vb next %s' % self.test_key[:-1]
        with self.capture_stdio() as stdio:
            errorcode = cmd.main(self.conn_args + args)
            stdout, stderr = stdio
            output = stdout.getvalue()
            verbose = stderr.getvalue()
        # returns no error and data
        self.assertFalse(errorcode)
        self.assertEquals('key: %s\n' % self.test_key, verbose)
        self.assertEquals('myvalue\n', output)

    def test_command_prev(self):
        # make sure there's nothing there
        value = self.client.get(self.test_key)
        self.assert_(value is None)
        # try to read value from command line
        args = 'prev %sXXX' % self.test_key
        with self.capture_stdout() as stdout:
            errorcode = cmd.main(self.conn_args + args)
            output = stdout.getvalue()
        # if simulator is empty, there's no output
        if not output:
            # returns error and no output
            self.assertEquals('', output)
            self.assertTrue(errorcode)
        else:
            self.assertFalse(errorcode)
        # put something there
        self.client.put(self.test_key, 'myvalue')
        # try a short offset to value from command line
        args = 'prev %sXXX' % self.test_key
        with self.capture_stdout() as stdout:
            errorcode = cmd.main(self.conn_args + args)
            output = stdout.getvalue()
        # returns no error and data
        self.assertFalse(errorcode)
        self.assertEquals('myvalue\n', output)
        # try a longer offset to value from command line
        args = 'prev %s~' % self.test_key.rsplit('/', 1)[0]
        with self.capture_stdout() as stdout:
            errorcode = cmd.main(self.conn_args + args)
            output = stdout.getvalue()
        # returns no error and data
        self.assertFalse(errorcode)
        self.assertEquals('myvalue\n', output)
        # try a prev right on top of value from command line
        args = 'prev %s' % self.test_key
        with self.capture_stdout() as stdout:
            errorcode = cmd.main(self.conn_args + args)
            output = stdout.getvalue()
        # if simulator is empty, there's no output
        if not output:
            # returns error and no output
            self.assertEquals('', output)
            self.assertTrue(errorcode)
        else:
            self.assertFalse(errorcode)
        # and past value from command line
        args = 'prev %s' % self.test_key[:-1]
        with self.capture_stdout() as stdout:
            errorcode = cmd.main(self.conn_args + args)
            output = stdout.getvalue()
        # if simulator is empty, there's no output
        if not output:
            # returns error and no output
            self.assertEquals('', output)
            self.assertTrue(errorcode)
        else:
            self.assertFalse(errorcode)

    def test_command_prev_verbose(self):
        # put something there
        self.client.put(self.test_key, 'myvalue')
        # try a short offset to value from command line
        args = '-vb prev %s~' % self.test_key
        with self.capture_stdio() as stdio:
            errorcode = cmd.main(self.conn_args + args)
            stdout, stderr = stdio
            output = stdout.getvalue()
            verbose = stderr.getvalue()
        # returns no error and data
        self.assertFalse(errorcode)
        self.assertEquals('key: %s\n' % self.test_key, verbose)
        self.assertEquals('myvalue\n', output)


class TestGetRangeCommand(BaseCommandTestCase):

    def test_command_getr(self):
        num_keys = 3
        for i in range(num_keys):
            self.client.put(self.test_key + '.%.5d' % i, 'myvalue.%.5d' % i)
        args = 'getr %s' % self.test_key
        errorcode, output = self.run_cmd(args)
        self.assertFalse(errorcode)
        expected = ''.join(['myvalue.%.5d' % i for i in range(num_keys)])
        self.assertEquals(expected + '\n', output)

    def test_missing_keys(self):
        args = 'getr %s' % self.test_key
        errorcode, output = self.run_cmd(args)
        self.assertFalse(errorcode)
        self.assertEquals('\n', output)

    def test_explicit_range(self):
        num_keys = 10
        for i in range(num_keys):
            self.client.put(self.test_key + '.%.5d' % i, 'myvalue.%.5d' % i)
        last_included_key_number = num_keys // 2
        args = 'getr {key} {key}.{stop:0=5}'.format(key=self.test_key,
                                                    stop=(last_included_key_number))
        errorcode, output = self.run_cmd(args)
        self.assertFalse(errorcode)
        expected = ''.join(['myvalue.%.5d' % i for i in
                            range(last_included_key_number + 1)])
        self.assertEquals(expected + '\n', output)


class TestDeleteRangeCommand(BaseCommandTestCase):

    def test_command_deleter(self):
        num_keys = 3
        keys = []
        for i in range(num_keys):
            key = self.test_key + '.%.5d' % i
            self.client.put(key, 'myvalue.%.5d' % i)
            keys.append(key)
        args = 'deleter %s' % self.test_key
        errorcode, output = self.run_cmd(args)
        self.assertFalse(errorcode)
        self.assertEquals('', output)
        for key in keys:
            self.assertEquals(None, self.client.get(key))

    def test_missing_keys(self):
        args = 'deleter %s' % self.test_key
        errorcode, output = self.run_cmd(args)
        self.assertFalse(errorcode)
        self.assertEquals('', output)

    def test_explicit_range(self):
        num_keys = 10
        keys = []
        for i in range(num_keys):
            key = self.test_key + '.%.5d' % i
            self.client.put(key, 'myvalue.%.5d' % i)
            keys.append(key)
        last_included_key_number = num_keys // 2
        args = 'deleter {key} {key}.{stop:0=5}'.format(key=self.test_key,
                                                    stop=(last_included_key_number))
        errorcode, output = self.run_cmd(args)
        self.assertFalse(errorcode)
        for i, key in enumerate(keys):
            if i <= last_included_key_number:
                # deleted
                self.assertEquals(None, self.client.get(key))
            else:
                # not deleted
                self.assertEquals('myvalue.%.5d' % i,
                                  self.client.get(key).value)


if __name__ == '__main__':
    unittest.main()
