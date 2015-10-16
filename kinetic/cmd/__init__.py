#!/usr/bin/env python

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

#@authors: [Ignacio Corderi, Clayg]

import argparse
import cmd
import functools
import logging
import shlex
import socket
import sys

import kinetic
from kinetic import AsyncClient

preparser = argparse.ArgumentParser(add_help=False)
preparser.add_argument('-H', '--hostname', default='localhost')
preparser.add_argument('-P', '--port', type=int, default=8123)
preparser.add_argument('-v', '--version', action='store_true',
                       help='Show kinetic version')
preparser.add_argument('-vb', '--verbose', action='count',
                       help='output more info (can stack)')
parser = argparse.ArgumentParser(parents=[preparser])
command_parsers = parser.add_subparsers()

# put
put_parser = command_parsers.add_parser('put', help='store value at key')
put_parser.add_argument('key', help='the key to access')
put_parser.add_argument('value', help='the value to store')

# get
get_parser = command_parsers.add_parser('get', help='read value at key')
get_parser.add_argument('key', help='the key to read')

# delete
delete_parser = command_parsers.add_parser('delete', help='remove a key')
delete_parser.add_argument('key', help='the key to remove')

# list
list_parser = command_parsers.add_parser(
    'list', help='list keys from start to end')
list_parser.add_argument('start', help='the start of key range')
list_parser.add_argument('end', help='the end of key range', nargs='?')

# next
next_parser = command_parsers.add_parser('next', help='read value at next key')
next_parser.add_argument('key', help='the min key to read')

# prev
prev_parser = command_parsers.add_parser('prev', help='read value at prev key')
prev_parser.add_argument('key', help='the max key to read')

# getr
getr_parser = command_parsers.add_parser(
    'getr', help='get keys from start to end')
getr_parser.add_argument('start', help='the start of key range')
getr_parser.add_argument('end', help='the end of key range', nargs='?')

# deleter
deleter_parser = command_parsers.add_parser(
    'deleter', help='get keys from start to end')
deleter_parser.add_argument('start', help='the start of key range')
deleter_parser.add_argument('end', help='the end of key range', nargs='?')


def add_parser(parser):
    """
    Create a decorator that uses the provided parser to pre-parse args based
    on line argument to the original do_* method.

    Also updates the parser's default func attribute to f for handle_command.
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapper(self, line):
            try:
                args = parser.parse_args(shlex.split(line))
            except SystemExit:
                # let's not go quite that far...
                return
            args.verbose = self.verbose
            return f(self, args)
        parser.set_defaults(func=f)
        wrapper.parser = parser
        return wrapper
    return decorator


def add_help(name, bases, attrs):
    """
    Sorta magic, if we find a do_<command> method that has a parser hanging on
    it, use that to create a help_<command>, there's some weird "scopy" stuff.
    """
    attrs['sub_commands'] = []
    for f_name, f in attrs.items():
        if f_name.startswith('do_') and hasattr(f, 'parser'):
            command = f_name.split('_', 1)[-1]
            attrs['sub_commands'].append(command)
            f.parser.prog = command
            def make_help(print_help):
                def help_f(self):
                    print_help()
                return help_f
            help_f = make_help(f.parser.print_help)
            help_f.__name__ == 'help_%s' % command
            attrs['help_%s' % command] = help_f

    return type(name, bases, attrs)


def configure_logging(level):
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger('kinetic')
    logger.propagate = True
    if not any(h.__class__ == logging.NullHandler for h in logger.handlers):
        logger.addHandler(logging.NullHandler())
    if level >= 3:
        logger.setLevel(logging.DEBUG)
    elif level >= 2:
        logger.setLevel(logging.INFO)
    else:
        logger.propagate = False


class Cmd(cmd.Cmd, object):

    __metaclass__ = add_help

    prompt = 'kinetic> '
    intro = """
    The Kinetic Protocol Command Line Interface Tools

    type help for commands
    """

    def __init__(self, **options):
        cmd.Cmd.__init__(self)

        hostname = options.get('hostname', 'localhost')
        port = options.get('port', 8123)
        self.verbose = options.get('verbose') or 0
        self.client = AsyncClient(hostname, port)
        self.client.connect()

    def do_verbose(self, line):
        """Set active verbosity level [0-3]"""
        try:
            # see if the last word in the line is an integer
            level = int(line.strip().rsplit(None, 1)[-1])
        except (ValueError, IndexError):
            if line:
                print 'Unknown level: %r' % line
            print 'Current level: %s' % self.verbose
            return
        configure_logging(level)
        self.verbose = level

    def do_quit(self, line):
        """Quit"""
        return StopIteration

    do_EOF = do_quit

    def postcmd(self, stop, line):
        if stop is StopIteration:
            print '\nuser quit'
            return True

    @add_parser(put_parser)
    def do_put(self, args):
        self.client.put(args.key, args.value)

    @add_parser(get_parser)
    def do_get(self, args):
        entry = self.client.get(args.key)
        if not entry:
            return 1
        print entry.value

    @add_parser(delete_parser)
    def do_delete(self, args):
        if not self.client.delete(args.key):
            return 1

    def _list(self, args):
        if not args.end:
            args.end = args.start + '\xff'
        keys = self.client.getKeyRange(args.start, args.end)
        # getKeyRange will return a maximum of 200 keys. if we have that many
        # we need to continue retrieving keys until we get none or less than 200.
        if len(keys) == 200:
            last_key_retrieved = keys[len(keys)-1]
            retrieving_keys = True
            start_key_inclusive = False
            while retrieving_keys:
                partial_keys = self.client.getKeyRange(last_key_retrieved, args.end, start_key_inclusive)
                if len(partial_keys) > 0:
                    keys.extend(partial_keys)
                    if len(partial_keys) == 200:
                        last_key_retrieved = partial_keys[len(partial_keys)-1]
                    else:
                        retrieving_keys = False
                else:
                    retrieving_keys = False
        return keys

    @add_parser(list_parser)
    def do_list(self, args):
        keys = self._list(args)
        for key in keys:
            print key

    @add_parser(next_parser)
    def do_next(self, args):
        entry = self.client.getNext(args.key)
        if not entry:
            return 1
        if args.verbose:
            print >> sys.stderr, 'key:', entry.key
        print entry.value

    @add_parser(prev_parser)
    def do_prev(self, args):
        entry = self.client.getPrevious(args.key)
        if not entry:
            return 1
        if args.verbose:
            print >> sys.stderr, 'key:', entry.key
        print entry.value

    @add_parser(getr_parser)
    def do_getr(self, args):
        # behave like a prefix
        if not args.end:
            args.end = args.start + '\xff'
        for entry in self.client.getRange(args.start, args.end):
            if args.verbose:
                print >> sys.stderr, 'key:', entry.key
            sys.stdout.write(entry.value)
        print ''

    @add_parser(deleter_parser)
    def do_deleter(self, args):
        def on_success(m): pass
        def on_error(ex): pass
        keys = self._list(args)
        for k in keys:
            self.client.deleteAsync(on_success, on_error, k, force=True)
        self.client.wait()


def handle_loop(**options):
    while True:
        try:
            Cmd(**options).cmdloop()
        except socket.error as e:
            return 'ERROR: %s' % e
        except KeyboardInterrupt:
            print ''
            continue
        break


def handle_command(args):
    args = parser.parse_args(args)
    c = Cmd(**vars(args))
    try:
        return args.func(c, args)
    except socket.error as e:
        return 'ERROR: %s' % e
    except KeyboardInterrupt:
        print ''
        return 'ERROR: user quit'


def main(args=None):
    """
    :param args: only for testing, should be a string
    """
    if args:
        args = shlex.split(args)
    else:
        args = sys.argv[1:]
    preparse_args, extra_args = preparser.parse_known_args(args)
    configure_logging(preparse_args.verbose)

    if preparse_args.version:
        # print version and leave
        print 'kinetic library version "%s"' % kinetic.__version__
        print 'protocol version "%s"' % kinetic.protocol_version
        errorcode = 0
    elif extra_args:
        errorcode = handle_command(args)
    else:
        errorcode = handle_loop(**vars(preparse_args))
    return errorcode


if __name__ == "__main__":
    sys.exit(main())
