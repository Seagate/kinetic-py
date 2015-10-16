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
from kinetic.deprecated import BlockingClient
from kinetic import operations
from kinetic.common import KineticException
from functools import wraps
import warnings

def withPin(f):
    @wraps(f)
    def wrapper(self, *args, **kwargs):
        old = self.pin
        if 'pin' in kwargs:
            self.pin = kwargs['pin']
            del kwargs['pin']
        elif not self.pin:
            raise KineticException("This operation requires a pin.")

        try:
            f(self, *args, **kwargs)
        finally:
            self.pin = old
    return wrapper


def requiresSsl(f):
    @wraps(f)
    def wrapper(self, *args, **kwargs):
        if not self.use_ssl:
            raise KineticException("This operation requires SSL.")
        f(self, *args, **kwargs)
    return wrapper


class SecureClient(BlockingClient):

    def __init__(self, *args, **kwargs):
        kwargs['use_ssl'] = True
        # len() < 2 is because port can be positional on the baseclient
        if 'port' not in kwargs and len(args) < 2:
            kwargs['port'] = 8443
                
        super(SecureClient, self).__init__(*args, **kwargs)

    @withPin
    @requiresSsl
    def unlock(self, *args, **kwargs):
        return self._process(operations.UnlockDevice(), *args, **kwargs)

    @withPin
    @requiresSsl
    def lock(self, *args, **kwargs):
        return self._process(operations.LockDevice(), *args, **kwargs)

    @withPin
    @requiresSsl
    def erase(self, *args, **kwargs):
        return self._process(operations.EraseDevice(), *args, **kwargs)

    @withPin
    @requiresSsl
    def instantSecureErase(self, *args, **kwargs):
        return self._process(operations.SecureEraseDevice(), *args, **kwargs)

    @requiresSsl
    def setErasePin(self, *args, **kwargs):
        return self._process(operations.SetErasePin(), *args, **kwargs)

    @requiresSsl
    def setLockPin(self, *args, **kwargs):
        return self._process(operations.SetLockPin(), *args, **kwargs)

    @requiresSsl
    def setACL(self, *args, **kwargs):
        return self._process(operations.SetACL(), *args, **kwargs)

    @requiresSsl
    def setSecurity(self, *args, **kwargs):
        """
            Set the access control lists to lock users out of different permissions.
            Arguments: aclList -> A list of ACL (Access Control List) objects.
        """
        warnings.warn(
            "Shouldn't use this function anymore! Use setErasePin/setLockPin/setACL instead.",
            DeprecationWarning
        )
        return self._process(operations.Security(), *args, **kwargs)

