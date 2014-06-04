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

import logging
from kinetic import baseclient
from kinetic import operations

class AdminClient(baseclient.BaseClient):

    def __init__(self, *args, **kwargs):
        if 'socket_timeout' not in kwargs:
            kwargs['socket_timeout'] = 60.0
        super(AdminClient, self).__init__(*args, **kwargs)

    # TODO(Nacho): this code is duplicated with client... not sure if its worth refactoring
    # it's pretty generic, maybe we can move it to the baseclient or something
    def _process(self, op, *args, **kwargs):
        header, value = op.build(*args, **kwargs)
        try:
            with self:
                # update header
                self.update_header(header)
                # send message synchronously
                r, v = self.send(header, value)
            return op.parse(r,v)
        except Exception as e:
            return op.onError(e)

    def getLog(self,*args, **kwargs):
        return self._process(operations.GetLog, *args, **kwargs)

    def setPin(self, new_pin, pin=None):
        return self._process(operations.Setup, pin=pin, setPin=new_pin)

    def instantSecureErase(self, pin=None):
        return self._process(operations.Setup, instantSecureErase=True, pin=pin)

    def setClusterVersion(self, cluster_version, pin=None):
        return self._process(operations.Setup, newClusterVersion=cluster_version, pin=pin)

    def updateFirmware(self, binary, pin=None):
        return self._process(operations.Setup, firmware=binary, pin=pin)

    def setSecurity(self, userACLList):
        """
            Set the access control lists to lock users out of different permissions.
            Arguments: aclList -> A list of ACL (Access Control List) objects.
        """
        return self._process(operations.Security, ACLList = userACLList)

def main():
    from kinetic.common import LogTypes
    from kinetic import Client

    logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)

    client = AdminClient("localhost",8123)
    client.connect()

    #print client.getLog([LogTypes.Utilization, LogTypes.Temperature, LogTypes.Capacity])
    #print client.getLog(LogTypes.all())

    with Client("localhost",8123) as nc:
        nc.delete("id")
        nc.put("id","1234")
        print nc.get("id")
        #client.setPin("111")
        print client.instantSecureErase("111")
        #print client.setClusterVersion(1200,"111")
        print nc.get("id")

    try:
        input("Press [Enter] to exit.\n")
    except: None

if __name__ == "__main__":
    main()
