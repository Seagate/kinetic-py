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

import struct

from common import KeyRange

def buildRange(key):
    import array
    inBytes = map(ord,key)
    inBytes[len(inBytes)-1] = inBytes[len(inBytes)-1]+1
    keyPlus1 = array.array('B', inBytes).tostring()
    return KeyRange(key, keyPlus1, True, False)
