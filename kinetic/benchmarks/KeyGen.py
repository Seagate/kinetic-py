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

#@author: Tim Feldman

import random
import string
import sys

# Generates a random key as a string of size 1 to maxKeySize
# bytes with values of minByte to maxByte, inclusive, and
# with equal probability for all possible keys.
# Note that with a large number of possible keys, approximately
# pow(1 + maxByte - minByte, maxKeySize), the limits of float precision
# results in all keys being maxKeySize in length. This is the case, for
# instance, with byte values of 0 to 255 and max key sizes of 128 or
# larger.
# Defaults are for common Kinetic keys.
# Notes on the distribution of keys by size:
# For a number of values per byte, v, v = 1 + maxByte - minByte,
#     and a number of keys, x, x = maxKeySize,
# the number of keys by size, k, is
#     v^k / totalKeys
# where totalKeys is v + v^2 + v^3 + ... + v^x.
# A list of the probabilities of keys by key size is
#     size  probability
#     1      v  / (v + v^2 + v^3 + ... + v^x)
#     2     v^2 / (v + v^2 + v^3 + ... + v^x)
#     3     v^3 / (v + v^2 + v^3 + ... + v^x)
#     ...   ...
#     n     v^n / (v + v^2 + v^3 + ... + v^x)
#     ...   ...
#     x     v^x / (v + v^2 + v^3 + ... + v^x)
# These are very large, difficult to calculate numbers when v^x is large
# compared to 1/epsilon.
# An approximation for the likelihood of a key of size k is
#     (v / (v + 1))^(1 + x - k)
# A list of these approximate probabilities of keys by key size is
#     size  probability
#     1     (v / (v + 1))^x
#     2     (v / (v + 1))^(x - 1)
#     3     (v / (v + 1))^(x - 3)
#     ...   ...
#     n     (v / (v + 1))^(1 + x - n)
#     ...
#     x      v / (v + 1)
# Note that in this approximation, many of the smaller probabilities will be
# zero in this program and other limited-precision calculations.
def GenerateRandomKey(minByte=0, maxByte=255, maxKeySize=32):
    assert(maxKeySize > 0)
    assert(0 <= minByte <= 255)
    assert(minByte <= maxByte <= 255)

    values = 1 + maxByte - minByte    # local shorthand

    # First determine the size of the key to generate.
    # There is an accurate method that works only with smaller key ranges
    # and an approximate method that works for larger key ranges.
    try:
        totalKeys = sum(pow(values, k) for k in range(1, maxKeySize + 1))
        # Compare a random pick to thresholds for the cumulative
        # likelihood of successively smaller key sizes.
        pick = random.random()
        numKeysOfKeySizeAndLarger = 0
        for keySize in range(maxKeySize, 1, -1):
            numKeysOfKeySizeAndLarger = numKeysOfKeySizeAndLarger + \
                                        pow(values, keySize)
            portion = float(numKeysOfKeySizeAndLarger) / numKeys
            if pick <= portion:
                break
    except:
        while True:
            keySize = maxKeySize
            while keySize > 0:
                if random.randint(0, maxByte+1) == 0:   # a 1 out of maxByte+1 chance
                    keySize = keySize - 1
                else:
                     break
            if keySize != 0:
                break
            # Else there were maxKeySize zeros in a row
            # and a valid key size was not found
            # so re-start the attempt to get a key size.

    # keySize is now the size of the key to generate
    # with a distribution of size proportional to the
    # representation in the set of all keys.

    key = "".join(chr(random.randint(minByte, maxByte)) \
            for i in range(keySize))

    return key


# Generates the next key, a string with bytes of minByte to maxByte,
# inclusive, in lexographical order after the specified key.
# The key after a key of size maxKeySize with bytes of all maxByte is
# a key with one byte whose value is minByte.
# Defaults are for common Kinetic keys.
def GenerateSequentialKey(key, minByte=0, maxByte=255, maxKeySize=32):
    assert(isinstance(key, str))
    assert(len(key) <= maxKeySize)
    assert(0 <= minByte <= 255)
    assert(minByte <= maxByte <= 255)

    if len(key) == maxKeySize:
        while (len(key) > 0) and (ord(key[-1]) == maxByte):
            key = key[:-1]
        if len(key) == 0:
            key = chr(minByte)
        else:
            newChar = chr(ord(key[-1]) + 1)
            key = key[:-1] + newChar
    else:
        key = key + chr(minByte)

    return key


# Generate a display string for a key.
# Only keys with maximum values of 255 are supported; that is, a set
# of bytes. The display string shows each byte as a pair of hexadecimal
# numerals. Groups of four bytes or 8 hex numerals are delimited by a
# space. There is a new line every 32 bytes. Each line is additionally
# completed with the ASCII equivalent for non-whitespace printable
# values and whitespace and non-printable values represented by a dot.
def KeyToDisplayString (instr):
    bytesPerGroup = 4
    groupDelimiter = ' '
    bytesPerLine = 32
    nonprintableGlyph = '.'
    outstr = ""
    asciistr = ""
    for i in range(len(instr)):
        c = instr[i]
        outstr = outstr + "".join("{0:02x}".format(ord(c)))
        if ((c in string.digits) or (c in string.letters) or
                (c in string.punctuation)):
            asciistr = asciistr + c
        else:
            asciistr = asciistr + nonprintableGlyph
        if (i % bytesPerLine == bytesPerLine - 1):
            outstr = outstr + "  " + asciistr
            asciistr = ""
            if i != len(instr) - 1:
                outstr = outstr + '\n'
        elif (i % bytesPerGroup == bytesPerGroup - 1) and \
                (i != len(instr) - 1):
            outstr = outstr + groupDelimiter
            asciistr = asciistr + groupDelimiter

    # Generate blank fill after hex and then append last asciistr.
    for j in range(bytesPerLine - (len(instr) % bytesPerLine)):
        outstr = outstr + "  "
        if j % bytesPerGroup == bytesPerGroup - 1:
            outstr = outstr + " "
    outstr = outstr + "  " + asciistr

    return outstr


def main ():
    # The generate functions support strings of values from minByte to
    # maxByte, inclusive.
    # The intended use of low (maxByte-minByte) values is to get from
    # the random key generator a higher frequency of keys of less than
    # maxKeySize and keys for which the sequential key is shorter.
    # The intended use of the minByte to maxByte range as non-whitespace
    # printable values is to have complete ASCII strings.
    minByte = ord('a')    # as low as 0 for Kinetic
    maxByte = ord('z')    # up to 255 for Kinetic

    # Generate and print pairs of keys, the first of each pair is a
    # random key and the second is sequential to it.
    print ("Random keys and their sequential key")
    for i in range(50):
        randKey = GenerateRandomKey(minByte, maxByte)
        print "rand:\n", KeyToDisplayString(randKey)
        print "seql:\n", KeyToDisplayString(GenerateSequentialKey(
              randKey, minByte, maxByte))
        print

    # Run the corner cases of the first key in the lexographical order
    # and the last key in the lexographical order.
    print "Corner cases, default size, min and max byte values"
    firstKey = chr(0)
    print "first key:\n", KeyToDisplayString(firstKey)
    seqlKey = GenerateSequentialKey(firstKey)
    print "seql:\n", KeyToDisplayString(seqlKey)
    lastKey = "".join([chr(255) for x in range(32)])
    print "\nlast key:\n", KeyToDisplayString(lastKey)
    seqlKey = GenerateSequentialKey(lastKey)
    print "seql:\n", KeyToDisplayString(seqlKey)
    print

    # Generate random keys and bin the sizes to check on the
    # distribution of sizes.
    print "Histogram of key sizes computation in progress"
    minByte = 0
    maxByte = 255
    maxKeySize = 32
    numKeys = 1000000
    sizeBin = [0] * (maxKeySize + 1)    # the index of sizeBin is the key size
    for i in range(numKeys):
        # Print a progress indicator.
        if i % 100 == 0:
            print "\r %f%% done " % (100.0 * i / numKeys),
        # Get a random key and bin it by size.
        length = len(GenerateRandomKey(minByte, maxByte, maxKeySize))
        sizeBin[length] = sizeBin[length] + 1
    # Print the results.
    print "Histogram of key sizes"
    print "min byte value =", minByte, "; max byte value =", maxByte, \
            "; max key size =", maxKeySize, \
            "; number of keys to generate=", numKeys
    values = 1 + maxByte - minByte    # local shorthand
    numPossibleKeys = sum(pow(values, k) for k in range(1, maxKeySize + 1))
    print "key size   num of keys  portion of total  num expected"
    for i in range(1, maxKeySize+1):
        try:
            numExpected = float(numKeys * pow(values, i)) / numPossibleKeys
            print "%8d   %8d        %8.4f%%     %12.2f" % (
                    i, sizeBin[i], 100.0 * sizeBin[i] / numKeys, numExpected)
        except:
            numExpected = numKeys * pow(values, i) / numPossibleKeys
            print "%8d   %8d        %8.4f%%     %10d" % (
                    i, sizeBin[i], 100.0 * sizeBin[i] / numKeys, numExpected)


if __name__ == "__main__":
    main()

