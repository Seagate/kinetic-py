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

#@author: Robert Cope

from kinetic import Client
from kinetic import AdminClient
from kinetic import KineticMessageException
from base import BaseTestCase
from kinetic import common
from kinetic.common import KineticException
import kinetic.kinetic_pb2 as messages


class AdminClientTestCase(BaseTestCase):

    DEFAULT_CLUSTER_VERSION = 0
    MAX_KEY_SIZE = 4096
    MAX_VALUE_SIZE = 1024 * 1024
    MAX_VERSION_SIZE = 2048
    MAX_KEY_RANGE_COUNT = 200

    def setUp(self):
        super(AdminClientTestCase, self).setUp()
        self.adminClient = AdminClient(self.host, self.port)
        self.adminClient.connect()

    def tearDown(self):
        self.adminClient.close()

    def test_setSecurity(self):

        self.client.put(self.buildKey(1), "test_value_1")

        acl = common.ACL(identity=100)
        domain = common.Domain(roles=[common.Roles.READ])
        acl.domains = [domain]

        if self.adminClient.use_ssl:
            self.adminClient.setSecurity([acl])

            # Verify user 100 can only read
            read_only_client = Client(self.host, self.port, identity=100)
            read_only_client.get(self.buildKey(1))  # Should be OK.
            args = (self.buildKey(2), 'test_value_2')
            self.assertRaises(KineticMessageException, read_only_client.put, *args)
        else:
            try:
                #TODO: change this to self.assertRaises
                self.adminClient.setSecurity([acl])
            except KineticException:
                pass
            else:
                self.fail('Exception should be thrown if not using SSL')

    def test_get_capacity(self):
        log = self.adminClient.getLog([messages.Command.GetLog.CAPACITIES])
        self.assertIsNotNone(log)

        capacity = log.capacity
        self.assertIsNotNone(capacity)

        self.assertTrue(capacity.portionFull >= 0)
        self.assertTrue(capacity.nominalCapacityInBytes >= 0)

    def test_get_capacity_and_utilization(self):
        log = self.adminClient.getLog([messages.Command.GetLog.CAPACITIES, messages.Command.GetLog.UTILIZATIONS])
        self.assertIsNotNone(log)

        capacity = log.capacity
        self.assertIsNotNone(capacity)

        self.assertTrue(capacity.portionFull >= 0)
        self.assertTrue(capacity.nominalCapacityInBytes >= 0)

        util_list = log.utilizations

        for util in util_list:
            self.assertTrue(util.value >= 0)

    def test_get_configuration(self):
        log = self.adminClient.getLog([messages.Command.GetLog.CONFIGURATION])
        self.assertIsNotNone(log)

        configuration = log.configuration
        self.assertIsNotNone(configuration)

        self.assertTrue(len(configuration.compilationDate) > 0)
        self.assertTrue(len(configuration.model) > 0)
        self.assertTrue(configuration.port >= 0)
        self.assertTrue(configuration.tlsPort >= 0)
        self.assertTrue(len(configuration.serialNumber) > 0)
        self.assertTrue(len(configuration.sourceHash) > 0)
        self.assertTrue(len(configuration.vendor) > 0)
        self.assertTrue(len(configuration.version) > 0)

        for interface in configuration.interface:
            self.assertTrue(len(interface.name) > 0)

    def test_get_limits(self):
        log = self.adminClient.getLog([messages.Command.GetLog.LIMITS])
        self.assertIsNotNone(log)

        limits = log.limits
        self.assertIsNotNone(limits)

        self.assertTrue(limits.maxKeySize == AdminClientTestCase.MAX_KEY_SIZE)
        self.assertTrue(limits.maxValueSize == AdminClientTestCase.MAX_VALUE_SIZE)
        self.assertTrue(limits.maxVersionSize == AdminClientTestCase.MAX_VERSION_SIZE)
        self.assertTrue(limits.maxKeyRangeCount == AdminClientTestCase.MAX_KEY_RANGE_COUNT)

    def test_get_log(self):
        #TODO: is there a way to specify all types without explicitly enumerating them all?
        log = self.adminClient.getLog([messages.Command.GetLog.TEMPERATURES, messages.Command.GetLog.UTILIZATIONS,
                                       messages.Command.GetLog.STATISTICS, messages.Command.GetLog.MESSAGES,
                                       messages.Command.GetLog.CAPACITIES, messages.Command.GetLog.LIMITS])
        self.assertIsNotNone(log)

        self.assertTrue(len(log.temperatures) > 0)
        self.assertTrue(len(log.utilizations) > 0)
        self.assertTrue(len(log.statistics) > 0)
        self.assertTrue(log.messages > 0)
        self.assertTrue(log.capacity.portionFull >= 0)
        self.assertTrue(log.capacity.nominalCapacityInBytes >= 0)
        self.assertTrue(log.limits.maxKeySize == AdminClientTestCase.MAX_KEY_SIZE)
        self.assertTrue(log.limits.maxValueSize == AdminClientTestCase.MAX_VALUE_SIZE)
        self.assertTrue(log.limits.maxVersionSize == AdminClientTestCase.MAX_VERSION_SIZE)
        self.assertTrue(log.limits.maxKeyRangeCount == AdminClientTestCase.MAX_KEY_RANGE_COUNT)

    def test_get_temperature(self):
        log = self.adminClient.getLog([messages.Command.GetLog.TEMPERATURES])
        self.assertIsNotNone(log)

        for temperature in log.temperatures:
            self.assertTrue(temperature.current >= 0)
            self.assertTrue(temperature.maximum >= 0)

    def test_get_temperature_and_capacity(self):
        log = self.adminClient.getLog([messages.Command.GetLog.TEMPERATURES, messages.Command.GetLog.CAPACITIES])
        self.assertIsNotNone(log)

        for temperature in log.temperatures:
            self.assertTrue(temperature.current >= 0)
            self.assertTrue(temperature.maximum >= 0)

        capacity = log.capacity
        self.assertIsNotNone(capacity)

        self.assertTrue(capacity.portionFull >= 0)
        self.assertTrue(capacity.nominalCapacityInBytes >= 0)

    def test_get_temperature_and_capacity_and_utilization(self):
        log = self.adminClient.getLog([messages.Command.GetLog.TEMPERATURES, messages.Command.GetLog.CAPACITIES,
                                       messages.Command.GetLog.UTILIZATIONS])
        self.assertIsNotNone(log)

        for temperature in log.temperatures:
            self.assertTrue(temperature.current >= 0)
            self.assertTrue(temperature.maximum >= 0)

        capacity = log.capacity
        self.assertIsNotNone(capacity)

        self.assertTrue(capacity.portionFull >= 0)
        self.assertTrue(capacity.nominalCapacityInBytes >= 0)

        util_list = log.utilizations

        for util in util_list:
            self.assertTrue(util.value >= 0)

    def test_get_temperature_and_utilization(self):
        log = self.adminClient.getLog([messages.Command.GetLog.TEMPERATURES, messages.Command.GetLog.UTILIZATIONS])
        self.assertIsNotNone(log)

        for temperature in log.temperatures:
            self.assertTrue(temperature.current >= 0)
            self.assertTrue(temperature.maximum >= 0)

        util_list = log.utilizations

        for util in util_list:
            self.assertTrue(util.value >= 0)

    def test_get_utilization(self):
        log = self.adminClient.getLog([messages.Command.GetLog.UTILIZATIONS])
        self.assertIsNotNone(log)

        util_list = log.utilizations

        for util in util_list:
            self.assertTrue(util.value >= 0)

    def reset_cluster_version_to_default(self):
        c = AdminClient(self.host, self.port)
        c.setClusterVersion(AdminClientTestCase.DEFAULT_CLUSTER_VERSION)
        c.close()

    def test_set_cluster_version(self):
        new_cluster_version = AdminClientTestCase.DEFAULT_CLUSTER_VERSION + 1
        self.adminClient.setClusterVersion(new_cluster_version)
        self.reset_cluster_version_to_default()

    def test_update_firmware(self):
        #TODO: implement test_update_firmware
        pass

    def test_unlock(self):
        #TODO: implement test_unlock
        if self.adminClient.use_ssl:
            pass
        else:
            self.assertRaises(KineticException)

    def test_lock(self):
        #TODO: implement test_lock
        if self.adminClient.use_ssl:
            pass
        else:
            self.assertRaises(KineticException)

    def test_erase(self):
        #TODO: implement test_erase
        if self.adminClient.use_ssl:
            pass
        else:
            self.assertRaises(KineticException)

    def test_instance_secure_erase(self):
        #TODO: implement test_instance_secure_erase
        if self.adminClient.use_ssl:
            pass
        else:
            self.assertRaises(KineticException)

    def test_set_erase_pin(self):
        #TODO: implement test_set_erase_pin
        if self.adminClient.use_ssl:
            pass
        else:
            self.assertRaises(KineticException)

    def test_set_lock_pin(self):
        #TODO: implement test_set_lock_pin
        if self.adminClient.use_ssl:
            pass
        else:
            self.assertRaises(KineticException)

    def test_set_acl(self):
        #TODO: implement test_set_acl
        if self.adminClient.use_ssl:
            pass
        else:
            self.assertRaises(KineticException)

