from unittest import TestCase
from simulator.rsk.netparams import NetworkUpgrades, NetworkParameters

import logging

logging.disable(logging.CRITICAL)


class TestNetworkParameters(TestCase):
    def test_construct(self):
        nu = NetworkUpgrades(wasabi=123)
        params = NetworkParameters(nu)
        self.assertEqual(params.network_upgrades, nu)
        self.assertEqual(params.name, None)

    def test_construct_with_name(self):
        nu = NetworkUpgrades(wasabi=123)
        params = NetworkParameters(nu, name="a-name")
        self.assertEqual(params.name, "a-name")

    def test_invalid_upgrades(self):
        with self.assertRaises(TypeError):
            NetworkParameters(123)


class TestNetworkUpgrades(TestCase):
    def setUp(self):
        self.netupgrades = NetworkUpgrades(wasabi=100, papyrus=200, somethingelse=None)

    def test_getter(self):
        self.assertEqual(100, self.netupgrades.get("wasabi"))
        self.assertEqual(200, self.netupgrades.get("papyrus"))
        self.assertEqual(None, self.netupgrades.get("somethingelse"))

    def test_getter_doesnotexist(self):
        with self.assertRaises(KeyError):
            self.netupgrades.get("doesnotexist")

    def test_is_active(self):
        self.assertTrue(self.netupgrades.is_active("wasabi", 101))
        self.assertTrue(self.netupgrades.is_active("wasabi", 100))
        self.assertTrue(self.netupgrades.is_active("wasabi", 200))
        self.assertFalse(self.netupgrades.is_active("wasabi", 10))
        self.assertFalse(self.netupgrades.is_active("wasabi", 99))

        self.assertTrue(self.netupgrades.is_active("papyrus", 201))
        self.assertTrue(self.netupgrades.is_active("papyrus", 200))
        self.assertTrue(self.netupgrades.is_active("papyrus", 200))
        self.assertFalse(self.netupgrades.is_active("papyrus", 110))
        self.assertFalse(self.netupgrades.is_active("papyrus", 199))

        self.assertFalse(self.netupgrades.is_active("somethingelse", 0))
        self.assertFalse(self.netupgrades.is_active("somethingelse", 1))
        self.assertFalse(self.netupgrades.is_active("somethingelse", 1_000_000))

    def test_is_active_doesnotexist(self):
        with self.assertRaises(KeyError):
            self.netupgrades.is_active("doesnotexist", 123)
