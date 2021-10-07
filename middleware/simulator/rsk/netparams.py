# The MIT License (MIT)
#
# Copyright (c) 2021 RSK Labs Ltd
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import json


class NetworkUpgrades:
    wasabi = "wasabi"
    papyrus = "papyrus"
    iris = "iris"

    @staticmethod
    def from_dict(dict):
        return NetworkUpgrades(**dict)

    def __init__(self, **kwargs):
        self._upgrades = kwargs.copy()

    def get(self, upgrade_name):
        return self._upgrades[upgrade_name]

    def to_dict(self):
        return self._upgrades.copy()

    def is_active(self, upgrade_name, block_number):
        abn = self.get(upgrade_name)
        return abn <= block_number if abn is not None else False


NetworkUpgrades.MAINNET = NetworkUpgrades(
    wasabi=1_591_000,
    papyrus=2_392_700,
    iris=3_614_800,
)

NetworkUpgrades.TESTNET = NetworkUpgrades(
    wasabi=0,
    papyrus=863_000,
    iris=2_060_500,
)

NetworkUpgrades.REGTEST = NetworkUpgrades(
    wasabi=0,
    papyrus=0,
    iris=0,
)


class NetworkParameters:
    @staticmethod
    def from_string(s):
        # By name?
        if type(s) == str and not s.startswith("{"):
            return NetworkParameters.by_name(s)

        # JSON spec
        try:
            return NetworkParameters.from_dict(json.loads(s))
        except Exception as e:
            raise ValueError("Invalid network parameters '%s': %s" % (s, str(e)))

    @staticmethod
    def from_dict(dict):
        return NetworkParameters(
            network_upgrades=NetworkUpgrades.from_dict(dict["network_upgrades"]))

    @staticmethod
    def by_name(name):
        try:
            return NetworkParameters.BY_NAME[name]
        except Exception as e:
            raise ValueError("Invalid network parameters name '%s': %s" % (name, str(e)))

    def __init__(self, network_upgrades, name=None):
        if type(network_upgrades) != NetworkUpgrades:
            raise TypeError("Expected an instance of NetworkUpgrades but got a '%s'" %
                            type(network_upgrades).__name__)
        self._network_upgrades = network_upgrades
        self._name = name

    @property
    def name(self):
        return self._name

    def to_dict(self):
        return {"network_upgrades": self._network_upgrades.to_dict()}

    @property
    def network_upgrades(self):
        return self._network_upgrades

    def __str__(self):
        return json.dumps(self.to_dict(), indent=2)


NetworkParameters.MAINNET = NetworkParameters(name="mainnet",
                                              network_upgrades=NetworkUpgrades.MAINNET)
NetworkParameters.TESTNET = NetworkParameters(name="testnet",
                                              network_upgrades=NetworkUpgrades.TESTNET)
NetworkParameters.REGTEST = NetworkParameters(name="regtest",
                                              network_upgrades=NetworkUpgrades.REGTEST)
NetworkParameters.BY_NAME = {
    "mainnet": NetworkParameters.MAINNET,
    "testnet": NetworkParameters.TESTNET,
    "regtest": NetworkParameters.REGTEST,
}
