import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from iwdrofimenu.actions import encode_action
from iwdrofimenu.main import Main


class _FakeIWD:
    instances = []

    def __init__(self, device):
        self.device = device
        self.scan_calls = 0
        _FakeIWD.instances.append(self)

    def scan(self):
        self.scan_calls += 1
        return True


class _FakeNetworkList:
    def __init__(self, iwd, message=None, data=None, combi_mode=False):
        self.iwd = iwd
        self.message = message
        self.data = data
        self.combi_mode = combi_mode


class MainTests(unittest.TestCase):
    def setUp(self):
        _FakeIWD.instances.clear()
        self.args = SimpleNamespace(arg="", combi_mode=False)

    def test_initial_render_auto_scans(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch("iwdrofimenu.main.IWD", _FakeIWD), patch("iwdrofimenu.main.RofiNetworkList", _FakeNetworkList):
                Main("wlan0", self.args)

        self.assertEqual(_FakeIWD.instances[-1].scan_calls, 1)

    def test_action_invocation_skips_auto_scan(self):
        env = {"ROFI_INFO": encode_action("abort")}
        with patch.dict(os.environ, env, clear=True):
            with patch("iwdrofimenu.main.IWD", _FakeIWD), patch("iwdrofimenu.main.RofiNetworkList", _FakeNetworkList):
                Main("wlan0", self.args)

        self.assertEqual(_FakeIWD.instances[-1].scan_calls, 0)

    def test_scan_action_still_scans_once(self):
        env = {"ROFI_INFO": encode_action("scan")}
        with patch.dict(os.environ, env, clear=True):
            with patch("iwdrofimenu.main.IWD", _FakeIWD), patch("iwdrofimenu.main.RofiNetworkList", _FakeNetworkList):
                Main("wlan0", self.args)

        self.assertEqual(_FakeIWD.instances[-1].scan_calls, 1)


if __name__ == "__main__":
    unittest.main()
