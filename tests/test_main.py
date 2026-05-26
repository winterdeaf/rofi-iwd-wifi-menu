import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from iwdrofimenu.actions import encode_action
from iwdrofimenu.main import Main, WORKER_PASSPHRASE_ENV


class _FakeIWD:
    instances = []
    state = {"State": "Disconnected"}
    network = {
        "path": "/net/1",
        "ssid": "Test WiFi",
        "security": "open",
        "known": True,
    }

    def __init__(self, device):
        self.device = device
        self.scan_calls = 0
        self.last_error = None
        self.last_error_user_friendly = False
        self.state = dict(self.__class__.state)
        self.network = dict(self.__class__.network)
        _FakeIWD.instances.append(self)

    def scan(self):
        self.scan_calls += 1
        return True

    def get_state(self, key):
        return self.state.get(key)

    def ssid(self):
        return self.state.get("Connected network")

    def connected_network_path(self):
        return self.state.get("Connected network path")

    def update_connection_state(self, refresh=True):
        del refresh
        return self.state

    def get_network(self, path, refresh=True):
        del refresh
        if path != self.network["path"]:
            return None
        return dict(self.network)

    def disconnect(self):
        return True

    def forget(self, path=None):
        del path
        return True


class _ConnectingIWD(_FakeIWD):
    state = {
        "State": "Connecting",
        "Connected network": "Test WiFi",
        "Connected network path": "/net/1",
    }


class _FakeNetworkList:
    calls = []

    def __init__(self, iwd, message=None, data=None, combi_mode=False):
        _FakeNetworkList.calls.append(
            {
                "iwd": iwd,
                "message": message,
                "data": data,
                "combi_mode": combi_mode,
            }
        )


class MainTests(unittest.TestCase):
    def setUp(self):
        _FakeIWD.instances.clear()
        _FakeNetworkList.calls.clear()
        self.args = SimpleNamespace(arg="", combi_mode=False, verbose=False)

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

    def test_initial_render_shows_connecting_message_from_iwd_state(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch("iwdrofimenu.main.IWD", _ConnectingIWD), patch("iwdrofimenu.main.RofiNetworkList", _FakeNetworkList):
                Main("wlan0", self.args)

        self.assertEqual(_FakeNetworkList.calls[-1]["message"], "Connecting to Test WiFi...")

    def test_connect_action_spawns_background_worker(self):
        env = {"ROFI_INFO": encode_action("connect", network_path="/net/1", ssid="Test WiFi")}
        with patch.dict(os.environ, env, clear=True):
            with patch("iwdrofimenu.main.IWD", _FakeIWD), patch("iwdrofimenu.main.RofiNetworkList", _FakeNetworkList), patch("iwdrofimenu.main.subprocess.Popen") as popen:
                Main("wlan0", self.args)

        command = popen.call_args.args[0]
        self.assertIn("--connect-worker", command)
        self.assertIn("--worker-network-path", command)
        self.assertIn("/net/1", command)
        self.assertIn("--worker-ssid", command)
        self.assertIn("Test WiFi", command)
        self.assertEqual(_FakeNetworkList.calls[-1]["message"], "Connecting to Test WiFi...")

    def test_passphrase_connect_spawns_background_worker_with_env(self):
        env = {"ROFI_DATA": encode_action("connect_with_passphrase", network_path="/net/1", ssid="Test WiFi")}
        args = SimpleNamespace(arg="hunter2", combi_mode=False, verbose=False)
        with patch.dict(os.environ, env, clear=True):
            with patch("iwdrofimenu.main.IWD", _ConnectingIWD), patch("iwdrofimenu.main.RofiNetworkList", _FakeNetworkList), patch("iwdrofimenu.main.subprocess.Popen") as popen:
                Main("wlan0", args)

        worker_env = popen.call_args.kwargs["env"]
        self.assertEqual(worker_env[WORKER_PASSPHRASE_ENV], "hunter2")
        self.assertEqual(_FakeNetworkList.calls[-1]["data"], "")
        self.assertEqual(_FakeNetworkList.calls[-1]["message"], "Connecting to Test WiFi...")


if __name__ == "__main__":
    unittest.main()
