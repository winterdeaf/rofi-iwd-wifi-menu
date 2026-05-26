import io
import os
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from iwdrofimenu.iwd_rofi_dialogs import RofiNetworkList


class _FakeIWD:
    def __init__(self, state, connected_network_path=None):
        self._state = state
        self._connected_network_path = connected_network_path

    def update_known_networks(self):
        return {}

    def get_networks(self):
        return [
            {
                "path": "/net/1",
                "ssid": "Cafe WiFi",
                "security": "open",
                "quality": 5,
                "connected": True,
                "known": True,
            }
        ]

    def update_connection_state(self, refresh=True):
        del refresh
        return dict(self._state)

    def connected_network_path(self):
        return self._connected_network_path


class RofiNetworkListTests(unittest.TestCase):
    def test_connecting_network_is_marked_urgent_not_active(self):
        iwd = _FakeIWD({"State": "Connecting"}, connected_network_path="/net/1")
        buf = io.StringIO()

        with patch.dict(os.environ, {}, clear=True):
            with redirect_stdout(buf):
                RofiNetworkList(iwd)

        output = buf.getvalue()
        self.assertNotIn("\0active\x1f3\n", output)
        self.assertIn("\0urgent\x1f3\n", output)

    def test_connected_network_is_marked_active(self):
        iwd = _FakeIWD({"State": "Connected"}, connected_network_path="/net/1")
        buf = io.StringIO()

        with patch.dict(os.environ, {}, clear=True):
            with redirect_stdout(buf):
                RofiNetworkList(iwd)

        output = buf.getvalue()
        self.assertIn("\0active\x1f3\n", output)


if __name__ == "__main__":
    unittest.main()
