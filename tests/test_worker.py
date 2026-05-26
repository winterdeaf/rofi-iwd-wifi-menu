import unittest
from unittest.mock import patch

from iwdrofimenu.iwd_dbus import IWD
from iwdrofimenu.main import run_connect_worker


class _WorkerIWD:
    instances = []
    ConnectionResult = IWD.ConnectionResult
    result = IWD.ConnectionResult.SUCCESS
    last_error_value = None

    def __init__(self, device):
        self.device = device
        self.last_error = self.__class__.last_error_value
        self.last_error_user_friendly = False
        self.closed = False
        self.connect_calls = []
        _WorkerIWD.instances.append(self)

    def connect(self, network_path, passphrase=None, timeout=30):
        self.connect_calls.append((network_path, passphrase, timeout))
        return self.__class__.result

    def close(self):
        self.closed = True


class _WorkerFailureIWD(_WorkerIWD):
    result = IWD.ConnectionResult.NOT_SUCCESSFUL
    last_error_value = "dbus failed"


class WorkerTests(unittest.TestCase):
    def setUp(self):
        _WorkerIWD.instances.clear()

    def test_run_connect_worker_disables_client_timeout_and_is_silent_on_success(self):
        with patch("iwdrofimenu.main.IWD", _WorkerIWD), patch("iwdrofimenu.main._notify") as notify:
            result = run_connect_worker("wlan0", "/net/1", "Cafe WiFi", "secret")

        self.assertEqual(result, 0)
        self.assertEqual(_WorkerIWD.instances[-1].connect_calls, [("/net/1", "secret", 0)])
        self.assertTrue(_WorkerIWD.instances[-1].closed)
        notify.assert_not_called()

    def test_run_connect_worker_notifies_on_failure(self):
        with patch("iwdrofimenu.main.IWD", _WorkerFailureIWD), patch("iwdrofimenu.main._notify") as notify:
            result = run_connect_worker("wlan0", "/net/1", "Cafe WiFi")

        self.assertEqual(result, 1)
        self.assertTrue(_WorkerIWD.instances[-1].closed)
        notify.assert_called_once()
        self.assertIn("Cafe WiFi", notify.call_args.args[0])
        self.assertEqual(notify.call_args.args[1], "dbus failed")


if __name__ == "__main__":
    unittest.main()
