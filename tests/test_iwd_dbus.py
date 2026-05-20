import asyncio
import types
import unittest
from unittest.mock import AsyncMock

from dbus_next.errors import InterfaceNotFoundError

from iwdrofimenu.iwd_dbus import IWD, STATION_DIAGNOSTIC_INTERFACE


class _FakeProxy:
    def __init__(self, interfaces):
        self.interfaces = interfaces

    def get_interface(self, name):
        if name not in self.interfaces:
            raise InterfaceNotFoundError(f"interface not found on this object: {name}")
        return self.interfaces[name]


class _FakeBus:
    def __init__(self, proxies):
        self._proxies = list(proxies)
        self.introspect_calls = []

    async def introspect(self, service, path):
        self.introspect_calls.append((service, path))
        return object()

    def get_proxy_object(self, service, path, introspection):
        del service, path, introspection
        return self._proxies.pop(0)


class IWDDbusTests(unittest.TestCase):
    def test_connect_honors_timeout(self):
        iwd = IWD.__new__(IWD)
        iwd._closed = False
        iwd._loop = asyncio.new_event_loop()
        iwd._bus = None
        iwd.last_error = None
        iwd.last_error_user_friendly = False
        iwd.get_network = lambda path: {"path": path, "security": "open", "known": True}
        iwd.update_connection_state = lambda refresh=True: None

        async def slow_connect(self, network_path, passphrase):
            del network_path, passphrase
            await asyncio.sleep(0.05)

        iwd._connect_network = types.MethodType(slow_connect, iwd)

        try:
            result = iwd.connect("/dev/path", timeout=0.01)
        finally:
            iwd.close()

        self.assertEqual(result, IWD.ConnectionResult.TIMEOUT)
        self.assertEqual(iwd.last_error, "Connection attempt timed out")

    def test_get_interface_reintrospects_when_cached_proxy_is_stale(self):
        cached_proxy = _FakeProxy({})
        fresh_interface = object()
        fresh_proxy = _FakeProxy({STATION_DIAGNOSTIC_INTERFACE: fresh_interface})

        iwd = IWD.__new__(IWD)
        iwd._proxy_cache = {"/dev/path": cached_proxy}
        iwd._bus = _FakeBus([fresh_proxy])

        interface = asyncio.run(iwd._get_interface("/dev/path", STATION_DIAGNOSTIC_INTERFACE))

        self.assertIs(interface, fresh_interface)
        self.assertEqual(len(iwd._bus.introspect_calls), 1)
        self.assertIs(iwd._proxy_cache["/dev/path"], fresh_proxy)

    def test_get_diagnostics_returns_empty_if_interface_disappears(self):
        iwd = IWD.__new__(IWD)
        iwd._device_path = "/dev/path"
        iwd._managed_objects = {"/dev/path": {STATION_DIAGNOSTIC_INTERFACE: {}}}
        iwd._get_interface = AsyncMock(side_effect=InterfaceNotFoundError("missing"))

        diagnostics = asyncio.run(iwd._get_diagnostics())

        self.assertEqual(diagnostics, {})


if __name__ == "__main__":
    unittest.main()
