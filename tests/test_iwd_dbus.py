import asyncio
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
