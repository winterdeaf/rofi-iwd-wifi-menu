"""D-Bus based iwd integration.

This module talks directly to iwd instead of parsing iwctl output.
"""

from __future__ import annotations

import asyncio
import itertools
from dataclasses import dataclass
from enum import Enum
from typing import Any

from dbus_next import BusType, DBusError, Variant
from dbus_next.aio import MessageBus
from dbus_next.service import ServiceInterface, method

IWD_SERVICE = "net.connman.iwd"
OBJECT_MANAGER = "org.freedesktop.DBus.ObjectManager"
AGENT_MANAGER = "net.connman.iwd.AgentManager"
AGENT_INTERFACE = "net.connman.iwd.Agent"
DEVICE_INTERFACE = "net.connman.iwd.Device"
STATION_INTERFACE = "net.connman.iwd.Station"
STATION_DIAGNOSTIC_INTERFACE = "net.connman.iwd.StationDiagnostic"
NETWORK_INTERFACE = "net.connman.iwd.Network"
KNOWN_NETWORK_INTERFACE = "net.connman.iwd.KnownNetwork"
ROOT_PATH = "/"
AGENT_MANAGER_PATH = "/net/connman/iwd"


class IWDException(Exception):
    """Base exception for iwd D-Bus errors."""


@dataclass(slots=True)
class NetworkRecord:
    path: str
    ssid: str
    security: str
    signal_strength: int
    quality: int
    connected: bool
    known: bool
    known_network: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "ssid": self.ssid,
            "security": self.security,
            "signal_strength": self.signal_strength,
            "quality": self.quality,
            "connected": self.connected,
            "known": self.known,
            "known_network": self.known_network,
        }


class _PassphraseAgent(ServiceInterface):
    def __init__(self, passphrase: str):
        super().__init__(AGENT_INTERFACE)
        self.passphrase = passphrase

    @method()
    def Release(self) -> "":
        return

    @method()
    def RequestPassphrase(self, network: "o") -> "s":
        return self.passphrase

    @method()
    def RequestPrivateKeyPassphrase(self, network: "o") -> "s":
        return self.passphrase

    @method()
    def RequestUserNameAndPassword(self, network: "o") -> "ss":
        raise DBusError(f"{AGENT_INTERFACE}.Error.Canceled", "Unsupported")

    @method()
    def RequestUserPassword(self, network: "o", user: "s") -> "s":
        raise DBusError(f"{AGENT_INTERFACE}.Error.Canceled", "Unsupported")

    @method()
    def Cancel(self, reason: "s") -> "":
        return


class IWD:
    """Small synchronous wrapper around iwd's D-Bus API."""

    SECURITY_LABELS = {
        "open": "Open",
        "psk": "WPA-PSK",
        "8021x": "802.1X",
        "wep": "WEP",
        "hotspot": "Hotspot",
    }

    DETAIL_LABELS = [
        ("Connected network", "SSID"),
        ("State", "State"),
        ("Security", "Security"),
        ("ConnectedBss", "Access Point"),
        ("RSSI", "Signal"),
        ("AverageRSSI", "Average signal"),
        ("Frequency", "Frequency"),
        ("Channel", "Channel"),
        ("RxMode", "RX mode"),
        ("RxBitrate", "RX bitrate"),
        ("RxMCS", "RX MCS"),
        ("TxMode", "TX mode"),
        ("TxBitrate", "TX bitrate"),
        ("TxMCS", "TX MCS"),
        ("ConnectedTime", "Connected for"),
        ("InactiveTime", "Inactive for"),
        ("Device", "Device"),
        ("Scanning", "Scanning"),
    ]

    HIDDEN_STATE_KEYS = {"Connected network path", "Known network path"}

    class ConnectionResult(Enum):
        SUCCESS = 0
        NEED_PASSPHRASE = 1
        NOT_SUCCESSFUL = 2
        TIMEOUT = 3

    _agent_counter = itertools.count()

    def __init__(self, device: str = "wlan0"):
        self.device = device
        self.last_error: str | None = None
        self.last_error_user_friendly = False
        self.state: dict[str, Any] | None = None
        self.known_networks: dict[str, dict[str, Any]] = {}
        self.device_info: dict[str, Any] = {}
        self._managed_objects: dict[str, dict[str, dict[str, Any]]] = {}
        self._device_path: str | None = None
        self._proxy_cache: dict[str, Any] = {}
        self._closed = False
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._bus = self._run(self._connect())
        self.refresh()

    async def _connect(self) -> MessageBus:
        return await MessageBus(bus_type=BusType.SYSTEM).connect()

    def _run(self, coroutine):
        if self._closed:
            raise IWDException("IWD client is already closed")
        return self._loop.run_until_complete(coroutine)

    def close(self) -> None:
        if getattr(self, "_closed", True):
            return
        self._closed = True
        try:
            bus = getattr(self, "_bus", None)
            if bus is not None:
                bus.disconnect()
        except Exception:
            pass
        try:
            loop = getattr(self, "_loop", None)
            if loop is not None and not loop.is_closed():
                loop.close()
        except Exception:
            pass

    def __del__(self):
        self.close()

    @staticmethod
    def _unwrap(value: Any) -> Any:
        if isinstance(value, Variant):
            return IWD._unwrap(value.value)
        if isinstance(value, list):
            return [IWD._unwrap(item) for item in value]
        if isinstance(value, dict):
            return {key: IWD._unwrap(item) for key, item in value.items()}
        return value

    async def _get_proxy_object(self, path: str):
        proxy = self._proxy_cache.get(path)
        if proxy is not None:
            return proxy
        introspection = await self._bus.introspect(IWD_SERVICE, path)
        proxy = self._bus.get_proxy_object(IWD_SERVICE, path, introspection)
        self._proxy_cache[path] = proxy
        return proxy

    async def _get_interface(self, path: str, interface: str):
        proxy = await self._get_proxy_object(path)
        return proxy.get_interface(interface)

    async def _get_managed_objects(self) -> dict[str, dict[str, dict[str, Any]]]:
        object_manager = await self._get_interface(ROOT_PATH, OBJECT_MANAGER)
        objects = await object_manager.call_get_managed_objects()
        return self._unwrap(objects)

    def refresh_objects_only(self):
        self._managed_objects = self._run(self._get_managed_objects())
        self._device_path = self._resolve_device_path()
        return self._managed_objects

    def refresh(self) -> dict[str, dict[str, dict[str, Any]]]:
        self.refresh_objects_only()
        self.update_device_info(refresh=False)
        self.update_connection_state(refresh=False)
        self.update_known_networks(refresh=False)
        return self._managed_objects

    def _resolve_device_path(self) -> str:
        matches = []
        for path, interfaces in self._managed_objects.items():
            device = interfaces.get(DEVICE_INTERFACE)
            if not device:
                continue
            if device.get("Name") == self.device:
                matches.append(path)

        if matches:
            return matches[0]

        station_devices = [
            path
            for path, interfaces in self._managed_objects.items()
            if DEVICE_INTERFACE in interfaces and STATION_INTERFACE in interfaces
        ]
        if len(station_devices) == 1:
            self.device = self._managed_objects[station_devices[0]][DEVICE_INTERFACE]["Name"]
            return station_devices[0]

        raise IOError(f"Wi-Fi device '{self.device}' not found in iwd D-Bus objects.")

    def _interfaces_for(self, path: str | None) -> dict[str, dict[str, Any]]:
        if not path:
            return {}
        return self._managed_objects.get(path, {})

    def _network_props(self, path: str | None) -> dict[str, Any] | None:
        if not path:
            return None
        return self._interfaces_for(path).get(NETWORK_INTERFACE)

    def _known_network_props(self, path: str | None) -> dict[str, Any] | None:
        if not path:
            return None
        return self._interfaces_for(path).get(KNOWN_NETWORK_INTERFACE)

    def _station_props(self) -> dict[str, Any]:
        return self._interfaces_for(self._device_path).get(STATION_INTERFACE, {})

    def _device_props(self) -> dict[str, Any]:
        return self._interfaces_for(self._device_path).get(DEVICE_INTERFACE, {})

    @staticmethod
    def _quality_from_signal(signal_strength: int) -> int:
        if signal_strength >= -5500:
            return 5
        if signal_strength >= -6700:
            return 4
        if signal_strength >= -7500:
            return 3
        if signal_strength >= -8500:
            return 2
        return 1

    def _set_error(self, message: str | None, user_friendly: bool = False) -> None:
        self.last_error = message
        self.last_error_user_friendly = bool(message) and user_friendly

    @classmethod
    def _unsupported_credentials_message(cls, security: str | None) -> str | None:
        if security == "8021x":
            return "Enterprise / 802.1x networks are not supported by this rofi UI yet."
        if security == "wep":
            return "WEP networks are not supported."
        if security == "hotspot":
            return "This network requires credentials that iwdrofimenu cannot prompt for yet."
        return None

    @staticmethod
    def _format_duration_ms(milliseconds: int) -> str:
        if milliseconds < 1000:
            return f"{milliseconds} ms"
        return IWD._format_duration_seconds(milliseconds / 1000)

    @staticmethod
    def _format_duration_seconds(seconds: float | int) -> str:
        total_seconds = int(seconds)
        hours, remainder = divmod(total_seconds, 3600)
        minutes, secs = divmod(remainder, 60)

        parts = []
        if hours:
            parts.append(f"{hours}h")
        if minutes:
            parts.append(f"{minutes}m")
        if secs or not parts:
            parts.append(f"{secs}s")
        return " ".join(parts)

    @classmethod
    def _format_value(cls, key: str, value: Any) -> str:
        if isinstance(value, bool):
            return "yes" if value else "no"
        if isinstance(value, list):
            return ", ".join(map(str, value))
        if value is None:
            return ""

        if key == "Security":
            return cls.SECURITY_LABELS.get(str(value), str(value))
        if key == "State":
            return str(value).replace("-", " ").title()
        if key in {"RSSI", "AverageRSSI"}:
            return f"{value} dBm"
        if key == "Frequency":
            return f"{value} MHz"
        if key == "ConnectedTime":
            return cls._format_duration_seconds(value)
        if key == "InactiveTime":
            return cls._format_duration_ms(value)
        if key in {"RxBitrate", "TxBitrate"}:
            return f"{int(value) * 100} Kbit/s"
        if key == "ExpectedThroughput":
            return f"{value} Kbit/s"
        return str(value)

    def get_connection_details(self, refresh: bool = True) -> list[tuple[str, str]]:
        state = self.update_connection_state(refresh=refresh) if refresh else self.state
        if not state:
            return []

        details: list[tuple[str, str]] = []
        seen: set[str] = set()
        for key, label in self.DETAIL_LABELS:
            value = state.get(key)
            if value in (None, ""):
                continue
            details.append((label, str(value)))
            seen.add(key)

        for key, value in state.items():
            if key in seen or key in self.HIDDEN_STATE_KEYS or value in (None, ""):
                continue
            details.append((key, str(value)))

        return details

    def get_state(self, property_name: str):
        if self.state is None:
            return None
        return self.state.get(property_name)

    def connected(self):
        state = self.get_state("State")
        if state is None:
            return None
        return str(state).lower() == "connected"

    def ssid(self):
        return self.get_state("Connected network")

    def connected_network_path(self) -> str | None:
        return self.get_state("Connected network path")

    def connected_known_network_path(self) -> str | None:
        return self.get_state("Known network path")

    def update_device_info(self, refresh: bool = True):
        if refresh:
            self.refresh_objects_only()

        props = self._device_props()
        self.device_info = {
            "Name": props.get("Name"),
            "Address": props.get("Address"),
            "Powered": props.get("Powered"),
            "Mode": props.get("Mode"),
            "Adapter": props.get("Adapter"),
        }
        return self.device_info

    def adapter(self):
        return self.device_info.get("Adapter")

    async def _get_diagnostics(self) -> dict[str, Any]:
        if not self._device_path:
            return {}
        if STATION_DIAGNOSTIC_INTERFACE not in self._interfaces_for(self._device_path):
            return {}
        diagnostic = await self._get_interface(self._device_path, STATION_DIAGNOSTIC_INTERFACE)
        try:
            return self._unwrap(await diagnostic.call_get_diagnostics())
        except DBusError:
            return {}

    def update_connection_state(self, refresh: bool = True):
        if refresh:
            self.refresh_objects_only()

        station = self._station_props()
        device = self._device_props()
        network_path = station.get("ConnectedNetwork")
        network = self._network_props(network_path)
        known_path = network.get("KnownNetwork") if network else None

        state: dict[str, Any] = {
            "Device": self._format_value("Device", device.get("Name")),
            "State": self._format_value("State", station.get("State")),
            "Scanning": self._format_value("Scanning", station.get("Scanning")),
        }
        if network_path:
            state["Connected network path"] = network_path
        if network:
            state["Connected network"] = self._format_value("Connected network", network.get("Name"))
            state["Security"] = self._format_value("Security", network.get("Type"))
            if known_path:
                state["Known network path"] = known_path

        diagnostics = self._run(self._get_diagnostics())
        for key, value in diagnostics.items():
            state[key] = self._format_value(key, value)

        self.state = state
        return self.state

    async def _scan(self) -> None:
        station = await self._get_interface(self._device_path, STATION_INTERFACE)
        await station.call_scan()

    def scan(self):
        try:
            self._run(self._scan())
            self._set_error(None)
            return True
        except DBusError as error:
            if error.type.endswith(".Busy"):
                self._set_error(None)
                return True
            self._set_error(str(error))
            return False

    async def _get_ordered_network_paths(self) -> list[tuple[str, int]]:
        station = await self._get_interface(self._device_path, STATION_INTERFACE)
        ordered = await station.call_get_ordered_networks()
        return [(path, signal_strength) for path, signal_strength in ordered]

    def get_networks(self):
        self.refresh_objects_only()
        try:
            ordered = self._run(self._get_ordered_network_paths())
        except DBusError as error:
            self._set_error(str(error))
            return None

        self._set_error(None)
        networks: list[dict[str, Any]] = []
        for path, signal_strength in ordered:
            props = self._network_props(path)
            if not props:
                continue
            record = NetworkRecord(
                path=path,
                ssid=props.get("Name", ""),
                security=props.get("Type", ""),
                signal_strength=signal_strength,
                quality=self._quality_from_signal(signal_strength),
                connected=bool(props.get("Connected", False)),
                known=bool(props.get("KnownNetwork")),
                known_network=props.get("KnownNetwork"),
            )
            networks.append(record.to_dict())
        return networks

    def get_network(self, path: str, refresh: bool = True) -> dict[str, Any] | None:
        if refresh:
            self.refresh_objects_only()
        props = self._network_props(path)
        if not props:
            return None
        return {
            "path": path,
            "ssid": props.get("Name", ""),
            "security": props.get("Type", ""),
            "connected": bool(props.get("Connected", False)),
            "known": bool(props.get("KnownNetwork")),
            "known_network": props.get("KnownNetwork"),
        }

    def update_known_networks(self, refresh: bool = True):
        if refresh:
            self.refresh_objects_only()

        self.known_networks = {}
        for path, interfaces in self._managed_objects.items():
            props = interfaces.get(KNOWN_NETWORK_INTERFACE)
            if not props:
                continue
            self.known_networks[path] = {
                "path": path,
                "name": props.get("Name"),
                "security": props.get("Type"),
                "hidden": props.get("Hidden", False),
                "last_connected": props.get("LastConnectedTime"),
                "autoconnect": props.get("AutoConnect", True),
            }
        return self.known_networks

    async def _disconnect(self) -> None:
        station = await self._get_interface(self._device_path, STATION_INTERFACE)
        await station.call_disconnect()

    def disconnect(self):
        try:
            self._run(self._disconnect())
            self._set_error(None)
            self.update_connection_state()
            return True
        except DBusError as error:
            if error.type.endswith(".NotConnected"):
                self._set_error(None)
                self.update_connection_state()
                return True
            self._set_error(str(error))
            return None

    async def _register_agent(self, agent_path: str, agent: _PassphraseAgent) -> None:
        self._bus.export(agent_path, agent)
        manager = await self._get_interface(AGENT_MANAGER_PATH, AGENT_MANAGER)
        await manager.call_register_agent(agent_path)

    async def _unregister_agent(self, agent_path: str) -> None:
        try:
            manager = await self._get_interface(AGENT_MANAGER_PATH, AGENT_MANAGER)
            await manager.call_unregister_agent(agent_path)
        except DBusError as error:
            if not error.type.endswith(".NotFound"):
                raise
        finally:
            self._bus.unexport(agent_path)

    async def _connect_network(self, network_path: str, passphrase: str | None) -> None:
        network = await self._get_interface(network_path, NETWORK_INTERFACE)
        agent_path = None
        if passphrase is not None:
            agent_path = f"/iwdrofimenu/agent/{next(self._agent_counter)}"
            agent = _PassphraseAgent(passphrase)
            await self._register_agent(agent_path, agent)
        try:
            await network.call_connect()
        finally:
            if agent_path is not None:
                await self._unregister_agent(agent_path)

    def connect(self, network_path: str, passphrase: str | None = None, timeout: int = 30):
        del timeout
        network = self.get_network(network_path)
        if not network:
            self._set_error("Network no longer exists", user_friendly=True)
            return IWD.ConnectionResult.NOT_SUCCESSFUL

        security = network["security"]
        known = network["known"]

        if passphrase is None and security == "psk" and not known:
            self._set_error(None)
            return IWD.ConnectionResult.NEED_PASSPHRASE
        if security in {"wep", "8021x", "hotspot"} and passphrase is None and not known:
            self._set_error(self._unsupported_credentials_message(security), user_friendly=True)
            return IWD.ConnectionResult.NOT_SUCCESSFUL

        try:
            self._run(self._connect_network(network_path, passphrase))
            self._set_error(None)
            self.update_connection_state()
            return IWD.ConnectionResult.SUCCESS
        except DBusError as error:
            unsupported = self._unsupported_credentials_message(security)
            if error.type.endswith(".NoAgent") and security == "psk":
                self._set_error(None)
                return IWD.ConnectionResult.NEED_PASSPHRASE
            if error.type.endswith(".Timeout"):
                self._set_error(str(error))
                return IWD.ConnectionResult.TIMEOUT
            if unsupported and error.type.endswith((".NoAgent", ".NotSupported", ".NotConfigured")):
                self._set_error(unsupported, user_friendly=True)
                return IWD.ConnectionResult.NOT_SUCCESSFUL
            self._set_error(str(error))
            return IWD.ConnectionResult.NOT_SUCCESSFUL

    async def _forget(self, known_network_path: str) -> None:
        known = await self._get_interface(known_network_path, KNOWN_NETWORK_INTERFACE)
        await known.call_forget()

    def forget(self, path: str | None = None):
        self.refresh_objects_only()
        target = path
        if target and self._known_network_props(target):
            pass
        elif target:
            network = self._network_props(target)
            if network and network.get("KnownNetwork"):
                target = network["KnownNetwork"]
        if not target:
            self.update_connection_state(refresh=False)
            target = self.connected_known_network_path()
        if not target:
            self._set_error("No known network to forget", user_friendly=True)
            return None

        try:
            self._run(self._forget(target))
            self._set_error(None)
            self.refresh()
            return True
        except DBusError as error:
            self._set_error(str(error))
            return None
