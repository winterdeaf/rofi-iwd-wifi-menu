"""Main file of the script."""

import logging
import os
from pathlib import Path
import subprocess
import sys
import time
from string import Template

from settings import TEMPLATES

from .actions import decode_action, encode_action
from .iwd_dbus import IWD
from .iwd_rofi_dialogs import (
    RofiConfirmDialog,
    RofiNetworkList,
    RofiPasswordInput,
    RofiShowActiveConnection,
)
from .text import sanitize_rofi

WORKER_PASSPHRASE_ENV = "IWDROFIMENU_WORKER_PASSPHRASE"


def _background_worker_script() -> str:
    return str(Path(__file__).resolve().parent.parent / "iwdrofimenu.py")


def _connection_progress_message(ssid: str | None) -> str:
    return Template(TEMPLATES["msg_connection_in_progress"]).substitute(
        ssid=sanitize_rofi(ssid or "network")
    )


def _notify(summary: str, body: str | None = None) -> None:
    command = ["notify-send", summary]
    if body:
        command.append(body)

    try:
        subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )
    except OSError:
        pass


def run_connect_worker(device: str, network_path: str, ssid: str | None, passphrase: str | None = None) -> int:
    iwd = IWD(device)
    ssid_text = sanitize_rofi(ssid or "network")

    try:
        # Leave the worker-side timeout disabled so the temporary passphrase
        # agent stays available for the full connect attempt.
        result = iwd.connect(network_path, passphrase, timeout=0)

        if result == IWD.ConnectionResult.SUCCESS:
            return 0
        if result == IWD.ConnectionResult.TIMEOUT:
            _notify(
                f"Wi-Fi timed out: {ssid_text}",
                iwd.last_error or Template(TEMPLATES["msg_connection_timeout"]).substitute(ssid=ssid_text),
            )
            return 1

        if result == IWD.ConnectionResult.NEED_PASSPHRASE:
            body = "This network needs credentials and cannot be completed in the background."
        elif iwd.last_error:
            body = iwd.last_error
        else:
            body = Template(TEMPLATES["msg_connection_not_successful"]).substitute(ssid=ssid_text)

        _notify(f"Wi-Fi connection failed: {ssid_text}", body)
        return 1
    finally:
        iwd.close()


class Main:
    """Main class bringing everything together."""

    def __init__(self, device="wlan0", args=None):
        self.args = args
        self.arg = self.args.arg
        self.combi_mode = self.args.combi_mode
        self.message = ""

        self.retv = os.environ.get("ROFI_RETV")
        self.info = os.environ.get("ROFI_INFO")
        self.data = os.environ.get("ROFI_DATA")

        self.data_action = decode_action(self.data)
        self.info_action = decode_action(self.info)

        self.iwd = IWD(device)
        if self._should_auto_scan():
            self.iwd.scan()

        commands = {
            "scan": self.scan,
            "refresh": self.refresh,
            "show_active_connection": self.show_active_connection,
            "disconnect": self.disconnect,
            "connect": self.connect,
            "connect_with_passphrase": self.connect_with_passphrase,
            "forget_current": self.forget,
            "abort": self.abort,
        }

        logging.info(
            "ARG=%s RETV=%s DATA=%s INFO=%s DATA_ACTION=%s INFO_ACTION=%s",
            self.arg,
            self.retv,
            self.data,
            self.info,
            self.data_action,
            self.info_action,
        )

        self.apply_actions(commands)

        if not self.message:
            self.message = self._status_message()

        RofiNetworkList(
            self.iwd,
            message=self.message,
            data=self.data,
            combi_mode=self.combi_mode,
        )

    def exit_if_combi_mode(self):
        if self.combi_mode:
            sys.exit(0)

    def _should_auto_scan(self):
        return self.data_action is None and self.info_action is None

    def _status_message(self):
        state = str(self.iwd.get_state("State") or "").lower()
        if state == "connecting":
            return _connection_progress_message(self.iwd.ssid())
        return ""

    def _spawn_connect_worker(self, network_path, ssid, passphrase=None):
        env = os.environ.copy()
        env.pop("ROFI_INFO", None)
        env.pop("ROFI_DATA", None)
        env.pop("ROFI_RETV", None)
        if passphrase is None:
            env.pop(WORKER_PASSPHRASE_ENV, None)
        else:
            env[WORKER_PASSPHRASE_ENV] = passphrase

        command = [
            sys.executable,
            _background_worker_script(),
            "--connect-worker",
            "--worker-network-path",
            network_path,
            "--worker-ssid",
            ssid or "",
        ]
        if getattr(self.args, "verbose", False):
            command.append("--verbose")

        subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
            env=env,
        )

    def _wait_for_connection_state(self, network_path, timeout=2.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.iwd.update_connection_state()
            state = str(self.iwd.get_state("State") or "").lower()
            if state in {"connecting", "connected"} and self.iwd.connected_network_path() == network_path:
                return True
            time.sleep(0.1)
        return False

    def _start_background_connection(self, network_path, ssid, passphrase=None, settle_timeout=0.0):
        self.data = ""
        try:
            self._spawn_connect_worker(network_path, ssid, passphrase)
        except OSError as error:
            self.message = f"Could not start background connection: {error}"
            return False

        if settle_timeout > 0:
            self._wait_for_connection_state(network_path, timeout=settle_timeout)

        self.message = self._status_message() or _connection_progress_message(ssid)
        self.exit_if_combi_mode()
        return True

    def apply_actions(self, commands):
        done = False
        if self.data_action:
            action = self.data_action.get("action")
            handler = commands.get(action)
            if handler is not None:
                handler(self.data_action)
                done = True

        if done or not self.info_action:
            return

        action = self.info_action.get("action")
        handler = commands.get(action)
        if handler is not None:
            handler(self.info_action)

    def _error_message(self, fallback: str) -> str:
        return self.iwd.last_error or fallback

    def refresh(self, action):
        del action
        return

    def abort(self, action):
        del action
        self.data = ""

    def scan(self, action):
        del action
        if self.iwd.scan():
            self.message = TEMPLATES["msg_scanning"]
        else:
            self.message = self._error_message("Scan failed")

    def show_active_connection(self, action):
        del action
        RofiShowActiveConnection(self.iwd, data="")
        sys.exit(0)

    def disconnect(self, action):
        del action
        self.iwd.disconnect()
        self.iwd.update_connection_state()
        self.exit_if_combi_mode()

    def forget(self, action):
        if action.get("confirm"):
            if not self.iwd.forget():
                self.message = self._error_message("Could not forget network")
            return

        ssid = self.iwd.ssid()
        if not ssid:
            self.message = "No connected network"
            return

        msg = Template(TEMPLATES["msg_really_discard"]).substitute(ssid=sanitize_rofi(ssid))
        RofiConfirmDialog(
            TEMPLATES["prompt_confirm"],
            message=msg,
            data="",
            confirm_caption=TEMPLATES["confirm_discard"],
            confirm_info=encode_action("forget_current", confirm=True),
            abort_caption=TEMPLATES["back"],
            abort_info=encode_action("show_active_connection"),
        )
        sys.exit(0)

    def connect(self, action):
        network_path = action.get("network_path")
        network = self.iwd.get_network(network_path)
        if not network:
            self.message = "Selected network is no longer available"
            return

        if network["security"] == "psk" and not network["known"]:
            RofiPasswordInput(network["ssid"], network_path)
            sys.exit(0)

        self._start_background_connection(network_path, network["ssid"])

    def connect_with_passphrase(self, action):
        network_path = action.get("network_path")
        ssid = action.get("ssid") or "network"

        if self.info_action and self.info_action.get("action") == "abort":
            self.data = ""
            return

        # Give iwd a short grace period to publish the in-progress state after
        # we hand over the passphrase, so the menu is more likely to reopen in
        # a connecting state instead of flipping back immediately.
        self._start_background_connection(network_path, ssid, self.arg, settle_timeout=2.0)
