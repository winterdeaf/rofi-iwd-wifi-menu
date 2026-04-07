"""Main file of the script."""

import logging
import os
import sys
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


class Main:
    """Main class bringing everything together."""

    def __init__(self, device="wlan0", args=None):
        self.args = args
        self.arg = self.args.arg
        self.combi_mode = self.args.combi_mode
        self.message = ""
        self.iwd = IWD(device)
        self.iwd.scan()

        self.retv = os.environ.get("ROFI_RETV")
        self.info = os.environ.get("ROFI_INFO")
        self.data = os.environ.get("ROFI_DATA")

        self.data_action = decode_action(self.data)
        self.info_action = decode_action(self.info)

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

        RofiNetworkList(
            self.iwd,
            message=self.message,
            data=self.data,
            combi_mode=self.combi_mode,
        )

    def exit_if_combi_mode(self):
        if self.combi_mode:
            sys.exit(0)

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

        msg = Template(TEMPLATES["msg_really_discard"]).substitute(ssid=ssid)
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

        result = self.iwd.connect(network_path)
        self.iwd.update_connection_state()
        self._handle_connection_result(result, network["ssid"], network_path)

    def connect_with_passphrase(self, action):
        network_path = action.get("network_path")
        ssid = action.get("ssid") or "network"

        if self.info_action and self.info_action.get("action") == "abort":
            self.data = ""
            return

        result = self.iwd.connect(network_path, self.arg)
        self.iwd.update_connection_state()

        if result == IWD.ConnectionResult.SUCCESS:
            self.data = ""
        elif result in {IWD.ConnectionResult.NOT_SUCCESSFUL, IWD.ConnectionResult.NEED_PASSPHRASE}:
            msg = Template(TEMPLATES["msg_connection_not_successful_after_pass"]).substitute(ssid=ssid)
            RofiPasswordInput(ssid, network_path, message=msg)
            sys.exit(0)

        self._handle_connection_result(result, ssid, network_path)

    def _handle_connection_result(self, result, ssid, network_path):
        if result == IWD.ConnectionResult.NEED_PASSPHRASE:
            RofiPasswordInput(ssid, network_path)
            sys.exit(0)

        if result == IWD.ConnectionResult.SUCCESS:
            template_str = TEMPLATES["msg_connection_successful"]
            self.exit_if_combi_mode()
        elif result == IWD.ConnectionResult.NOT_SUCCESSFUL:
            if self.iwd.last_error_user_friendly and self.iwd.last_error:
                self.message = self.iwd.last_error
                return
            template_str = TEMPLATES["msg_connection_not_successful"]
        elif result == IWD.ConnectionResult.TIMEOUT:
            template_str = TEMPLATES["msg_connection_timeout"]
        else:
            template_str = TEMPLATES["msg_connection_not_successful"]
        self.message = Template(template_str).substitute(ssid=ssid)
