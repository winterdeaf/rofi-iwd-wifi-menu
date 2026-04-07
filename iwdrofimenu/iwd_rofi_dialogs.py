"""Classes defining the rofi dialogs for this script."""

from string import Template

from settings import ICONS, ROFI_THEME_FILE, SHOW_SEPARATOR, SIGNAL_QUALITY_TEXT, TEMPLATES

from .actions import encode_action
from .rofidialog import RofiDialog, RofiSimpleDialog


class RofiBasicDialog(RofiDialog):
    """Base class for dialogs used by the script."""

    def __init__(self, prompt, message, data=None, theme_snippet=""):
        self.settings = {
            "theme": ((f"@import \"{ROFI_THEME_FILE}\"" if ROFI_THEME_FILE else "") + theme_snippet),
            "markup-rows": "true",
        }
        super().__init__(prompt, message, data, self.settings)

    def add_separator(self, custom_text=None):
        text = custom_text if custom_text is not None else TEMPLATES["separator"]
        if SHOW_SEPARATOR:
            self.add_row(text, nonselectable="true")


class RofiPasswordInput(RofiSimpleDialog):
    """Dialog for password input."""

    def __init__(self, ssid, network_path, prompt=None, message=None):
        entries = [
            {
                "caption": TEMPLATES["cancel"],
                "info": encode_action("abort"),
                "icon": ICONS["back"],
            }
        ]
        if prompt is None:
            prompt = TEMPLATES["prompt_pass"]
        if message is None:
            message = f"Please enter the passphrase for {ssid} and press enter."
        super().__init__(
            prompt,
            message=message,
            entries=entries,
            data=encode_action("connect_with_passphrase", network_path=network_path, ssid=ssid),
            no_custom="false",
        )


class RofiConfirmDialog(RofiSimpleDialog):
    """Confirm dialog."""

    def __init__(self, prompt, message="", data=None,
                 confirm_caption="OK", confirm_info="",
                 abort_caption="Back", abort_info=""):
        entries = [
            {
                "caption": confirm_caption,
                "info": confirm_info,
                "icon": ICONS["confirm"],
            },
            {
                "caption": abort_caption,
                "info": abort_info,
                "icon": ICONS["back"],
            },
        ]
        super().__init__(prompt, message=message, entries=entries, data=data, no_custom="true")


class RofiIWDDialog(RofiBasicDialog):
    """Base class that carries an IWD object."""

    def __init__(self, prompt, iwd, message=None, data=None, theme_snippet=""):
        super().__init__(prompt, message=message, data=data, theme_snippet=theme_snippet)
        self.iwd = iwd


class RofiShowActiveConnection(RofiIWDDialog):
    """Dialog showing the active connection."""

    row_template = Template(TEMPLATES["connection-details-entry"])

    def __init__(self, iwd, message="", data=None):
        super().__init__(TEMPLATES["prompt_ssid"], iwd, message=message, theme_snippet="", data=data)

        self.iwd.update_connection_state()

        self.add_row(TEMPLATES["back"], icon=ICONS["back"])

        if self.iwd.connected_network_path():
            self.add_row(
                TEMPLATES["disconnect"],
                info=encode_action("disconnect"),
                icon=ICONS["disconnect"],
            )
        self.add_separator()

        details = self.iwd.get_connection_details(refresh=False)
        if details:
            for name, value in details:
                self.add_row(
                    self.row_template.substitute(property=name, value=value),
                    nonselectable="true",
                )
        else:
            self.add_row("No active connection", nonselectable="true")

        known_path = self.iwd.connected_known_network_path()
        if known_path:
            self.add_separator()
            self.add_row(
                TEMPLATES["discard"],
                info=encode_action("forget_current"),
                icon=ICONS["trash"],
            )


class RofiNetworkList(RofiIWDDialog):
    """Main dialog showing networks."""

    row_template = Template(TEMPLATES["network_list_entry"])

    def __init__(self, iwd, message=None, data=None, combi_mode=False):
        super().__init__(TEMPLATES["prompt_ssid"], iwd, message=message, data=data)
        self.combi_mode = combi_mode

        active_entry_template = TEMPLATES["network_list_entry_active"]
        self.row_template_active = self.row_template if not active_entry_template else Template(active_entry_template)

        known_entry_template = TEMPLATES["network_list_entry_known"]
        self.row_template_known = self.row_template if not known_entry_template else Template(known_entry_template)

        self.iwd.update_known_networks()

        if not self.combi_mode:
            self.add_row(
                TEMPLATES["scan"],
                info=encode_action("scan"),
                icon=ICONS["scan"],
                meta=TEMPLATES["meta_scan"],
            )
            self.add_row(
                TEMPLATES["refresh"],
                info=encode_action("refresh"),
                icon=ICONS["refresh"],
                meta=TEMPLATES["meta_refresh"],
            )
            self.add_separator()

        networks = self.iwd.get_networks() or []
        if self.combi_mode:
            networks = [nw for nw in networks if nw["known"] or nw["security"] == "open"]

        self.networks = networks

        offset = 3 if (SHOW_SEPARATOR and TEMPLATES["separator"] and not self.combi_mode) else 2
        if self.combi_mode:
            offset = 0
        self.mark_known_or_active_networks(offset=offset)
        self.add_networks_to_dialog()

    def mark_known_or_active_networks(self, offset):
        active = None
        known = []
        for idx, nw in enumerate(self.networks):
            if nw["connected"]:
                active = idx + offset
            elif nw["known"] and not self.combi_mode:
                known.append(idx + offset)
        if active is not None:
            self.set_option("active", f"{active}")
        self.set_option("urgent", ",".join(map(str, known)))

    def add_networks_to_dialog(self):
        for nw in self.networks:
            self.add_network_to_dialog(nw)

    def choose_icon(self, nw):
        key = "wifi-signal" if nw["security"] == "open" else "wifi-encrypted-signal"
        return ICONS[f"{key}-{nw['quality']}"]

    def add_network_to_dialog(self, nw):
        cmd = encode_action("connect", network_path=nw["path"], ssid=nw["ssid"])
        meta = TEMPLATES["meta_connect"]
        nw = dict(nw)
        nw["quality_str"] = SIGNAL_QUALITY_TEXT[nw["quality"]]

        if nw["connected"]:
            text = self.row_template_active.substitute(nw)
            if self.combi_mode:
                cmd = encode_action("disconnect")
                meta = TEMPLATES["meta_disconnect"]
            else:
                cmd = encode_action("show_active_connection")
                meta = TEMPLATES["meta_showactive"]
        elif nw["known"]:
            text = self.row_template_known.substitute(nw)
        else:
            text = self.row_template.substitute(nw)

        self.add_row(text, info=cmd, icon=self.choose_icon(nw), meta=meta)
