import io
import unittest
from contextlib import redirect_stdout

from iwdrofimenu.rofidialog import RofiDialog
from iwdrofimenu.text import escape_markup, sanitize_rofi


class TextSanitizationTests(unittest.TestCase):
    def test_sanitize_rofi_replaces_control_characters(self):
        raw = "evil\nssid\x1fmeta\0end\r"
        self.assertEqual(sanitize_rofi(raw), "evil ssid meta end ")

    def test_escape_markup_escapes_tags_after_sanitizing(self):
        raw = "<b>pwnd</b>\nssid"
        self.assertEqual(escape_markup(raw), "&lt;b&gt;pwnd&lt;/b&gt; ssid")

    def test_rofidialog_output_sanitizes_row_and_option_fields(self):
        buf = io.StringIO()
        dialog = RofiDialog()
        with redirect_stdout(buf):
            dialog.add_row("bad\nssid", info="cmd\x1fboom", meta="x\0y")

        output = buf.getvalue()
        self.assertIn("bad ssid", output)
        self.assertIn("info\x1fcmd boom", output)
        self.assertIn("meta\x1fx y", output)
        self.assertNotIn("bad\nssid", output)


if __name__ == "__main__":
    unittest.main()
