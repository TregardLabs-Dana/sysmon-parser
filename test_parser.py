#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

import parser as sysmon_parser

SAMPLES_DIR = Path(__file__).parent / "samples"
PARSER_PATH = Path(__file__).parent / "parser.py"

MINIMAL_EVENT_XML = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <Computer>TEST-HOST</Computer>
  </System>
  <EventData>
    <Data Name="Image">C:\\Windows\\System32\\notepad.exe</Data>
  </EventData>
</Event>
"""


class TestParseEvent(unittest.TestCase):
    def test_missing_fields_are_none(self):
        event_elem = ET.fromstring(MINIMAL_EVENT_XML)
        result = sysmon_parser.parse_event(event_elem)

        self.assertEqual(result["EventID"], "1")
        self.assertEqual(result["Computer"], "TEST-HOST")
        self.assertEqual(result["Image"], "C:\\Windows\\System32\\notepad.exe")
        self.assertIsNone(result["CommandLine"])
        self.assertIsNone(result["User"])
        self.assertIsNone(result["Hashes"])


class TestParseFile(unittest.TestCase):
    def test_single_event_file(self):
        events = sysmon_parser.parse_file(SAMPLES_DIR / "event1.xml")

        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["EventID"], "1")
        self.assertEqual(event["Image"], "C:\\Windows\\System32\\whoami.exe")
        self.assertEqual(event["CommandLine"], "whoami.exe /all")
        self.assertEqual(event["User"], "CORP\\jsmith")
        self.assertEqual(event["IntegrityLevel"], "Medium")
        self.assertEqual(event["ParentImage"], "C:\\Windows\\System32\\cmd.exe")

    def test_multi_event_file(self):
        events = sysmon_parser.parse_file(SAMPLES_DIR / "multi_events.xml")

        self.assertEqual(len(events), 3)
        images = [event["Image"] for event in events]
        self.assertIn("C:\\Windows\\System32\\whoami.exe", images)
        self.assertIn("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", images)


class TestFilterEvents(unittest.TestCase):
    def setUp(self):
        self.events = sysmon_parser.parse_file(SAMPLES_DIR / "multi_events.xml")

    def test_no_filters_returns_all(self):
        result = sysmon_parser.filter_events(self.events)
        self.assertEqual(len(result), 3)

    def test_image_substring_is_case_insensitive(self):
        result = sysmon_parser.filter_events(self.events, image="POWERSHELL")
        self.assertEqual(len(result), 2)
        for event in result:
            self.assertIn("powershell", event["Image"].lower())

    def test_user_exact_match_is_case_insensitive(self):
        result = sysmon_parser.filter_events(self.events, user="corp\\jsmith")
        self.assertEqual(len(result), 2)
        for event in result:
            self.assertEqual(event["User"], "CORP\\jsmith")

    def test_user_is_exact_not_substring(self):
        result = sysmon_parser.filter_events(self.events, user="jsmith")
        self.assertEqual(len(result), 0)

    def test_integrity_level_exact_match(self):
        result = sysmon_parser.filter_events(self.events, integrity_level="Medium")
        self.assertEqual(len(result), 3)

    def test_command_line_substring(self):
        result = sysmon_parser.filter_events(self.events, command_line="-enc")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["User"], "CORP\\bwilson")

    def test_filters_combine_with_and(self):
        result = sysmon_parser.filter_events(
            self.events, integrity_level="Medium", image="powershell"
        )
        self.assertEqual(len(result), 2)

    def test_no_match_returns_empty_list(self):
        result = sysmon_parser.filter_events(self.events, user="nobody")
        self.assertEqual(result, [])


class TestCli(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(PARSER_PATH), *args],
            capture_output=True,
            text=True,
        )

    def test_single_event_outputs_json_object(self):
        proc = self.run_cli(str(SAMPLES_DIR / "event1.xml"))
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertIsInstance(data, dict)
        self.assertEqual(data["Image"], "C:\\Windows\\System32\\whoami.exe")

    def test_multi_event_outputs_json_array(self):
        proc = self.run_cli(str(SAMPLES_DIR / "multi_events.xml"))
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 3)

    def test_filter_with_no_match_outputs_empty_array(self):
        proc = self.run_cli(str(SAMPLES_DIR / "multi_events.xml"), "--user", "nobody")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout), [])

    def test_output_flag_writes_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_path = Path(tmp_dir) / "out.json"
            proc = self.run_cli(str(SAMPLES_DIR / "event1.xml"), "-o", str(out_path))
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(proc.stdout, "")
            data = json.loads(out_path.read_text())
            self.assertEqual(data["EventID"], "1")

    def test_invalid_integrity_level_choice_errors(self):
        proc = self.run_cli(
            str(SAMPLES_DIR / "event1.xml"), "--integrity-level", "Bogus"
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("invalid choice", proc.stderr)


if __name__ == "__main__":
    unittest.main()
