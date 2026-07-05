#!/usr/bin/env python3
import csv
import io
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


class TestRenderFormats(unittest.TestCase):
    def setUp(self):
        self.events = sysmon_parser.parse_file(SAMPLES_DIR / "multi_events.xml")

    def test_render_json_array_for_multiple_events(self):
        output = sysmon_parser.render_json(self.events)
        data = json.loads(output)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 3)

    def test_render_json_object_for_single_event(self):
        output = sysmon_parser.render_json(self.events[:1])
        data = json.loads(output)
        self.assertIsInstance(data, dict)

    def test_render_jsonl_one_object_per_line(self):
        output = sysmon_parser.render_jsonl(self.events)
        lines = output.splitlines()
        self.assertEqual(len(lines), 3)
        for line, event in zip(lines, self.events):
            self.assertEqual(json.loads(line), event)

    def test_render_csv_has_header_and_rows(self):
        output = sysmon_parser.render_csv(self.events)
        rows = list(csv.DictReader(io.StringIO(output)))

        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["Image"], "C:\\Windows\\System32\\whoami.exe")
        self.assertEqual(rows[0]["User"], "CORP\\jsmith")
        self.assertIn("-Enc", rows[2]["CommandLine"])

    def test_render_csv_empty_events_has_header_only(self):
        output = sysmon_parser.render_csv([])
        rows = list(csv.DictReader(io.StringIO(output)))
        self.assertEqual(rows, [])


class TestComputeStats(unittest.TestCase):
    def setUp(self):
        self.events = sysmon_parser.parse_file(SAMPLES_DIR / "multi_events.xml")

    def test_stats_over_all_events(self):
        stats = sysmon_parser.compute_stats(self.events)

        self.assertEqual(stats["total_events"], 3)
        self.assertEqual(
            stats["unique_processes"],
            [
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "C:\\Windows\\System32\\whoami.exe",
            ],
        )
        self.assertEqual(stats["unique_users"], ["CORP\\bwilson", "CORP\\jsmith"])
        self.assertEqual(stats["events_by_integrity_level"], {"Medium": 3})

    def test_stats_over_filtered_subset(self):
        filtered = sysmon_parser.filter_events(self.events, image="powershell")
        stats = sysmon_parser.compute_stats(filtered)

        self.assertEqual(stats["total_events"], 2)
        self.assertEqual(len(stats["unique_processes"]), 1)

    def test_stats_on_empty_events(self):
        stats = sysmon_parser.compute_stats([])

        self.assertEqual(stats["total_events"], 0)
        self.assertEqual(stats["unique_processes"], [])
        self.assertEqual(stats["unique_users"], [])
        self.assertEqual(stats["events_by_integrity_level"], {})

    def test_stats_counts_missing_integrity_level_as_unknown(self):
        event_elem = ET.fromstring(MINIMAL_EVENT_XML)
        stats = sysmon_parser.compute_stats([sysmon_parser.parse_event(event_elem)])

        self.assertEqual(stats["events_by_integrity_level"], {"Unknown": 1})


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

    def test_format_json_is_default(self):
        default_proc = self.run_cli(str(SAMPLES_DIR / "multi_events.xml"))
        explicit_proc = self.run_cli(str(SAMPLES_DIR / "multi_events.xml"), "--format", "json")
        self.assertEqual(default_proc.stdout, explicit_proc.stdout)

    def test_format_jsonl_outputs_one_line_per_event(self):
        proc = self.run_cli(str(SAMPLES_DIR / "multi_events.xml"), "--format", "jsonl")
        self.assertEqual(proc.returncode, 0)
        lines = proc.stdout.strip("\n").splitlines()
        self.assertEqual(len(lines), 3)
        for line in lines:
            self.assertIsInstance(json.loads(line), dict)

    def test_format_csv_outputs_header_and_rows(self):
        proc = self.run_cli(str(SAMPLES_DIR / "multi_events.xml"), "--format", "csv")
        self.assertEqual(proc.returncode, 0)
        rows = list(csv.DictReader(io.StringIO(proc.stdout)))
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["User"], "CORP\\jsmith")

    def test_format_with_filter_applies_before_rendering(self):
        proc = self.run_cli(
            str(SAMPLES_DIR / "multi_events.xml"), "--format", "jsonl", "--user", "CORP\\bwilson"
        )
        self.assertEqual(proc.returncode, 0)
        lines = proc.stdout.strip("\n").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["User"], "CORP\\bwilson")

    def test_invalid_format_choice_errors(self):
        proc = self.run_cli(str(SAMPLES_DIR / "event1.xml"), "--format", "xml")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("invalid choice", proc.stderr)

    def test_stats_outputs_summary_object(self):
        proc = self.run_cli(str(SAMPLES_DIR / "multi_events.xml"), "--stats")
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["total_events"], 3)
        self.assertEqual(len(data["unique_processes"]), 2)
        self.assertEqual(len(data["unique_users"]), 2)
        self.assertEqual(data["events_by_integrity_level"], {"Medium": 3})

    def test_stats_respects_filters(self):
        proc = self.run_cli(
            str(SAMPLES_DIR / "multi_events.xml"), "--stats", "--image", "powershell"
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["total_events"], 2)


if __name__ == "__main__":
    unittest.main()
