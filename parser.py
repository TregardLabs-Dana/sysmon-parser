#!/usr/bin/env python3
import argparse
import csv
import io
import json
import sys
import xml.etree.ElementTree as ET

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

FIELDS = [
    "UtcTime",
    "Image",
    "CommandLine",
    "User",
    "IntegrityLevel",
    "ParentImage",
    "ParentCommandLine",
    "Hashes",
]

CSV_FIELDNAMES = ["EventID", "Computer"] + FIELDS


def parse_event(event_elem):
    result = {"EventID": event_elem.findtext("e:System/e:EventID", namespaces=NS)}
    result["Computer"] = event_elem.findtext("e:System/e:Computer", namespaces=NS)

    data_by_name = {
        data.get("Name"): (data.text or "")
        for data in event_elem.findall("e:EventData/e:Data", NS)
    }
    for field in FIELDS:
        result[field] = data_by_name.get(field)

    return result


def parse_file(path):
    tree = ET.parse(path)
    root = tree.getroot()

    if root.tag.endswith("Events"):
        events = root.findall("e:Event", NS)
    else:
        events = [root]

    return [parse_event(event) for event in events]


def filter_events(events, image=None, user=None, integrity_level=None, command_line=None):
    def matches(event):
        if image and image.lower() not in (event.get("Image") or "").lower():
            return False
        if user and user.lower() != (event.get("User") or "").lower():
            return False
        if integrity_level and integrity_level != event.get("IntegrityLevel"):
            return False
        if command_line and command_line.lower() not in (event.get("CommandLine") or "").lower():
            return False
        return True

    return [event for event in events if matches(event)]


def render_json(events):
    result = events[0] if len(events) == 1 else events
    return json.dumps(result, indent=2)


def render_jsonl(events):
    return "\n".join(json.dumps(event) for event in events)


def render_csv(events):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDNAMES, lineterminator="\n")
    writer.writeheader()
    writer.writerows(events)
    return buffer.getvalue().rstrip("\n")


RENDERERS = {"json": render_json, "jsonl": render_jsonl, "csv": render_csv}


def main():
    argparser = argparse.ArgumentParser(description="Parse a Sysmon Event ID 1 XML file into JSON.")
    argparser.add_argument("xml_path", help="Path to the Sysmon XML file")
    argparser.add_argument("-o", "--output", help="Write output to this file instead of stdout")
    argparser.add_argument(
        "--format",
        choices=["json", "jsonl", "csv"],
        default="json",
        help="Output format: json (default, JSON array/object), jsonl (one JSON object per line), or csv",
    )
    argparser.add_argument("--image", help="Filter: Image contains this substring (case-insensitive)")
    argparser.add_argument("--user", help="Filter: User exact match (case-insensitive)")
    argparser.add_argument(
        "--integrity-level",
        choices=["High", "Medium", "Low", "System"],
        help="Filter: IntegrityLevel exact match",
    )
    argparser.add_argument("--command-line", help="Filter: CommandLine contains this substring (case-insensitive)")
    args = argparser.parse_args()

    events = parse_file(args.xml_path)
    events = filter_events(
        events,
        image=args.image,
        user=args.user,
        integrity_level=args.integrity_level,
        command_line=args.command_line,
    )
    output_str = RENDERERS[args.format](events)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output_str + "\n")
    else:
        print(output_str)


if __name__ == "__main__":
    main()
