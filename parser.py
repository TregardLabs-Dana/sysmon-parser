#!/usr/bin/env python3
import argparse
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


def main():
    argparser = argparse.ArgumentParser(description="Parse a Sysmon Event ID 1 XML file into JSON.")
    argparser.add_argument("xml_path", help="Path to the Sysmon XML file")
    argparser.add_argument("-o", "--output", help="Write JSON to this file instead of stdout")
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
    result = events[0] if len(events) == 1 else events
    output_json = json.dumps(result, indent=2)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output_json + "\n")
    else:
        print(output_json)


if __name__ == "__main__":
    main()
