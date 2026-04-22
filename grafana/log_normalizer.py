#!/usr/bin/env python3
"""
log_normalizer.py — S7pot Log Normalizer
=========================================
Converts interaction.json (concatenated JSON objects, no array wrapper)
into a proper NDJSON file (one JSON object per line) that Promtail can tail.

Runs continuously, tailing the source file for new events.

Usage:
    python3 log_normalizer.py
    python3 log_normalizer.py --source logs/interaction.json --output logs/interaction.ndjson
"""

import argparse
import json
import os
import re
import sys
import time

# ── defaults ──────────────────────────────────────────────────────────────────
DEFAULT_SOURCE = os.path.join(os.path.dirname(__file__), "..", "logs", "interaction.json")
DEFAULT_OUTPUT = os.path.join(os.path.dirname(__file__), "..", "logs", "interaction.ndjson")
POLL_INTERVAL  = 1.0   # seconds between source-file checks

# ── JSON object splitter ───────────────────────────────────────────────────────
def split_json_objects(text: str):
    """
    Extract all top-level JSON objects from a string that may contain
    concatenated objects with or without separating whitespace / newlines.
    Returns (list_of_dicts, leftover_text).
    """
    objects = []
    depth   = 0
    start   = None
    i       = 0

    while i < len(text):
        ch = text[i]
        if ch == '{':
            if depth == 0:
                start = i
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0 and start is not None:
                fragment = text[start : i + 1]
                try:
                    obj = json.loads(fragment)
                    objects.append(obj)
                except json.JSONDecodeError:
                    pass  # malformed fragment — skip
                start = None
        i += 1

    # anything after the last complete object is the leftover (partial)
    if start is not None:
        leftover = text[start:]
    else:
        leftover = ""

    return objects, leftover


def normalize(source_path: str, output_path: str):
    """
    Append-only normalization: reads ALL objects from source, counts how many
    are already in output, and appends only the new ones.

    IMPORTANT: the output file is NEVER truncated. Promtail tracks its read
    position in the file; truncating the file breaks position tracking and
    causes Loki to miss new events.

    Returns (new_objects_written, current_source_size).
    """
    # Count lines already written to the output (= already sent to Loki)
    existing_lines = 0
    if os.path.exists(output_path):
        with open(output_path, "r", encoding="utf-8") as f:
            existing_lines = sum(1 for _ in f)

    with open(source_path, "r", encoding="utf-8") as f:
        raw = f.read()

    objects, _ = split_json_objects(raw)

    # Only write objects that haven't been written yet
    new_objects = objects[existing_lines:]

    if new_objects:
        with open(output_path, "a", encoding="utf-8") as out:
            for obj in new_objects:
                out.write(json.dumps(obj) + "\n")

    return len(new_objects), os.path.getsize(source_path)


def tail(source_path: str, output_path: str):
    """
    Continuously tail source_path, appending new objects to output_path.
    On start it does a full back-fill for any events not yet in output.
    """
    # ── back-fill on startup ──────────────────────────────────────────────────
    count, last_size = normalize(source_path, output_path)
    print(f"[normalizer] Back-filled {count} events → {output_path}")

    pending = ""   # partial JSON that hasn't closed yet

    with open(output_path, "a", encoding="utf-8") as out:
        while True:
            time.sleep(POLL_INTERVAL)

            current_size = os.path.getsize(source_path)
            if current_size <= last_size:
                continue

            # read only the new bytes
            with open(source_path, "r", encoding="utf-8") as f:
                f.seek(last_size)
                chunk = f.read()

            last_size = current_size
            pending  += chunk

            objects, pending = split_json_objects(pending)
            for obj in objects:
                line = json.dumps(obj)
                out.write(line + "\n")
                out.flush()
                print(f"[normalizer] +event {obj.get('intent', '?')} [{obj.get('protocol', '?')}]")


# ── CLI ────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="S7pot log normalizer")
    parser.add_argument("--source",  default=DEFAULT_SOURCE, help="Path to interaction.json")
    parser.add_argument("--output",  default=DEFAULT_OUTPUT, help="Path to output NDJSON file")
    parser.add_argument("--once",    action="store_true",    help="Run once (no tail loop)")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)

    if args.once:
        count, _ = normalize(args.source, args.output)
        print(f"[normalizer] Wrote {count} events → {args.output}")
    else:
        try:
            tail(args.source, args.output)
        except KeyboardInterrupt:
            print("\n[normalizer] Stopped.")
            sys.exit(0)


if __name__ == "__main__":
    main()
