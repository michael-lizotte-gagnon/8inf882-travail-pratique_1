#!/usr/bin/env python3
"""Interactively query VCDB incidents using mappings-explorer's VERIS crosswalk.

Run ``python3 query_mitre_incidents.py`` from any directory to discover the
packaged VCDB databases and VERIS mappings in this repository. Press Enter to
accept the suggested input and mapping, then adjust the query filters.

The mapping is a related-to crosswalk, not incident-level proof that each
mapped ATT&CK technique was used. Output includes the matched VERIS values.
"""

import argparse
import csv
import io
import json
import re
import sys
import zipfile
from datetime import date
from pathlib import Path


TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
MISSING = object()
REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_INPUT = Path("VCDB/data/csv/vcdb.csv.zip")
DEFAULT_MAPPING = Path(
    "mappings-explorer/mappings/veris/attack-16.1/veris-1.4.0/enterprise/"
    "veris-1.4.0_attack-16.1-enterprise.json"
)


def repo_path(path):
    return path if path.is_absolute() else REPO_ROOT / path


def discover_inputs():
    sources = []
    for folder in (REPO_ROOT / "VCDB/data/csv", REPO_ROOT / "VCDB/data/joined"):
        if folder.is_dir():
            for path in sorted(folder.rglob("*")):
                if path.is_file() and (
                    path.name.lower().endswith((".csv", ".csv.zip", ".json", ".json.zip"))
                ):
                    sources.append({"label": str(path.relative_to(REPO_ROOT)), "paths": [path]})

    validated = REPO_ROOT / "VCDB/data/json/validated"
    overridden = REPO_ROOT / "VCDB/data/json/overridden"
    incident_dirs = [path for path in (validated, overridden) if path.is_dir()]
    if incident_dirs:
        sources.append({
            "label": "Per-incident JSON (validated + overridden)",
            "paths": incident_dirs,
        })
    return sources


def discover_mappings():
    folder = REPO_ROOT / "mappings-explorer/mappings/veris"
    if not folder.is_dir():
        return []
    return sorted(folder.rglob("*.json"))


def choose_option(title, options, default_index):
    if not options:
        raise ValueError(f"No {title.lower()} found")
    default_index = min(max(default_index, 0), len(options) - 1)
    print(f"\n{title}:")
    for index, option in enumerate(options, start=1):
        print(f"  {index}. {option}")
    while True:
        try:
            answer = input(f"Select [default {default_index + 1}]: ").strip()
        except EOFError:
            answer = ""
        if not answer:
            return default_index
        try:
            selected = int(answer) - 1
        except ValueError:
            selected = -1
        if 0 <= selected < len(options):
            return selected
        print(f"Enter a number from 1 to {len(options)}.")


def prompt_text(label, default=""):
    shown_default = f" [{default}]" if default != "" else ""
    try:
        value = input(f"{label}{shown_default}: ").strip()
    except EOFError:
        value = ""
    return value or default


def prompt_int(label, default):
    while True:
        value = prompt_text(label, str(default))
        try:
            return int(value)
        except ValueError:
            print("Enter a whole number.")


def prompt_optional_int(label, default):
    while True:
        value = prompt_text(label, "" if default is None else str(default))
        if not value:
            return None
        try:
            return int(value)
        except ValueError:
            print("Enter a whole number or leave blank.")


def prompt_list(label, defaults):
    default = ", ".join(defaults)
    value = prompt_text(label + " (comma-separated; '-' for none)", default)
    if value == "-":
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def prompt_filters(args, parser, prompt_output=True):
    args.min_techniques = prompt_int("Minimum mapped techniques", args.min_techniques)
    args.max_techniques = prompt_optional_int(
        "Maximum mapped techniques (blank for no maximum)", args.max_techniques
    )
    args.requested_techniques = prompt_list(
        "Required ATT&CK technique IDs", args.requested_techniques
    )
    args.technique_match = prompt_text(
        "Technique match (any/all)", args.technique_match
    ).lower()
    args.mapping_prefix = prompt_list(
        "VERIS mapping path prefixes counted", args.mapping_prefix or ["action."]
    )
    args.veris_paths = prompt_list("Required VERIS paths", args.veris_paths)
    args.veris_match = prompt_text("VERIS path match (any/all)", args.veris_match).lower()
    date_from = args.date_from.isoformat() if args.date_from else ""
    date_to = args.date_to.isoformat() if args.date_to else ""
    args.date_from = prompt_text("Incident date from (YYYY or YYYY-MM-DD)", date_from)
    args.date_to = prompt_text("Incident date to (YYYY or YYYY-MM-DD)", date_to)
    args.date_field = prompt_text(
        "Date field (incident/created/modified)", args.date_field
    ).lower()
    args.sub_source = prompt_text("Sub-source (blank for any)", args.sub_source or "")
    args.status = prompt_text("Analysis status (blank for any)", args.status or "")
    limit = prompt_text(
        "Maximum results (blank for no limit)",
        "" if args.limit is None else str(args.limit),
    )
    args.limit = int(limit) if limit else None
    if prompt_output:
        args.format = prompt_text(
            "Output format (text/csv/json/interactive)", args.format
        ).lower()

    try:
        args.date_from = parse_date_bound(args.date_from) if args.date_from else None
        args.date_to = parse_date_bound(args.date_to, upper=True) if args.date_to else None
    except ValueError as exc:
        parser.error(f"invalid date: {exc}")
    validate_filters(args, parser)


def validate_filters(args, parser):
    if args.min_techniques < 0:
        parser.error("--min-techniques must be non-negative")
    if args.max_techniques is not None and args.max_techniques < args.min_techniques:
        parser.error("--max-techniques must be greater than or equal to --min-techniques")
    if args.limit is not None and args.limit < 0:
        parser.error("--limit must be non-negative")
    if args.date_from and args.date_to and args.date_from > args.date_to:
        parser.error("--date-from must not be later than --date-to")
    if args.technique_match not in {"any", "all"}:
        parser.error("--technique-match must be any or all")
    if args.veris_match not in {"any", "all"}:
        parser.error("--veris-match must be any or all")
    if args.date_field not in {"incident", "created", "modified"}:
        parser.error("--date-field must be incident, created, or modified")
    if args.format not in {"text", "csv", "json", "interactive"}:
        parser.error("--format must be text, csv, json, or interactive")


def select_database_source(args, interactive):
    sources = discover_inputs()
    preferred_paths = [repo_path(path) for path in args.input]
    if args.input == [DEFAULT_INPUT] and not preferred_paths[0].exists() and sources:
        preferred_paths = sources[0]["paths"]
    if not any(tuple(source["paths"]) == tuple(preferred_paths) for source in sources):
        sources.append({
            "label": "Selected input" + ("s" if len(preferred_paths) != 1 else ""),
            "paths": preferred_paths,
        })
    default_index = next(
        (index for index, source in enumerate(sources)
         if tuple(source["paths"]) == tuple(preferred_paths)),
        next((index for index, source in enumerate(sources)
              if REPO_ROOT / DEFAULT_INPUT == source["paths"][0]), 0),
    )
    if interactive:
        index = choose_option(
            "VCDB database",
            [source["label"] for source in sources],
            default_index,
        )
    else:
        index = default_index
    return sources[index]["paths"]


def select_mapping(args, interactive):
    mappings = discover_mappings()
    preferred = repo_path(args.mapping)
    if args.mapping == DEFAULT_MAPPING and not preferred.exists() and mappings:
        preferred = next(
            (path for path in mappings
             if "veris-1.4.0" in path.name and "enterprise" in str(path)),
            mappings[0],
        )
    if preferred not in mappings:
        mappings.append(preferred)
        mappings.sort()
    default_index = mappings.index(preferred)
    if interactive:
        labels = []
        for path in mappings:
            try:
                labels.append(str(path.relative_to(REPO_ROOT)))
            except ValueError:
                labels.append(str(path))
        index = choose_option("VERIS-to-ATT&CK mapping", labels, default_index)
    else:
        index = default_index
    return mappings[index]


def parse_date_bound(value, upper=False):
    if re.fullmatch(r"\d{4}", value):
        year = int(value)
        return date(year, 12, 31) if upper else date(year, 1, 1)
    return date.fromisoformat(value)


def load_mapping(path):
    with path.open(encoding="utf-8") as source:
        mapping = json.load(source)
    techniques = {}
    for item in mapping.get("mapping_objects", []):
        technique_id = item.get("attack_object_id")
        capability_id = item.get("capability_id")
        if (
            item.get("status") == "non_mappable"
            or not isinstance(technique_id, str)
            or not TECHNIQUE_ID.fullmatch(technique_id)
            or not isinstance(capability_id, str)
        ):
            continue
        technique_id = technique_id.upper()
        entry = techniques.setdefault(
            technique_id, {"name": item.get("attack_object_name") or "", "paths": set()}
        )
        entry["paths"].add(capability_id)
        if not entry["name"] and item.get("attack_object_name"):
            entry["name"] = item["attack_object_name"]
    if not techniques:
        raise ValueError(f"No ATT&CK technique mappings found in {path}")
    return techniques


def records_from_json(source, source_name):
    data = json.load(source)
    if isinstance(data, dict):
        yield data
    elif isinstance(data, list):
        for record in data:
            if isinstance(record, dict):
                yield record
    else:
        raise ValueError(f"Expected a JSON object or array in {source_name}")


def records_from_csv(source):
    text = io.TextIOWrapper(source, encoding="utf-8-sig", newline="")
    yield from csv.DictReader(text)


def records_from_path(path):
    if path.is_dir():
        files = sorted(
            item for item in path.rglob("*")
            if item.is_file() and item.suffix.lower() == ".json"
        )
        for item in files:
            with item.open(encoding="utf-8-sig") as source:
                yield from records_from_json(source, str(item))
        return

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            candidates = [
                name for name in archive.namelist()
                if Path(name).suffix.lower() in {".json", ".csv"}
            ]
            if path.name.lower().endswith(".csv.zip"):
                candidates = [name for name in candidates if name.lower().endswith(".csv")]
            elif path.name.lower().endswith(".json.zip"):
                candidates = [name for name in candidates if name.lower().endswith(".json")]
            if len(candidates) > 1:
                root_candidates = [name for name in candidates if "/" not in name]
                if len(root_candidates) == 1:
                    candidates = root_candidates
            if len(candidates) != 1:
                raise ValueError(
                    f"Expected one .json or .csv file in {path}; found {len(candidates)}"
                )
            member = candidates[0]
            with archive.open(member) as source:
                if Path(member).suffix.lower() == ".csv":
                    yield from records_from_csv(source)
                else:
                    text = io.TextIOWrapper(source, encoding="utf-8-sig")
                    yield from records_from_json(text, f"{path}:{member}")
        return

    if path.suffix.lower() == ".csv":
        with path.open("rb") as source:
            yield from records_from_csv(source)
    else:
        with path.open(encoding="utf-8-sig") as source:
            yield from records_from_json(source, str(path))


def get_path(record, path):
    if path in record:
        return record[path]
    current = record
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return MISSING
        current = current[part]
    return current


def is_true(value):
    if isinstance(value, bool):
        return value
    return isinstance(value, str) and value.strip().casefold() in {
        "true", "1", "yes", "y"
    }


def has_veris_path(record, path):
    direct_value = record.get(path, MISSING)
    if direct_value is not MISSING and is_true(direct_value):
        return True

    parent, separator, leaf = path.rpartition(".")
    if not separator:
        return False
    observed = get_path(record, parent)
    if observed is MISSING:
        return False
    if isinstance(observed, list):
        return any(isinstance(value, str) and value.casefold() == leaf.casefold()
                   for value in observed)
    if isinstance(observed, dict):
        return is_true(observed.get(leaf, False))
    return isinstance(observed, str) and observed.casefold() == leaf.casefold()


def get_date_interval(record, field):
    if field in {"created", "modified"}:
        value = get_path(record, f"plus.{field}")
        if not isinstance(value, str) or value.strip().upper() in {"", "NA", "UNKNOWN"}:
            return None, ""
        try:
            parsed = date.fromisoformat(value[:10])
        except ValueError:
            return None, value
        return (parsed, parsed), value[:10]

    parts = [
        get_path(record, f"timeline.incident.{name}")
        for name in ("year", "month", "day")
    ]
    numbers = []
    for value in parts:
        try:
            numbers.append(int(value))
        except (ValueError, TypeError):
            numbers.append(None)
    year, month, day = numbers
    if not year or year < 1:
        return None, ""
    try:
        if month and day and 1 <= month <= 12 and 1 <= day <= 31:
            start = end = date(year, month, day)
            shown = f"{year:04d}-{month:02d}-{day:02d}"
        elif month and 1 <= month <= 12:
            start = date(year, month, 1)
            end = date(year + (month == 12), 1 if month == 12 else month + 1, 1)
            end = date.fromordinal(end.toordinal() - 1)
            shown = f"{year:04d}-{month:02d}"
        else:
            start, end = date(year, 1, 1), date(year, 12, 31)
            shown = str(year)
    except ValueError:
        return None, ""
    return (start, end), shown


def record_matches(record, techniques, args, mapping_prefixes):
    mapped_ids = set()
    evidence = {}
    for technique_id, details in techniques.items():
        matched_paths = sorted(
            path for path in details["paths"]
            if (
                not mapping_prefixes
                or any(path.startswith(prefix) for prefix in mapping_prefixes)
            ) and has_veris_path(record, path)
        )
        if matched_paths:
            mapped_ids.add(technique_id)
            evidence[technique_id] = matched_paths

    count = len(mapped_ids)
    if count < args.min_techniques:
        return None
    if args.max_techniques is not None and count > args.max_techniques:
        return None
    if args.technique_ids:
        matched_requested = mapped_ids.intersection(args.technique_ids)
        if args.technique_match == "all" and matched_requested != args.technique_ids:
            return None
        if args.technique_match == "any" and not matched_requested:
            return None
    if args.veris_paths:
        observed_paths = {path for path in args.veris_paths if has_veris_path(record, path)}
        if args.veris_match == "all" and observed_paths != set(args.veris_paths):
            return None
        if args.veris_match == "any" and not observed_paths:
            return None

    interval, displayed_date = get_date_interval(record, args.date_field)
    if args.date_from or args.date_to:
        if interval is None:
            return None
        start = args.date_from or date.min
        end = args.date_to or date.max
        if interval[1] < start or interval[0] > end:
            return None

    if args.sub_source:
        value = get_path(record, "plus.sub_source")
        values = value if isinstance(value, list) else [value]
        if not any(str(item).casefold() == args.sub_source.casefold() for item in values):
            return None
    if args.status:
        value = get_path(record, "plus.analysis_status")
        if not isinstance(value, str) or value.casefold() != args.status.casefold():
            return None

    return {
        "incident_id": get_path(record, "incident_id") or "",
        "date": displayed_date,
        "technique_count": count,
        "techniques": [
            {
                "id": technique_id,
                "name": techniques[technique_id]["name"],
                "veris_paths": evidence[technique_id],
            }
            for technique_id in sorted(mapped_ids)
        ],
        "summary": get_path(record, "summary") or "",
        "record": record,
    }


def output_results(results, output_format):
    if output_format == "json":
        json.dump(results, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    elif output_format == "csv":
        writer = csv.DictWriter(
            sys.stdout,
            fieldnames=("incident_id", "date", "technique_count", "techniques", "summary"),
        )
        writer.writeheader()
        for result in results:
            techniques = "; ".join(
                f'{item["id"]} {item["name"]}'.strip()
                for item in result["techniques"]
            )
            writer.writerow({
                "incident_id": result["incident_id"],
                "date": result["date"],
                "technique_count": result["technique_count"],
                "techniques": techniques,
                "summary": result["summary"],
            })
    else:
        for result in results:
            techniques = ", ".join(
                f'{item["id"]} {item["name"]}'.strip()
                for item in result["techniques"]
            )
            print(
                f'{result["incident_id"]} | {result["date"] or "date unknown"} | '
                f'{result["technique_count"]} techniques | {techniques}'
            )
            if result["summary"]:
                print(f'  {result["summary"]}')
            for item in result["techniques"]:
                print(f'  {item["id"]} VERIS: {", ".join(item["veris_paths"])}')


def clear_screen():
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


def query_records(input_paths, techniques, args, mapping_prefixes):
    results = []
    for input_path in input_paths:
        for record in records_from_path(input_path):
            result = record_matches(record, techniques, args, mapping_prefixes)
            if result is not None:
                results.append(result)
    if args.limit is not None:
        results = results[:args.limit]
    return results


def configure_technique_filter(args, techniques, parser):
    requested_ids = {value.upper() for value in args.requested_techniques}
    unknown_ids = requested_ids.difference(techniques)
    if unknown_ids:
        parser.error("technique IDs are not in the mapping: " + ", ".join(sorted(unknown_ids)))
    args.technique_ids = requested_ids
    return tuple(
        args.mapping_prefix if args.mapping_prefix is not None else ["action."]
    )


def browse_results(results, input_paths, techniques, args, parser):
    index = 0
    notice = ""
    while True:
        clear_screen()
        if results:
            result = results[index]
            print(
                f'Incident {index + 1}/{len(results)} | {result["incident_id"]} | '
                f'{result["date"] or "date unknown"} | '
                f'{result["technique_count"]} mapped techniques'
            )
            if result["summary"]:
                print(f'\n{result["summary"]}')
            print("\nMapped techniques:")
            for item in result["techniques"]:
                print(f'  {item["id"]} {item["name"]}')
                for path in item["veris_paths"]:
                    print(f"    VERIS: {path}")
        else:
            print("No incidents match the current filters.")

        if notice:
            print(f"\n{notice}")
        print("\nControls: [n]ext  [p]revious  [r]eplay  [g]o to first  [f]ilters  [q]uit")
        try:
            command = input("> ").strip().lower()
        except EOFError:
            command = "q"
        notice = ""

        if command in {"q", "quit"}:
            return
        if command in {"r", "replay", ""}:
            continue
        if command in {"n", "next"}:
            if index + 1 < len(results):
                index += 1
            else:
                notice = "Already at the last incident."
            continue
        if command in {"p", "previous"}:
            if index > 0:
                index -= 1
            else:
                notice = "Already at the first incident."
            continue
        if command in {"g", "first"}:
            index = 0
            continue
        if command in {"f", "filters"}:
            prompt_filters(args, parser, prompt_output=False)
            validate_filters(args, parser)
            mapping_prefixes = configure_technique_filter(args, techniques, parser)
            results = query_records(input_paths, techniques, args, mapping_prefixes)
            index = 0
            notice = f"Filters updated: {len(results)} matching incidents."
            continue
        notice = "Unknown command. Use n, p, r, g, f, or q."


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        nargs="+",
        type=Path,
        default=[DEFAULT_INPUT],
        help="VCDB file or directory; default: auto-discovered VCDB/data/csv/vcdb.csv.zip",
    )
    parser.add_argument(
        "--mapping",
        type=Path,
        default=DEFAULT_MAPPING,
        help="VERIS mapping JSON; default: mappings-explorer's ATT&CK 16.1 / VERIS 1.4.0 enterprise map",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="use defaults and supplied filters without prompting",
    )
    parser.add_argument("--min-techniques", type=int, default=2)
    parser.add_argument("--max-techniques", type=int)
    parser.add_argument("--technique", dest="requested_techniques", action="append", default=[],
                        help="require an ATT&CK technique ID; repeatable")
    parser.add_argument("--technique-match", choices=("any", "all"), default="any")
    parser.add_argument("--mapping-prefix", action="append",
                        help="count techniques mapped to VERIS paths with this prefix; "
                             "default: action. (repeatable)")
    parser.add_argument("--veris-path", dest="veris_paths", action="append", default=[],
                        help="require a VERIS path, e.g. action.hacking.variety.SQLi")
    parser.add_argument("--veris-match", choices=("any", "all"), default="any")
    parser.add_argument("--date-from", type=lambda value: parse_date_bound(value),
                        help="inclusive incident date (YYYY or YYYY-MM-DD)")
    parser.add_argument("--date-to", type=lambda value: parse_date_bound(value, upper=True),
                        help="inclusive incident date (YYYY or YYYY-MM-DD)")
    parser.add_argument("--date-field", choices=("incident", "created", "modified"),
                        default="incident")
    parser.add_argument("--sub-source", help="match plus.sub_source exactly, case-insensitive")
    parser.add_argument("--status", help="match plus.analysis_status, case-insensitive")
    parser.add_argument("--limit", type=int, help="maximum number of results to print")
    parser.add_argument(
        "--format",
        choices=("text", "csv", "json", "interactive"),
        default="text",
        help="output style; interactive browses one incident at a time",
    )
    args = parser.parse_args()

    interactive = not args.non_interactive and sys.stdin.isatty()
    input_paths = select_database_source(args, interactive)
    mapping_path = select_mapping(args, interactive)
    if interactive:
        prompt_filters(args, parser)
    validate_filters(args, parser)
    if args.format == "interactive" and not sys.stdin.isatty():
        parser.error("interactive output requires a terminal")

    techniques = load_mapping(mapping_path)
    mapping_prefixes = configure_technique_filter(args, techniques, parser)
    results = query_records(input_paths, techniques, args, mapping_prefixes)
    if args.format == "interactive":
        browse_results(results, input_paths, techniques, args, parser)
    else:
        output_results(results, args.format)


if __name__ == "__main__":
    main()
