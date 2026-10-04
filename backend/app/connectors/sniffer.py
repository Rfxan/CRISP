"""
Structure Sniffer for CRISP Vendor Onboarding.
Inspects sample files (XML, CSV, JSON) and returns structural metadata
and available fields without parsing into findings.
"""
from typing import Dict, Any, List, Set, Optional, Tuple
from defusedxml import ElementTree as ET
from xml.etree.ElementTree import Element
import csv
import io
import json
import re


FIELD_ALIASES = {
    "asset_id": ("host ip", "ip address", "asset id", "resource arn", "resource id", "host", "hostname", "ip", "target", "asset", "resource", "node"),
    "cve_id": ("cve id", "cve ids", "cve", "cves", "cve name", "vulnerability id"),
    "cvss": ("cvss v3 base score", "cvss3 base score", "cvss v3 score", "cvss3 score", "cvss v3", "cvss3", "cvss base", "cvss base score", "cvss score", "cvss", "base score"),
    "severity": ("severity", "threat", "risk factor", "risk rating", "severity level", "risk level", "risk", "level", "criticality"),
    "port": ("port", "service port", "protocol port", "target port"),
    "issue_type": ("check id", "rule id", "issue type", "plugin name", "check", "rule", "issue", "title", "name"),
}


def _field_words(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _scalar_values(value: Any) -> List[Any]:
    if isinstance(value, list):
        return [item for child in value for item in _scalar_values(child)]
    return [] if value is None or isinstance(value, dict) else [value]


def describe_field_values(fields: List[str], records: List[Any]) -> Dict[str, Any]:
    """Summarize types and coverage without exposing scan values to a model."""
    profiles = {}
    severity_names = {"critical", "high", "medium", "moderate", "low", "info", "information", "informational", "log"}
    for field in fields:
        profile = {"types": set(), "records_with_value": 0, "cve_matches": 0,
                   "severity_matches": 0, "numeric_0_to_10": 0, "cvss_vectors": 0}
        for record in records[:20]:
            raw = extract_field_value(record, field)
            kind = "null" if raw is None else "boolean" if isinstance(raw, bool) else (
                "number" if isinstance(raw, (float, int)) else "array" if isinstance(raw, list) else
                "object" if isinstance(raw, dict) else "string")
            profile["types"].add(kind)
            values = [value for value in _scalar_values(raw) if str(value).strip()]
            if values:
                profile["records_with_value"] += 1
            if any(re.search(r"\bCVE-\d{4}-\d{4,}\b", str(value), re.I) for value in values):
                profile["cve_matches"] += 1
            if any(str(value).strip().lower() in severity_names or re.fullmatch(r"[0-4]", str(value).strip()) for value in values):
                profile["severity_matches"] += 1
            numeric = []
            for value in values:
                try:
                    numeric.append(not isinstance(value, bool) and 0 <= float(value) <= 10)
                except (TypeError, ValueError):
                    continue
            if any(numeric):
                profile["numeric_0_to_10"] += 1
            if any(str(value).startswith(("CVSS:", "AV:")) for value in values):
                profile["cvss_vectors"] += 1
        profile["types"] = sorted(profile["types"])
        profiles[field] = profile
    return profiles


def suggest_field_mapping(fields: List[str], records: Optional[List[Any]] = None) -> Dict[str, str]:
    """Rank whole field names and sample values; never substring-match 'ip' in 'description'."""
    samples = records or []
    values = {field: [value for rec in samples[:20]
                      for value in _scalar_values(extract_field_value(rec, field))] for field in fields}
    suggested = {}
    for canonical, aliases in FIELD_ALIASES.items():
        candidates = []
        for field in fields:
            leaf = _field_words(field.split(".")[-1])
            whole = _field_words(field)
            ranks = [len(aliases) - index for index, alias in enumerate(aliases)
                     if _field_words(alias) in (leaf, whole)]
            score = max(ranks, default=0)
            observed = values[field]
            if score and samples and not observed and any(isinstance(extract_field_value(rec, field), (dict, list)) for rec in samples[:20]):
                score = 0
            if canonical == "cve_id":
                # OpenVAS puts CVEs in repeated <ref type="cve" id="CVE-..."/> attributes.
                has_cve = any(re.search(r"\bCVE-\d{4}-\d{4,}\b", str(v), re.I) for v in observed)
                cve_context = any(_field_words(part) in {"ref", "refs", "reference", "references", "cve", "cves"}
                                  for part in field.split(".")[:-1])
                if leaf == "id" and cve_context and has_cve:
                    score = len(aliases) + 1
                elif score and observed and not has_cve:
                    score = 0
            if canonical == "severity" and score and observed:
                descriptive = {"critical", "high", "medium", "moderate", "low", "info", "information", "informational", "log"}
                if any(str(v).strip().lower() in descriptive for v in observed):
                    score += 30
                # Numeric severity may represent a CVSS score, not a 0-4 rating.
                elif any(not re.fullmatch(r"[0-4]", str(v).strip()) for v in observed):
                    score = 0
            if canonical == "issue_type" and leaf == "name" and field.lower().startswith(("nvt.", "plugin.")):
                score += 2
            if canonical == "cvss" and score and observed:
                numeric = []
                for value in observed:
                    try:
                        numeric.append(0 <= float(value) <= 10)
                    except (TypeError, ValueError):
                        continue
                if not any(numeric):
                    score = 0
            if score:
                # Prefer a direct scalar over a similarly named nested container.
                candidates.append((score, bool(observed), -field.count("."), field))
        suggested[canonical] = max(candidates)[-1] if candidates else ""
    return suggested


def _xml_nodes_for_path(root: Element, parts: List[str]) -> List[Element]:
    nodes = [root]
    for part in parts:
        nodes = [child for node in nodes for child in node if child.tag.split("}")[-1] == part]
    return nodes


def _extract_xml_fields(elem: Element, prefix: str = "") -> Set[str]:
    """Recursively extract tag and attribute paths from an XML element."""
    fields = set()
    # Add attributes of current element
    for attr in elem.attrib.keys():
        fields.add(f"@{attr}" if not prefix else f"{prefix}.@{attr}")

    for child in elem:
        tag = child.tag
        # Strip XML namespace if present
        if "}" in tag:
            tag = tag.split("}", 1)[1]
        child_path = f"{prefix}.{tag}" if prefix else tag
        fields.add(child_path)
        fields.update(_extract_xml_fields(child, prefix=child_path))

    return fields


def _collect_xml_paths(elem: Element, current_path: str = "") -> List[Tuple[str, Element]]:
    """Collects all element paths in the XML document."""
    tag = elem.tag
    if "}" in tag:
        tag = tag.split("}", 1)[1]
    path = f"{current_path}.{tag}" if current_path else tag
    results = [(path, elem)]
    for child in elem:
        results.extend(_collect_xml_paths(child, path))
    return results


def _extract_json_fields(obj: Any, prefix: str = "", max_depth: int = 4) -> Set[str]:
    """Recursively extracts dot-notation paths from a JSON object."""
    fields = set()
    if max_depth <= 0:
        return fields

    if isinstance(obj, dict):
        for k, v in obj.items():
            curr = f"{prefix}.{k}" if prefix else str(k)
            fields.add(curr)
            if isinstance(v, dict):
                fields.update(_extract_json_fields(v, curr, max_depth - 1))
            elif isinstance(v, list) and v and isinstance(v[0], dict):
                # Sample the first item of nested list
                fields.update(_extract_json_fields(v[0], curr, max_depth - 1))
    return fields


def extract_field_value(record: Any, field_path: Optional[str]) -> Optional[Any]:
    """
    Extracts a value from a record (XML Element, Dict, or Row) using a dot-path.
    Used identically across sniffer and generic vendor connector.
    """
    if not field_path or record is None:
        return None

    path_str = str(field_path).strip()

    # 1. XML Element record
    if isinstance(record, Element):
        # Attribute on root element itself: e.g. "@port" or "port"
        if path_str.startswith("@"):
            attr_name = path_str[1:]
            return record.get(attr_name)

        # Attribute on child element: e.g. "ReportItem.@port" or "ReportItem@port"
        if "@" in path_str:
            parts = path_str.replace(".@", "@").split("@")
            child_subpath = parts[0].rstrip(".").replace(".", "/")
            attr_name = parts[1]
            if child_subpath:
                children = _xml_nodes_for_path(record, parts[0].rstrip(".").split("."))
                values = [child.get(attr_name) for child in children if child.get(attr_name) is not None]
                return values[0] if len(values) == 1 else (values or None)
            return record.get(attr_name)

        # Subelement text: e.g. "nvt.cve" -> search "nvt/cve" or ".//cve"
        targets = _xml_nodes_for_path(record, path_str.split("."))
        values = [target.text.strip() for target in targets if target.text and target.text.strip()]
        if values:
            return values[0] if len(values) == 1 else values

        # Fallback to direct attribute with same name
        if path_str in record.attrib:
            return record.attrib[path_str]

        # Deep search fallback
        leaf_tag = path_str.split(".")[-1]
        deep_target = next((node for node in record.iter() if node.tag.split("}")[-1] == leaf_tag
                            and node.text and node.text.strip()), None)
        if deep_target is not None:
            return deep_target.text.strip()

        return None

    # 2. Python Dict record (JSON or CSV DictReader)
    if isinstance(record, dict):
        # Direct key match first
        if path_str in record and record[path_str] is not None:
            return record[path_str]

        # Dot-path traversal for nested dicts
        parts = path_str.split(".")
        def walk(curr, remaining):
            if not remaining:
                return curr
            if isinstance(curr, list):
                return [value for child in curr for value in _scalar_values(walk(child, remaining))]
            if isinstance(curr, dict) and remaining[0] in curr:
                return walk(curr[remaining[0]], remaining[1:])
            return None
        return walk(record, parts)

    return None


def detect_structure(file_content: bytes, file_extension: str = "") -> Dict[str, Any]:
    """
    Inspects an uploaded file and returns its structure without parsing into findings.
    Supports XML, CSV, and JSON.
    Returns:
      {
        "format": "xml" | "csv" | "json",
        "detected_record_path": str,
        "record_count_sample": int,
        "available_fields": List[str]
      }
    Or:
      {"error": "reason"}
    """
    if not file_content or len(file_content.strip()) == 0:
        return {"error": "Uploaded file is empty"}

    ext = file_extension.lower().lstrip(".")

    # Try XML if extension matches or starts with '<'
    content_head = file_content.lstrip()[:200]
    is_xml_likely = ext in ["xml", "nessus"] or content_head.startswith(b"<")

    if is_xml_likely:
        try:
            root = ET.fromstring(file_content)
            all_nodes = _collect_xml_paths(root)

            # Count frequency of each path
            path_counts: Dict[str, int] = {}
            nodes_by_path: Dict[str, List[Element]] = {}
            for p, node in all_nodes:
                # Do not treat root element itself as a repeated record
                if p == root.tag.split("}")[-1]:
                    continue
                path_counts[p] = path_counts.get(p, 0) + 1
                nodes_by_path.setdefault(p, []).append(node)

            if not path_counts:
                return {"error": "XML document contains no child records"}

            # A reference list can be longer than the findings it belongs to.
            # Prefer complete finding records, using frequency only as a tie-breaker.
            record_names = {"result", "finding", "vulnerability", "alert", "record", "item", "reportitem", "issue", "detection", "entry", "check"}
            candidates = []
            for path, count in path_counts.items():
                sample_records = nodes_by_path[path][:20]
                fields = sorted(set().union(*(_extract_xml_fields(rec) for rec in sample_records)))
                if not fields:
                    continue
                mapping = suggest_field_mapping(fields, sample_records)
                required = sum(bool(mapping[key]) for key in ("asset_id", "severity"))
                identity = bool(mapping["cve_id"] or mapping["issue_type"])
                depth = sum(value.count(".") for key, value in mapping.items() if value and key in ("asset_id", "severity", "cve_id", "issue_type"))
                rank = (required == 2 and identity, required + identity,
                        path.split(".")[-1].lower() in record_names, -depth, count, len(fields))
                candidates.append((rank, path))
            if not candidates:
                return {"error": "XML document contains no mappable record fields"}
            best_path = max(candidates)[1]
            best_count = path_counts[best_path]

            # Aggregate fields across multiple samples of this record (up to 20 samples)
            available_fields_set = set()
            sample_records = nodes_by_path[best_path][:20]
            for rec in sample_records:
                available_fields_set.update(_extract_xml_fields(rec))
                for a in rec.attrib.keys():
                    available_fields_set.add(f"@{a}")

            available_fields = sorted(available_fields_set)
            return {
                "format": "xml",
                "detected_record_path": best_path,
                "record_count_sample": best_count,
                "available_fields": available_fields,
                "suggested_mapping": suggest_field_mapping(available_fields, sample_records),
                "field_profiles": describe_field_values(available_fields, sample_records)
            }
        except ET.ParseError as e:
            if ext == "xml":
                return {"error": f"Malformed XML file: {str(e)}"}
            # Otherwise continue to try other formats

    # Try JSON
    is_json_likely = ext == "json" or content_head.startswith(b"{") or content_head.startswith(b"[")
    if is_json_likely:
        try:
            text = file_content.decode("utf-8-sig", errors="ignore").strip()
            data = json.loads(text)

            detected_record_path = ""
            records: List[Any] = []

            if isinstance(data, list):
                records = [r for r in data if isinstance(r, dict)]
                detected_record_path = "root"
            elif isinstance(data, dict):
                # Search nested envelopes such as data.findings as well as top-level arrays.
                list_keys = []
                def collect_arrays(obj, prefix="", depth=0):
                    if depth > 8 or not isinstance(obj, dict):
                        return
                    for key, value in obj.items():
                        path = f"{prefix}.{key}" if prefix else key
                        if isinstance(value, list) and value and all(isinstance(item, dict) for item in value):
                            fields = sorted(set().union(*(_extract_json_fields(rec) for rec in value[:30])))
                            mapping = suggest_field_mapping(fields, value)
                            required = sum(bool(mapping[name]) for name in ("asset_id", "severity"))
                            list_keys.append(((required, bool(mapping["cve_id"] or mapping["issue_type"]), len(value)), path, value))
                        elif isinstance(value, dict):
                            collect_arrays(value, path, depth + 1)
                collect_arrays(data)
                if list_keys:
                    _, detected_record_path, records = max(list_keys, key=lambda item: item[0])
                else:
                    return {"error": "JSON document does not contain an array of finding records"}

            if not records:
                return {"error": "No records found in JSON structure"}

            available_fields_set = set()
            for rec in records[:30]:
                available_fields_set.update(_extract_json_fields(rec))

            available_fields = sorted(available_fields_set)
            return {
                "format": "json",
                "detected_record_path": detected_record_path,
                "record_count_sample": len(records),
                "available_fields": available_fields,
                "suggested_mapping": suggest_field_mapping(available_fields, records),
                "field_profiles": describe_field_values(available_fields, records)
            }
        except Exception as e:
            if ext == "json":
                return {"error": f"Malformed JSON file: {str(e)}"}

    # Try CSV
    try:
        text = file_content.decode("utf-8-sig", errors="ignore").strip()
        f_io = io.StringIO(text)
        # Check first line for CSV delimiters
        first_line = f_io.readline()
        f_io.seek(0)
        delimiter = ","
        if "\t" in first_line and first_line.count("\t") > first_line.count(","):
            delimiter = "\t"
        elif ";" in first_line and first_line.count(";") > first_line.count(","):
            delimiter = ";"

        reader = csv.reader(f_io, delimiter=delimiter)
        headers = next(reader, None)
        if headers:
            fieldnames = [h.strip() for h in headers]
            headers = [h for h in fieldnames if h]
            # Count remaining rows
            row_count = sum(1 for row in reader if any(row))
            if headers and (row_count > 0 or ext == "csv"):
                sample_reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
                _ = sample_reader.fieldnames  # Consume the original header before setting trimmed names.
                sample_reader.fieldnames = fieldnames
                sample_records = [row for _, row in zip(range(20), sample_reader)]
                return {
                    "format": "csv",
                    "detected_record_path": "row",
                    "record_count_sample": row_count,
                    "available_fields": headers,
                    "suggested_mapping": suggest_field_mapping(headers, sample_records),
                    "field_profiles": describe_field_values(headers, sample_records)
                }
    except Exception as e:
        if ext == "csv":
            return {"error": f"Malformed CSV file: {str(e)}"}

    return {"error": f"Unable to determine file structure or format (extension: .{ext})"}
