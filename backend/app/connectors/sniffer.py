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


def _extract_xml_fields(elem: Element, prefix: str = "") -> Set[str]:
    """Recursively extract tag and attribute paths from an XML element."""
    fields = set()
    # Add attributes of current element
    for attr in elem.attrib.keys():
        fields.add(f"@{attr}" if not prefix else f"{prefix}.@{attr}")

    has_children = False
    for child in elem:
        has_children = True
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
                child = record.find(child_subpath)
                return child.get(attr_name) if child is not None else None
            return record.get(attr_name)

        # Subelement text: e.g. "nvt.cve" -> search "nvt/cve" or ".//cve"
        xml_slash_path = path_str.replace(".", "/")
        target = record.find(xml_slash_path)
        if target is not None and target.text:
            return target.text.strip()

        # Fallback to direct attribute with same name
        if path_str in record.attrib:
            return record.attrib[path_str]

        # Deep search fallback
        leaf_tag = path_str.split(".")[-1]
        deep_target = record.find(f".//{leaf_tag}")
        if deep_target is not None and deep_target.text:
            return deep_target.text.strip()

        return None

    # 2. Python Dict record (JSON or CSV DictReader)
    if isinstance(record, dict):
        # Direct key match first
        if path_str in record and record[path_str] is not None:
            return record[path_str]

        # Dot-path traversal for nested dicts
        parts = path_str.split(".")
        curr = record
        for part in parts:
            if isinstance(curr, dict) and part in curr:
                curr = curr[part]
            else:
                return None
        return curr

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

            # Choose the most frequent non-leaf element path with children/attributes
            # Sort by frequency descending, then by number of available fields descending
            sorted_candidates = sorted(
                path_counts.items(),
                key=lambda item: (item[1], len(_extract_xml_fields(nodes_by_path[item[0]][0]))),
                reverse=True
            )

            # Filter candidates: prioritize elements with multiple fields
            best_path = None
            best_count = 0
            for path, count in sorted_candidates:
                sample_node = nodes_by_path[path][0]
                fields = _extract_xml_fields(sample_node)
                # Check attributes on candidate node itself as well
                for a in sample_node.attrib.keys():
                    fields.add(f"@{a}")
                if fields:
                    best_path = path
                    best_count = count
                    break

            if not best_path:
                best_path = sorted_candidates[0][0]
                best_count = sorted_candidates[0][1]

            # Aggregate fields across multiple samples of this record (up to 20 samples)
            available_fields_set = set()
            sample_records = nodes_by_path[best_path][:20]
            for rec in sample_records:
                available_fields_set.update(_extract_xml_fields(rec))
                for a in rec.attrib.keys():
                    available_fields_set.add(f"@{a}")

            return {
                "format": "xml",
                "detected_record_path": best_path,
                "record_count_sample": best_count,
                "available_fields": sorted(list(available_fields_set))
            }
        except ET.ParseError as e:
            if ext == "xml":
                return {"error": f"Malformed XML file: {str(e)}"}
            # Otherwise continue to try other formats

    # Try JSON
    is_json_likely = ext == "json" or content_head.startswith(b"{") or content_head.startswith(b"[")
    if is_json_likely:
        try:
            text = file_content.decode("utf-8", errors="ignore").strip()
            data = json.loads(text)

            detected_record_path = ""
            records: List[Any] = []

            if isinstance(data, list):
                records = [r for r in data if isinstance(r, dict)]
                detected_record_path = "root"
            elif isinstance(data, dict):
                # Search for list-valued keys
                list_keys = [(k, v) for k, v in data.items() if isinstance(v, list) and v and isinstance(v[0], dict)]
                if list_keys:
                    # Choose list with the highest record count
                    list_keys.sort(key=lambda item: len(item[1]), reverse=True)
                    detected_record_path = list_keys[0][0]
                    records = list_keys[0][1]
                else:
                    return {"error": "JSON document does not contain an array of finding records"}

            if not records:
                return {"error": "No records found in JSON structure"}

            available_fields_set = set()
            for rec in records[:30]:
                available_fields_set.update(_extract_json_fields(rec))

            return {
                "format": "json",
                "detected_record_path": detected_record_path,
                "record_count_sample": len(records),
                "available_fields": sorted(list(available_fields_set))
            }
        except Exception as e:
            if ext == "json":
                return {"error": f"Malformed JSON file: {str(e)}"}

    # Try CSV
    try:
        text = file_content.decode("utf-8", errors="ignore").strip()
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
            headers = [h.strip() for h in headers if h and h.strip()]
            # Count remaining rows
            row_count = sum(1 for row in reader if any(row))
            if headers and (row_count > 0 or ext == "csv"):
                return {
                    "format": "csv",
                    "detected_record_path": "row",
                    "record_count_sample": row_count,
                    "available_fields": headers
                }
    except Exception as e:
        if ext == "csv":
            return {"error": f"Malformed CSV file: {str(e)}"}

    return {"error": f"Unable to determine file structure or format (extension: .{ext})"}
