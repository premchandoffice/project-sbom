#!/usr/bin/env python3
"""
Generate a Markdown summary report for each CycloneDX SBOM JSON file
found in the input directory.

Usage:
    python3 generate_summary.py <sbom_input_dir> <report_output_dir>
"""
import json
import re
import sys
import collections
from pathlib import Path
from datetime import datetime, timezone


def summarize(sbom_path: Path) -> str:
    with open(sbom_path) as f:
        data = json.load(f)

    comps = data.get("components", [])
    meta = data.get("metadata", {})
    app_name = meta.get("component", {}).get("name", sbom_path.stem)
    scan_ts = meta.get("timestamp", "unknown")

    eco_counter = collections.Counter()
    license_counter = collections.Counter()
    name_versions = collections.defaultdict(set)

    for c in comps:
        purl = c.get("purl", "")
        m = re.match(r"pkg:([^/]+)/", purl)
        eco_counter[m.group(1) if m else "unknown"] += 1

        seen = set()
        for lic in c.get("licenses", []) or []:
            lid = lic.get("license", {}).get("id") or lic.get("license", {}).get("name")
            if lid and lid not in seen:
                license_counter[lid] += 1
                seen.add(lid)

        name_versions[c.get("name")].add(c.get("version"))

    total = len(comps)
    unique_names = len(name_versions)
    dupes = {k: v for k, v in name_versions.items() if len(v) > 1}
    top_dupes = sorted(dupes.items(), key=lambda x: -len(x[1]))[:10]
    has_vulns = "vulnerabilities" in data

    lines = []
    lines.append(f"# SBOM Summary Report — {app_name}")
    lines.append("")
    lines.append(f"- **Source file:** {sbom_path.name}")
    lines.append(f"- **Scan timestamp:** {scan_ts}")
    lines.append(f"- **Report generated:** {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"- **Total component entries:** {total}")
    lines.append(f"- **Unique package names:** {unique_names}")
    lines.append(f"- **Vulnerability data present:** {'Yes' if has_vulns else 'No'}")
    lines.append("")

    lines.append("## Ecosystem Breakdown")
    lines.append("")
    lines.append("| Ecosystem | Entries | % of Total |")
    lines.append("|---|---|---|")
    for eco, count in eco_counter.most_common():
        pct = (count / total * 100) if total else 0
        lines.append(f"| {eco} | {count} | {pct:.1f}% |")
    lines.append("")

    lines.append("## License Breakdown")
    lines.append("")
    lines.append("| License (SPDX) | Entries | % of Total |")
    lines.append("|---|---|---|")
    for lic, count in license_counter.most_common():
        pct = (count / total * 100) if total else 0
        lines.append(f"| {lic} | {count} | {pct:.1f}% |")
    lines.append("")

    lines.append("## Version Sprawl (Top 10)")
    lines.append("")
    if top_dupes:
        lines.append("| Package | Distinct Versions |")
        lines.append("|---|---|")
        for name, versions in top_dupes:
            lines.append(f"| {name} | {len(versions)} |")
    else:
        lines.append("No packages with multiple versions detected.")
    lines.append("")

    return "\n".join(lines)


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 generate_summary.py <sbom_input_dir> <report_output_dir>")
        sys.exit(1)

    input_dir = Path(sys.argv[1])
    output_dir = Path(sys.argv[2])
    output_dir.mkdir(parents=True, exist_ok=True)

    sbom_files = sorted(input_dir.glob("*.json"))
    if not sbom_files:
        print(f"No SBOM JSON files found in {input_dir}")
        sys.exit(1)

    for sbom_path in sbom_files:
        report_md = summarize(sbom_path)
        out_path = output_dir / f"{sbom_path.stem}-summary.md"
        out_path.write_text(report_md)
        print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
