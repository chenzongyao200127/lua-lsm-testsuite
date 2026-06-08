"""Emit a JUnit XML document from a matrix.json document.

One <testcase> per cell, ordered by `cell_id`. Verdicts are mapped through
the same `schemas.VERDICT_CLASSIFICATION` table TAP uses, so CI dashboards
that ingest JUnit see the same pass/fail/skip story as the TAP stream:

    pass  -> <testcase/>
    fail  -> <testcase><failure type="<verdict>" message="..."/></testcase>
    skip  -> <testcase><skipped message="<verdict>"/></testcase>

The document shape matches the de facto JUnit dialect (Jenkins/GitLab):

    <testsuites name="<matrix-name>" tests="N" failures="F" skipped="S">
      <testsuite name="<matrix-name>" tests="N" failures="F" skipped="S">
        <testcase classname="<matrix-name>" name="<cell_id>"/>
        ...
      </testsuite>
    </testsuites>
"""

from __future__ import annotations

from typing import Iterable, Mapping
from xml.etree import ElementTree as ET

from . import schemas


def _verdict_class(verdict: str | None) -> str:
    if verdict is None:
        return "fail"
    return schemas.VERDICT_CLASSIFICATION.get(verdict, "fail")


def emit_junit(matrix: Mapping[str, object]) -> str:
    cells_in: Iterable[Mapping[str, object]] = matrix.get("cells") or []  # type: ignore[assignment]
    cells = sorted(cells_in, key=lambda c: str(c.get("cell_id", "")))

    suite_name = str(matrix.get("name") or "matrix")
    total = len(cells)
    failures = sum(1 for c in cells
                   if _verdict_class(c.get("verdict") if isinstance(c.get("verdict"), str) else None) == "fail")
    skipped = sum(1 for c in cells
                  if _verdict_class(c.get("verdict") if isinstance(c.get("verdict"), str) else None) == "skip")

    root = ET.Element("testsuites", {
        "name": suite_name,
        "tests": str(total),
        "failures": str(failures),
        "skipped": str(skipped),
    })
    suite = ET.SubElement(root, "testsuite", {
        "name": suite_name,
        "tests": str(total),
        "failures": str(failures),
        "skipped": str(skipped),
    })

    for cell in cells:
        cell_id = str(cell.get("cell_id", ""))
        verdict = cell.get("verdict") if isinstance(cell.get("verdict"), str) else None
        klass = _verdict_class(verdict)
        case = ET.SubElement(suite, "testcase", {
            "classname": suite_name,
            "name": cell_id,
        })
        if klass == "fail":
            v = verdict or "no-verdict"
            ET.SubElement(case, "failure", {
                "type": v,
                "message": f"verdict: {v}",
            })
        elif klass == "skip":
            ET.SubElement(case, "skipped", {
                "message": str(verdict) if verdict else "unknown",
            })

    ET.indent(root, space="  ")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"
