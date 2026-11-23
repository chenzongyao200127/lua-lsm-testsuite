import json

from harness import unixbench_report

SAMPLE = """\
========================================================================
   BYTE UNIX Benchmarks (Version 5.1.3)

   System: lua-ci: GNU/Linux
Benchmark Run: Sun Nov 23 2026 07:03:01 - 07:18:22
1 CPU in system; running 1 parallel copy of tests

Dhrystone 2 using register variables       21587377.2 lps   (10.0 s, 7 samples)
Double-Precision Whetstone                     4281.4 MWIPS (9.9 s, 7 samples)

System Benchmarks Index Values               BASELINE       RESULT    INDEX
Dhrystone 2 using register variables         116700.0   21587377.2   1849.8
Double-Precision Whetstone                      55.0       4281.4    778.4
File Copy 1024 bufsize 2000 maxblocks         3960.0     123456.0    311.8
Pipe Throughput                              12440.0     987654.0    793.9
Process Creation                                126.0        654.0    519.0

System Benchmarks Index Score                                         1588.1
"""


def test_parse_index_score_and_rows():
    score = unixbench_report.parse_log(SAMPLE)
    assert score.index_score == 1588.1
    assert score.tests["Dhrystone 2 using register variables"] == 1849.8
    assert score.tests["Process Creation"] == 519.0
    assert len(score.tests) == 5
    assert score.cpus == 1
    assert score.parallel == 1


def test_parse_missing_score_is_none():
    score = unixbench_report.parse_log("wrapper crashed before Run\n")
    assert score.index_score is None
    assert score.tests == {}


def test_parse_stops_at_next_category():
    text = SAMPLE + """
2D Graphics Benchmarks Index Values             BASELINE       RESULT    INDEX
2D Graphics: rendering - fills and strokes      100.0        200.0      2.0
2D Graphics Benchmarks Index Score                                       2.0
"""
    score = unixbench_report.parse_log(text)
    assert score.index_score == 1588.1
    assert "2D Graphics: rendering - fills and strokes" not in score.tests


def test_collect_and_render(tmp_path):
    runs = tmp_path / "runs"
    cell = runs / "2026" / "perf-1-smoke"
    cell.mkdir(parents=True)
    (cell / "result.json").write_text(
        json.dumps({"cell_id": "perf-1-smoke", "workload": "unixbench", "verdict": "pass"})
    )
    (cell / "cell.json").write_text(
        json.dumps(
            {
                "profile": {
                    "policy": "/mnt/host/kernel/linux/.github/ci/policies/allow.lua",
                    "lsm": "capability,lua",
                    "nodebug": True,
                }
            }
        )
    )
    (cell / "unixbench.log").write_text(SAMPLE)

    cells = unixbench_report.collect(runs)
    assert len(cells) == 1
    assert cells[0].cell_id == "perf-1-smoke"
    assert cells[0].score.index_score == 1588.1
    assert unixbench_report.medians(cells) == {"allow": 1588.1}

    markdown = unixbench_report.render_markdown(cells)
    assert "| perf-1-smoke | allow |" in markdown
    assert "1588.1" in markdown
    assert "Report-only" in markdown


def test_collect_ignores_non_unixbench_cells(tmp_path):
    cell = tmp_path / "runs" / "smoke-cell"
    cell.mkdir(parents=True)
    (cell / "result.json").write_text(json.dumps({"workload": "smoke", "verdict": "pass"}))
    (cell / "unixbench.log").write_text(SAMPLE)
    assert unixbench_report.collect(tmp_path / "runs") == []


def test_render_empty_report():
    assert "_No UnixBench cells found._" in unixbench_report.render_markdown([])
