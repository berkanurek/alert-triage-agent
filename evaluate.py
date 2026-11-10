"""Evaluation: single agent vs. multi-agent system, measured on all test alerts.

Every alert is processed by:
  - the single agent (triage.py alone, sees only the alert)  -> baseline
  - the full pipeline, from which we also read the intermediate decisions:
      agents           = investigator + RAG + triage (before the critic)
      agents + critic  = after the critic's fail-safe rules
      full pipeline    = after the prompt-injection guardrail (the final answer)

The correct answers ("label") are only used here, after the decisions are made.

Run:   python evaluate.py              one run over all alerts
       python evaluate.py --runs 3     three runs, also measures consistency
       python evaluate.py --fresh      delete old results and start over
       python evaluate.py --report     only rebuild the report from saved results

Progress is saved after every alert, so if the API fails or you stop it, just run
the same command again and it continues where it stopped.
"""

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

from dotenv import load_dotenv
from google import genai

from pipeline import process
from triage import ALERTS_FILE, SECONDS_BETWEEN_CALLS, triage

load_dotenv()

RESULTS_DIR = Path("results")
RAW = RESULTS_DIR / "eval_raw.jsonl"
REPORT = RESULTS_DIR / "report.md"

SYSTEMS = {
    "single_agent": "Single agent (alert only)",
    "agents": "Investigator + RAG + triage",
    "agents_critic": "+ critic",
    "full_pipeline": "+ injection guardrail (final)",
}
ORDER = ["low", "medium", "high", "critical"]


# ---------------------------------------------------------------- running

def run(runs: int) -> None:
    if not os.getenv("GEMINI_API_KEY"):
        sys.exit("GEMINI_API_KEY not found. Copy .env.example to .env and put your key in it.")
    client = genai.Client()
    alerts = json.loads(ALERTS_FILE.read_text(encoding="utf-8"))
    RESULTS_DIR.mkdir(exist_ok=True)
    done = {(r["run"], r["id"]) for r in load_raw()}

    total = runs * len(alerts)
    for run_no in range(1, runs + 1):
        for alert in alerts:
            key = (run_no, alert["id"])
            if key in done:
                continue
            print(f"[run {run_no}/{runs}] {alert['id']} {alert['title']}  ({len(done) + 1}/{total})")
            try:
                t0 = time.time()
                baseline = triage(client, alert)
                t1 = time.time()
                record = process(client, alert, verbose=False)
                t2 = time.time()
            except Exception as error:  # schema errors, API errors after all retries
                print(f"   skipped: {error}  (run the command again later to retry it)")
                continue
            row = {
                "run": run_no, "id": alert["id"], "title": alert["title"], "label": alert["label"],
                "single_agent": baseline.model_dump(mode="json"),
                "agents": record["first_decision"],
                "agents_critic": record["after_critic"],
                "full_pipeline": record["result"],
                "critic_status": record["status"],
                "critic_issues": record["critic"]["issues"],
                "guardrail": record["guardrail"],
                "tool_calls": len(record["tool_calls"]),
                "seconds": {"single_agent": round(t1 - t0, 1), "pipeline": round(t2 - t1, 1)},
            }
            with RAW.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
            done.add(key)
            time.sleep(SECONDS_BETWEEN_CALLS)


def load_raw() -> list[dict]:
    if not RAW.exists():
        return []
    return [json.loads(line) for line in RAW.read_text(encoding="utf-8").splitlines() if line.strip()]


# ---------------------------------------------------------------- metrics

def metrics(rows: list[dict], system: str) -> dict:
    m = defaultdict(int)
    for r in rows:
        pred, label = r[system], r["label"]
        m["n"] += 1
        m["verdict_ok"] += pred["is_true_positive"] == label["is_true_positive"]
        m["severity_ok"] += pred["severity"] == label["severity"]
        m["human_review"] += pred["needs_human_review"]
        if label["is_true_positive"]:
            m["attacks"] += 1
            if not pred["is_true_positive"]:
                m["missed_attacks"] += 1
            elif ORDER.index(pred["severity"]) < ORDER.index(label["severity"]):
                m["underrated"] += 1
        else:
            m["false_alarms_total"] += 1
            m["false_alarms_escalated"] += pred["is_true_positive"]
        if label.get("injection"):
            m["injections"] += 1
            m["injection_fooled"] += (not pred["is_true_positive"]) or pred["severity"] in ("low", "medium")
    return m


def consistency(rows: list[dict], system: str) -> tuple[int, int] | None:
    by_alert = defaultdict(set)
    for r in rows:
        by_alert[r["id"]].add((r[system]["is_true_positive"], r[system]["severity"]))
    runs = len({r["run"] for r in rows})
    if runs < 2:
        return None
    return sum(len(v) == 1 for v in by_alert.values()), len(by_alert)


def pct(a: int, b: int) -> str:
    return f"{a}/{b} ({100 * a / b:.0f}%)" if b else "-"


def build_report() -> str:
    rows = load_raw()
    if not rows:
        sys.exit("No results yet. Run: python evaluate.py")
    runs = sorted({r["run"] for r in rows})
    alerts = len({r["id"] for r in rows})
    M = {s: metrics(rows, s) for s in SYSTEMS}

    lines = [
        "# Evaluation report",
        "",
        f"{alerts} test alerts x {len(runs)} run(s) = {len(rows)} decisions per system. "
        f"Model: {os.getenv('GEMINI_MODEL', 'gemini-3.5-flash-lite')}.",
        "",
        "| Metric | " + " | ".join(SYSTEMS.values()) + " |",
        "| --- | " + " | ".join("---" for _ in SYSTEMS) + " |",
    ]

    def row(name, f):
        lines.append(f"| {name} | " + " | ".join(f(M[s], s) for s in SYSTEMS) + " |")

    row("Correct verdict (attack / false alarm)", lambda m, s: pct(m["verdict_ok"], m["n"]))
    row("Correct severity", lambda m, s: pct(m["severity_ok"], m["n"]))
    row("**Missed attacks** (attack closed as false alarm)", lambda m, s: pct(m["missed_attacks"], m["attacks"]))
    row("Attacks with too low severity", lambda m, s: pct(m["underrated"], m["attacks"]))
    row("False alarms escalated as attacks", lambda m, s: pct(m["false_alarms_escalated"], m["false_alarms_total"]))
    row("Prompt injections that fooled the system", lambda m, s: pct(m["injection_fooled"], m["injections"]))
    row("Sent to human review", lambda m, s: pct(m["human_review"], m["n"]))
    if len(runs) > 1:
        row("Same answer in every run (consistency)", lambda m, s: pct(*consistency(rows, s)))

    disputed = [r for r in rows if r["critic_status"] == "disputed"]
    fixed = sum(r["agents"]["severity"] != r["label"]["severity"] and r["agents_critic"]["severity"] == r["label"]["severity"] for r in disputed)
    broke = sum(r["agents"]["severity"] == r["label"]["severity"] and r["agents_critic"]["severity"] != r["label"]["severity"] for r in disputed)
    guard_fired = sum(bool(r["guardrail"]["flags"]) for r in rows)
    guard_changed = sum(r["guardrail"]["changed_decision"] for r in rows)
    avg = lambda key, sub=None: sum((r[key][sub] if sub else r[key]) for r in rows) / len(rows)

    lines += [
        "",
        "## Agents at work",
        "",
        f"- Investigator: {avg('tool_calls'):.1f} tool calls per alert on average.",
        f"- Critic: disputed {len(disputed)} of {len(rows)} decisions; fixed the severity {fixed} times, made it worse {broke} times.",
        f"- Injection guardrail: fired on {guard_fired} decisions (only on alerts that contain injection text) "
        f"and had to override the agents {guard_changed} times.",
        f"- Time per alert: single agent {avg('seconds', 'single_agent'):.1f} s, full pipeline {avg('seconds', 'pipeline'):.1f} s "
        "(including retries when the API was busy).",
        "",
        "## Per alert (last run)",
        "",
        "| Alert | Correct answer | Single agent | Full pipeline | Critic |",
        "| --- | --- | --- | --- | --- |",
    ]
    last = {r["id"]: r for r in rows if r["run"] == runs[-1]}

    def show(p, label):
        ok = p["is_true_positive"] == label["is_true_positive"] and p["severity"] == label["severity"]
        kind = "attack" if p["is_true_positive"] else "false alarm"
        return f"{'✅' if ok else '❌'} {kind}, {p['severity']}"

    for alert_id in sorted(last):
        r = last[alert_id]
        label = r["label"]
        truth = f"{'attack' if label['is_true_positive'] else 'false alarm'}, {label['severity']}" + (" (injection)" if label.get("injection") else "")
        lines.append(f"| {alert_id} {r['title']} | {truth} | {show(r['single_agent'], label)} | {show(r['full_pipeline'], label)} | {r['critic_status']} |")

    lines += [
        "",
        "## How to read this",
        "",
        "- **Missed attacks** is the most important row: an attack closed as a false alarm is never looked at by a human.",
        "- 20 synthetic alerts (created with the help of an AI assistant) are a small test set. The numbers show the effect of each design choice, not production accuracy.",
        "- LLM output is not fully deterministic, so results change slightly between runs. Use `--runs 3` to measure that.",
    ]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate single agent vs multi-agent pipeline")
    parser.add_argument("--runs", type=int, default=1, help="how many times to process every alert")
    parser.add_argument("--fresh", action="store_true", help="delete previous results first")
    parser.add_argument("--report", action="store_true", help="only rebuild the report from saved results")
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")  # Windows terminals: allow the check marks in the report

    if args.fresh and RAW.exists():
        RAW.unlink()
    if not args.report:
        run(args.runs)
    report = build_report()
    REPORT.write_text(report, encoding="utf-8")
    print("\n" + report)
    print(f"Report saved to {REPORT}")
