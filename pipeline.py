"""Multi-agent pipeline: investigator -> RAG -> triage -> critic.

For every alert:
  1. the investigator agent collects evidence with its read-only tools,
  2. RAG finds the most relevant sections of the company playbooks,
  3. the triage agent decides, using the alert, the evidence and the playbooks,
  4. the critic agent reviews the decision; if it disagrees, fail-safe rules apply
     (keep the more severe assessment, send to a human),
  5. the prompt-injection guardrail (plain code) makes sure a manipulated alert
     can never be auto-closed,
  6. everything (decisions + every tool call) is written to an audit log.

Run:  python pipeline.py          (all alerts)
      python pipeline.py A-006    (one or more alerts)
"""

import json
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv
from google import genai
from pydantic import ValidationError

from critic import reconcile, review
from guardrails import enforce, scan_alert
from investigator import investigate
from rag import format_for_prompt, retrieve
from triage import ALERTS_FILE, SECONDS_BETWEEN_CALLS, triage

load_dotenv()

AUDIT_LOG = Path("results_pipeline.jsonl")


def process(client: genai.Client, alert: dict, verbose: bool = True) -> dict:
    flags = scan_alert(alert)  # code check, runs before any model sees the alert
    if flags and verbose:
        print(f"   !! possible prompt injection: {', '.join(flags)}")

    findings = investigate(client, alert, verbose=verbose)

    query = f"{alert['title']}. {alert['details']}\n{findings['summary']}"
    chunks = retrieve(client, query, k=3)
    playbooks = format_for_prompt(chunks)
    if verbose:
        print(f"   playbooks: {', '.join(c['id'] for c in chunks)}")

    decision = triage(client, alert, evidence=findings["summary"], playbooks=playbooks)
    critique = review(client, alert, findings["summary"], playbooks, decision)
    after_critic, status = reconcile(decision, critique)
    final, guard_changed = enforce(after_critic, flags)

    return {
        "id": alert["id"],
        "result": final.model_dump(mode="json"),
        "status": status,
        "first_decision": decision.model_dump(mode="json"),
        "after_critic": after_critic.model_dump(mode="json"),
        "critic": critique.model_dump(mode="json"),
        "guardrail": {"flags": flags, "changed_decision": guard_changed},
        "playbooks": [{"id": c["id"], "score": c["score"]} for c in chunks],
        "evidence": findings["summary"],
        "tool_calls": findings["trace"],
        "label": alert.get("label"),
    }


def main() -> None:
    if not os.getenv("GEMINI_API_KEY"):
        sys.exit("GEMINI_API_KEY not found. Copy .env.example to .env and put your key in it.")

    client = genai.Client()
    alerts = json.loads(ALERTS_FILE.read_text(encoding="utf-8"))
    if len(sys.argv) > 1:
        alerts = [a for a in alerts if a["id"] in sys.argv[1:]]

    with AUDIT_LOG.open("w", encoding="utf-8") as log:
        for i, alert in enumerate(alerts):
            print(f"\n{alert['id']} | {alert['title']}")
            try:
                record = process(client, alert)
            except ValidationError:
                print("   an agent's output did not match the schema -> rejected, needs a human")
                continue
            except Exception as error:
                print(f"   API error -> {error}")
                continue

            r = record["result"]
            print(
                f"   => {r['severity']} | real attack: {r['is_true_positive']} | "
                f"human review: {r['needs_human_review']} | critic: {record['status']}"
            )
            if record["status"] == "disputed":
                for issue in record["critic"]["issues"]:
                    print(f"      critic: {issue}")
            if record["guardrail"]["changed_decision"]:
                print("      guardrail: manipulated alert cannot be downgraded; raised to high + human review")
            log.write(json.dumps(record, ensure_ascii=False) + "\n")

            if i < len(alerts) - 1:
                time.sleep(SECONDS_BETWEEN_CALLS)

    print(f"\nAudit log saved to {AUDIT_LOG}")


if __name__ == "__main__":
    main()
