"""Per-trial counts for the named object and pipe measurements (plan-token-backends.md N, Q).

Reads local/2026-11-26/<config>-nq.json and prints, for each measured value, how often each result
occurred over the trials, one column per configuration. SIDs inside SDDL strings are replaced by their
kind (user, user_logon, other_logon, codex_account, qwenpaw_account, capability), so the output holds no
SID of the real PC. Usage: python probe-named-objects-summary.py [--sddl]
"""
import os
import re
import sys
import json
from collections import Counter, OrderedDict
from pathlib import Path

os.environ.setdefault("ISO_DATE", "2026-11-26")
sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import LOCAL, CONFIGS  # noqa: E402

SETUP = json.loads((LOCAL / "setup.json").read_text(encoding="utf-8"))
try:
    QA = json.loads((LOCAL / "qwenpaw-admin-accounts.json").read_text(encoding="utf-8"))
except OSError:
    QA = {}
CODEX = {v for v in SETUP["codex_accounts"].values() if v}
QCAPS = {v.get("cap_sid") for v in QA.values() if v.get("cap_sid")}


def sid_kind(s):
    if s == SETUP["user_sid"]:
        return "user"
    if s == SETUP["logon_sid"]:
        return "user_logon"
    if s.startswith("S-1-5-5-"):
        return "other_logon"
    if s in CODEX:
        return "codex_account"
    if s in QA:
        return "qwenpaw_account"
    if s in QCAPS:
        return "qwenpaw_capability"
    return "other_sid"


def clean(v):
    if isinstance(v, str):
        v = re.sub(r"S-1-5-(?:21|5)-[0-9-]+", lambda m: sid_kind(m.group(0)), v)
        v = re.sub(r"iso-nq-[a-z]+-[0-9a-f]{8}", "iso-nq-*", v)
        v = re.sub(r"\b(?:HH|S|A|B|H)-[0-9a-f]{8}\b", lambda m: m.group(0).split("-")[0] + "-marker", v)
    return v


def flat(prefix, v, out):
    if isinstance(v, dict):
        for k, x in v.items():
            flat(f"{prefix}.{k}" if prefix else k, x, out)
    else:
        out[prefix] = clean(json.dumps(v, ensure_ascii=False) if isinstance(v, list) else v)


def norm_names(d, tag):
    """Replace per-trial object names with a stable label (Local/Global + type)."""
    if not isinstance(d, dict):
        return d
    out = {}
    for k, v in d.items():
        k2 = k.replace(f"iso-nq-h-{tag}-", "").replace(f"iso-nq-a-{tag}-", "")
        out[k2] = norm_names(v, tag)
    return out


def trial_values(r):
    tag = r["tag"]
    vals = OrderedDict()
    res = (r.get("run1") or {}).get("result") or {}
    flat("N0_sandbox", res.get("N0"), vals)
    flat("N1N2_sandbox_open", norm_names(res.get("N1N2"), tag), vals)
    flat("N1N2_host_check", norm_names((r.get("host_check") or {}).get("result"), tag), vals)
    flat("Q1", res.get("Q1"), vals)
    flat("G4", res.get("G4"), vals)
    flat("N3Q2_sandbox_made", norm_names(r.get("sandbox_created"), tag), vals)
    hp = (r.get("host_precreate") or {}).get("result") or {}
    flat("N4_host_precreate", norm_names(hp.get("objects"), tag), vals)
    flat("Q3_host_pipe_first_instance", hp.get("pipe_first_instance"), vals)
    flat("Q3_host_pipe_plain", hp.get("pipe_plain"), vals)
    ho = (r.get("host_open") or {}).get("result") or {}
    flat("N3_host_open", norm_names(ho.get("objects"), tag), vals)
    flat("N3_host_section_rw", norm_names(ho.get("section_read"), tag), vals)
    flat("Q2_host_client", ho.get("pipe"), vals)
    rb = (r.get("run_b") or {}).get("result") or {}
    flat("N3_wsB_open", norm_names(rb.get("N3b"), tag), vals)
    flat("Q2_wsB_client", rb.get("Q2b"), vals)
    log = r.get("pipe_log") or []
    vals["Q2_server_got_host_data"] = any(x.get("data") == f"HH-{tag}" for x in log)
    vals["Q2_server_got_wsB_data"] = any(x.get("data") == f"B-{tag}" for x in log)
    vals["Q2_server_connections"] = len(log)
    vals["exit.run1"] = (r.get("run1") or {}).get("exit")
    vals["exit.run_b"] = (r.get("run_b") or {}).get("exit")
    vals["exit.hold"] = (r.get("hold") or {}).get("exit")
    if r.get("error"):
        vals["error"] = r["error"]
    return vals


sys.stdout.reconfigure(encoding="utf-8")
show_sddl = "--sddl" in sys.argv
cols = OrderedDict()
for cfg in CONFIGS:
    p = LOCAL / f"{cfg}-nq.json"
    if p.exists():
        d = json.loads(p.read_text(encoding="utf-8"))
        cols[cfg] = [trial_values(r) for r in d["result"]]
keys = []
for trials in cols.values():
    for v in trials:
        for k in v:
            if k not in keys:
                keys.append(k)
print("| item | " + " | ".join(cols) + " |")
print("| --- |" + " --- |" * len(cols))
for k in keys:
    if ("sddl" in k.lower()) != show_sddl and not k.endswith(".path"):
        continue
    cells = []
    for trials in cols.values():
        c = Counter(str(t.get(k, "-")) for t in trials)
        cells.append(", ".join(f"{v} ({n})" for v, n in c.most_common()))
    print(f"| {k} | " + " | ".join(cells) + " |")
