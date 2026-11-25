"""Aggregates local/2026-11-25/<config>-<group>.json into outcome counts per item (no SIDs or paths).

Usage: python probe-token-backends-summary.py <config> [<config> ...]
Prints one JSON object per config; outcome strings are normalised (error:13 and error:5 -> denied).
"""
import sys
import json
from collections import Counter, defaultdict
from pathlib import Path

LOCAL = Path(__file__).resolve().parents[1] / "local" / "2026-11-25"


def norm(v):
    if v in ("ok", "granted", "decrypted_match", "marker_found", "exists"):
        return "allowed"
    if isinstance(v, str) and v.startswith("ok:"):
        return "allowed"
    if v in ("error:5", "error:13"):
        return "denied"
    return v if isinstance(v, (str, bool, int, float, type(None))) else json.dumps(v)[:60]


def count(rows):
    return dict(Counter(rows))


def load(config, group):
    p = LOCAL / f"{config}-{group}.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def summarize(config):
    out = {}
    core = load(config, "core")
    if core:
        items = defaultdict(list)
        exits = []
        for r in core["result"]:
            exits.append(r.get("exit"))
            res = r.get("result") or {}
            for sect in ("fs", "reg"):
                for k, v in (res.get(sect) or {}).items():
                    items[k].append(norm(v))
            for k, v in (res.get("C7_dpapi") or {}).items():
                items[f"C7_{k}"].append(norm(v))
            items["P2_cmdline"].append(norm(res.get("P2_cmdline")))
            for k, v in (res.get("G5_pipe") or {}).items():
                items[f"G5_pipe_{k}"].append(norm(v))
            for pid, pv in (res.get("P1_test_process") or {}).items():
                for k, v in pv["process"].items():
                    items[f"P1_{k}"].append(norm(v))
                for k, v in (pv["token"] if isinstance(pv["token"], dict) else {}).items():
                    items[f"P1b_{k}"].append(norm(v))
            for exe, pv in (res.get("P5_product") or {}).items():
                name = "runner" if "runner" in exe else exe
                for k, v in pv["process"].items():
                    items[f"P5_{name}_{k}"].append(norm(v))
                for k, v in (pv["token"] if isinstance(pv["token"], dict) else {}).items():
                    items[f"P5_{name}_{k}"].append(norm(v))
            for cat, vs in ((res.get("R2_hku") or {}).get("by_category") or {}).items():
                items[f"R2_{cat}"].append("/".join(sorted(norm(v) for v in vs)))
            env = res.get("env") or {}
            items["E1_plain"].append(env.get("ISO_TB_PLAIN") == "plain-marker-1")
            items["E1_api_key"].append(env.get("ISO_TB_API_KEY") == "apikey-marker-2")
            tok = res.get("token") or {}
            if isinstance(tok, dict):
                items["A_restricted_count"].append(len(tok.get("restricted_sids") or []))
                items["A_integrity"].append(tok.get("integrity"))
                items["A_desktop"].append((tok.get("desktop") or "")[:20])
                items["A_hkcu_kind"].append("DEFAULT" if ".DEFAULT" in (tok.get("hkcu") or "") else "user-hive" if tok.get("hkcu") else None)
                items["A_job_flags"].append(tok.get("limit_flags"))
                items["A_ui_restrictions"].append(tok.get("ui_restrictions"))
        out["core_exits"] = count(exits)
        out["core"] = {k: count(v) for k, v in items.items()}
        p4 = [(r.get("result") or {}).get("P4_proc_list") for r in core["result"] if (r.get("result") or {}).get("P4_proc_list")]
        out["P4"] = p4[0] if p4 else None
        out["C3_pre_codex_group_ace"] = core["context"].get("c3_pre_codex_group_ace")
    for g in ("b6first", "b5", "b8b", "c5", "f1", "g4", "g", "p6", "h", "r2x", "p7", "b10", "r2qa", "r2hold",
              "prep", "uac-before", "cleanuprec", "uac-after", "r3", "nest"):
        d = load(config, g)
        if d:
            out[g] = d["result"]
    return out


if __name__ == "__main__":
    for c in sys.argv[1:]:
        print(json.dumps({c: summarize(c)}, ensure_ascii=False, default=str))
