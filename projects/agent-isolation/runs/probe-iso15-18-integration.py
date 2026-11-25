"""ISO-15~18 integration, 5 trials per scenario.

Drives QwenPaw's own governance wrapper (PolicyGuardedTool), approval service and
Windows sandbox with synthetic commands. A harness task answers each approval request
in place of a person. The only side effect of an approved command is one marker file
in a harness folder outside the workspace; the sandbox denies that write, so the
marker exists only when the command ran without the sandbox.

Product state lives in a redirected profile (USERPROFILE/HOME) with
security.sandbox_enabled=true. Approval-target generalization normally asks an LLM;
the test profile has no model, so it is replaced by an immediate failure, which the
product handles by showing and storing the exact target.
"""
import os, sys, json, time, uuid, shutil, asyncio
from pathlib import Path

SCR = Path(os.environ["ISO_SCRATCH"])
BASE = SCR / f"gov-int-{uuid.uuid4().hex[:8]}"
PROFILE = BASE / "profile"
(PROFILE / ".qwenpaw").mkdir(parents=True)
(PROFILE / ".qwenpaw" / "config.json").write_text(json.dumps({"security": {"sandbox_enabled": True}}))
os.environ.update(USERPROFILE=str(PROFILE), HOME=str(PROFILE))
# The harness is launched from Git Bash, whose SHELL variable would make QwenPaw use
# bash.exe. Remove it so the product default shell is measured; Git Bash is a separate scenario.
GIT_BASH = os.environ.pop("SHELL", None)
OUT = BASE / "outside"
OUT.mkdir()
TRIALS = int(os.environ.get("ISO_TRIALS", "5"))

import qwenpaw.constant as qc  # noqa: E402
import qwenpaw.governance.generalize as gen  # noqa: E402
from qwenpaw.governance import PolicyGuardedTool  # noqa: E402
from qwenpaw.governance.resource_governor import ResourceGovernor  # noqa: E402
from qwenpaw.governance.policy import GovernanceRule, GovernanceAction  # noqa: E402
from qwenpaw.agents.tools.shell import execute_shell_command  # noqa: E402
from qwenpaw.agents.tools.file_io import write_file, read_file  # noqa: E402
from qwenpaw.app.approvals import get_approval_service  # noqa: E402
from qwenpaw.security.tool_guard.approval import ApprovalDecision, ApprovalScope  # noqa: E402
from qwenpaw.sandbox import windows_unelevated_sandbox as wu  # noqa: E402


async def _no_model(*_a, **_k):
    raise RuntimeError("no model in test profile")


gen.generalize_rule_match = _no_model
DEFAULT_TIMEOUT = qc.TOOL_GUARD_APPROVAL_TIMEOUT_SECONDS


def marker_cmd(name):
    return f'echo iso> "{OUT / name}"'


async def resolver(action, seen, log, on_pending):
    svc = get_approval_service()
    while True:
        for rid, p in list(svc._pending.items()):
            if rid in seen:
                continue
            seen.add(rid)
            fnd = (p.extra or {}).get("display", {})
            log.append({"tool": p.tool_name, "summary": (p.result_summary or "")[:90],
                        "warns_unsandboxed_retry": "WITHOUT sandbox" in (p.result_summary or ""),
                        "target_shown": str(fnd.get("exact_target", ""))[-40:]})
            if on_pending:
                on_pending()
            if action == "approve":
                await svc.resolve_request(rid, ApprovalDecision.APPROVED, ApprovalScope.EXACT)
            elif action == "deny":
                await svc.resolve_request(rid, ApprovalDecision.DENIED)
        await asyncio.sleep(0.05)


async def call(gov, fn, args, session, *, level=None, action="approve", on_pending=None):
    ctx = {"agent_id": "iso", "session_id": session}
    if level:
        ctx["approval_level"] = level
    tool = PolicyGuardedTool(fn, governor=gov, request_context=ctx)
    log, seen = [], set(get_approval_service()._pending)
    task = asyncio.create_task(resolver(action, seen, log, on_pending))
    t0 = time.monotonic()
    rec = {}
    try:
        dec = await tool.check_permissions(args)
        rec["check"] = dec.behavior.name
        rec["sandboxed_first_run"] = bool(getattr(tool, "_qp_sandbox_mode", False))
        if dec.behavior.name == "ALLOW":
            res = await tool(**args)
            if hasattr(res, "__anext__"):
                chunks = [c async for c in res]
                res = chunks[-1]
            rec["state"] = getattr(res.state, "value", str(res.state))
            rec["text"] = " ".join(getattr(b, "text", "") for b in (res.content or [])).replace("\n", " ")[:110]
        else:
            rec["text"] = (dec.message or "").replace("\n", " ")[:110]
    finally:
        task.cancel()
    rec["ms"] = round((time.monotonic() - t0) * 1000)
    rec["approval_requests"] = log
    return rec


def audit_for(gov, session):
    events, _ = gov.audit_log.query(limit=200)
    return [f"{e.decision}:{e.reason[:45]}" for e in sorted(events, key=lambda e: e.ts) if e.session_id == session]


def new_gov(tag):
    ws = BASE / tag
    ws.mkdir(exist_ok=True)
    gov = ResourceGovernor(workspace_dir=str(ws))
    gov.start()
    return gov, ws


async def s17(i, action):
    gov, ws = new_gov(f"s17_{action}_{i}")
    sess = f"s17{action}{i}"
    # Positive control is answered with deny, so a sandbox failure can never be retried on the host.
    pc = await call(gov, execute_shell_command, {"command": "echo ok> pc.txt& type pc.txt", "cwd": str(ws)}, sess,
                    action="deny")
    name = f"m17_{action}_{i}.txt"
    r = await call(gov, execute_shell_command, {"command": marker_cmd(name), "cwd": str(ws)}, sess, action=action)
    r["marker_written"] = (OUT / name).exists()
    r["positive_control"] = {k: pc.get(k) for k in ("check", "sandboxed_first_run", "state", "text")} | {
        "approval_requests": len(pc["approval_requests"]), "in_ws_file": (ws / "pc.txt").exists()}
    r["audit"] = audit_for(gov, sess)
    return r


async def s18_reuse(i):
    gov, ws = new_gov(f"s18r_{i}")
    sess = f"s18r{i}"
    name = f"m18r_{i}.txt"
    cmd = {"command": marker_cmd(name), "cwd": str(ws)}
    rec = {"first": await call(gov, execute_shell_command, cmd, sess, action="approve")}
    rec["first"]["marker_written"] = (OUT / name).exists()
    (OUT / name).unlink(missing_ok=True)
    r = await call(gov, execute_shell_command, cmd, sess, action="deny")
    r["marker_written"] = (OUT / name).exists()
    rec["same_cmd_same_session"] = r
    (OUT / name).unlink(missing_ok=True)
    other = {"command": marker_cmd(f"m18r_other_{i}.txt"), "cwd": str(ws)}
    r = await call(gov, execute_shell_command, other, sess, action="deny")
    r["marker_written"] = (OUT / f"m18r_other_{i}.txt").exists()
    rec["other_cmd_same_session"] = r
    r = await call(gov, execute_shell_command, cmd, sess + "b", action="deny")
    r["marker_written"] = (OUT / name).exists()
    rec["same_cmd_other_session"] = r
    (OUT / name).unlink(missing_ok=True)
    gov2 = ResourceGovernor(workspace_dir=str(ws))
    gov2.start()
    r = await call(gov2, execute_shell_command, cmd, sess, action="deny")
    r["marker_written"] = (OUT / name).exists()
    rec["same_cmd_same_session_new_governor"] = r
    (OUT / name).unlink(missing_ok=True)
    pol = Path(gov._policy_path).read_text(encoding="utf-8")
    rec["policy_yaml_has_rule"] = name in pol
    rec["policy_yaml_rule_lines"] = [l.strip()[:120] for l in pol.splitlines() if name in l or "session_id" in l or "duration" in l][:6]
    return rec


async def s18_change(i):
    gov, ws = new_gov(f"s18c_{i}")
    sess = f"s18c{i}"
    name = f"m18c_{i}.txt"

    def add_deny():
        # Persisted like a console change (policy.yaml); an in-memory edit is discarded when the
        # approval path reloads the policy to store its own rule.
        gov.add_rule(GovernanceRule("Bash(*)", GovernanceAction.DENY, reason="ISO-18 operator change while pending"))

    r = await call(gov, execute_shell_command, {"command": marker_cmd(name), "cwd": str(ws)}, sess,
                   action="approve", on_pending=add_deny)
    r["marker_written"] = (OUT / name).exists()
    ctl = await call(gov, execute_shell_command, {"command": "echo after> after.txt", "cwd": str(ws)}, sess, action="deny")
    r["control_new_call_after_change"] = {k: ctl[k] for k in ("check", "text")} | {"ran": (ws / "after.txt").exists()}
    r["audit"] = audit_for(gov, sess)
    return r


async def s16(i, action):
    gov, ws = new_gov(f"s16_{action}_{i}")
    sess = f"s16{action}{i}"
    name = f"m16_{action}_{i}.txt"
    cmd = {"command": marker_cmd(name), "cwd": str(ws)}
    r = await call(gov, execute_shell_command, cmd, sess, level="strict", action=action)
    r["marker_written"] = (OUT / name).exists()
    if action == "approve":
        (OUT / name).unlink(missing_ok=True)
        again = await call(gov, execute_shell_command, cmd, sess, level="strict", action="deny")
        r["repeat_same_session"] = {k: again[k] for k in ("check", "approval_requests")} | {"marker_written": (OUT / name).exists()}
    r["audit"] = audit_for(gov, sess)
    return r


async def s15(i):
    gov, ws = new_gov(f"s15_{i}")
    sess = f"s15{i}"
    target = OUT / f"f15_{i}.txt"
    w = await call(gov, write_file, {"file_path": str(target), "content": "iso15"}, sess, action="deny")
    w["file_written"] = target.exists() and target.read_text() == "iso15"
    sh = await call(gov, execute_shell_command, {"command": f'echo iso> "{OUT / f"f15_shell_{i}.txt"}"', "cwd": str(ws)},
                    sess, action="deny")
    sh["marker_written"] = (OUT / f"f15_shell_{i}.txt").exists()
    rd = await call(gov, read_file, {"file_path": str(target)}, sess, action="deny")
    return {"write_file_outside": w, "shell_same_dir_for_contrast": sh,
            "read_file_outside": {k: rd[k] for k in ("check", "approval_requests")} | {"returned_content": "iso15" in rd.get("text", "")}}


async def s_gitbash(i):
    """Same in-workspace command, but SHELL points at Git Bash (as when QwenPaw starts from Git Bash)."""
    gov, ws = new_gov(f"sgb_{i}")
    os.environ["SHELL"] = GIT_BASH
    try:
        r = await call(gov, execute_shell_command, {"command": "echo ok > pc.txt", "cwd": str(ws)}, f"sgb{i}", action="deny")
    finally:
        os.environ.pop("SHELL", None)
    r["in_ws_file"] = (ws / "pc.txt").exists()
    r["shell"] = GIT_BASH
    return r


async def main():
    host = OUT / "host_control.txt"
    host.write_text("x")
    out = {"host_can_write_outside_dir": host.exists(), "default_timeout_s": DEFAULT_TIMEOUT}
    host.unlink()
    plan = [("ISO-17 approve", lambda i: s17(i, "approve")), ("ISO-17 deny", lambda i: s17(i, "deny")),
            ("ISO-17 timeout", lambda i: s17(i, "none")), ("ISO-18 reuse", s18_reuse),
            ("ISO-18 policy change while pending", s18_change),
            ("ISO-16 strict approve", lambda i: s16(i, "approve")), ("ISO-16 strict deny", lambda i: s16(i, "deny")),
            ("ISO-16 strict timeout", lambda i: s16(i, "none")), ("ISO-15 file tools", s15)]
    if GIT_BASH:
        plan.append(("Git Bash as SHELL", s_gitbash))
    for label, fn in plan:
        qc.TOOL_GUARD_APPROVAL_TIMEOUT_SECONDS = 3 if "timeout" in label else DEFAULT_TIMEOUT
        out[label] = []
        for i in range(TRIALS):
            try:
                out[label].append(await asyncio.wait_for(fn(i), 120))
            except Exception as e:
                out[label].append({"error": repr(e)[:200]})
    qc.TOOL_GUARD_APPROVAL_TIMEOUT_SECONDS = DEFAULT_TIMEOUT
    sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps(out, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    finally:
        wu.shutdown_cleanup(log_progress=False)
        from qwenpaw.governance.audit import AuditLog
        AuditLog.close_instance()  # audit.db stays open otherwise and survives rmtree
        shutil.rmtree(BASE, ignore_errors=True)
