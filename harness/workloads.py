"""Concrete workloads driven by the cell runner.

Each workload is a callable matching the WorkloadFn signature
(harness.cell_runner.WorkloadFn). Workloads should:
- run their guest-side commands via ssh.run() with a generous timeout,
- record every guest-side command via ctx.record_command() so the bundle's
  commands.sh can replay the cell without parsing per-workload logs,
- write the workload's stdout into <artifact_dir>/workload-<name>.log,
- return a WorkloadResult; never raise on a guest-side non-zero exit
  (those are recorded but should not be classified as harness-error).

Workloads do NOT capture dmesg or snapshot stats -- that's the cell runner's
job, both because it must happen for every workload and because both
snapshots must be taken on the host side after the workload returns.
"""

from __future__ import annotations

import shlex
import shutil
from dataclasses import dataclass
from pathlib import Path

from . import ssh
from .celltypes import CellContext, WorkloadFn, WorkloadResult

# Mount point inside the guest for the harness's host-side artifact share
# (virtio-9p tag "host_share"). Workloads write logs that the harness can
# scrape post-run without an extra scp round-trip.
GUEST_HOST_SHARE = "/mnt/host"

# Workspace-relative paths exposed via the same 9p share.
LUA_LSM_TOOLS_DIR = "lua-lsm-tools"
LUA_LSM_TOOLS_TOOLS = f"{LUA_LSM_TOOLS_DIR}/tools"
LUA_LSM_TOOLS_EXAMPLES = f"{LUA_LSM_TOOLS_DIR}/examples"
LUA_LSM_TESTSUITE_DIR = "lua-lsm-testsuite"
LUA_LSM_TESTSUITE_FIXTURES = f"{LUA_LSM_TESTSUITE_DIR}/fixtures"
UNIXBENCH_DIR = "unixbench"

# securityfs interfaces the kernel exposes for lua-lsm.
SECURITYFS_LUA = "/sys/kernel/security/lua"
SECURITYFS_REGISTER = f"{SECURITYFS_LUA}/register"
SECURITYFS_UNREGISTER = f"{SECURITYFS_LUA}/unregister"

# Default smoke policy: hello.lua is the canonical example, registered as
# "hello" by the file's `return { name = 'hello' }`.
DEFAULT_SMOKE_POLICY_FILE = "hello.lua"
DEFAULT_SMOKE_POLICY_NAME = "hello"
DISABLED_POLICY_SENTINEL = "none"


# ---------------------------------------------------------------------------
# Workload registry: the single source of truth for everything the harness
# needs to know about a workload beyond the function itself. Adding a
# workload means adding one SPECS entry here (plus a config that selects it);
# guest fixture requirements, policy resolution, share-dir requirements, and
# the CLI's --workload choices all derive from this table.


@dataclass(frozen=True)
class WorkloadSpec:
    name: str
    fn: WorkloadFn
    # Guest paths whose presence the cell runner verifies before invoking the
    # workload. Empty means "no fixture required".
    guest_fixtures: tuple[str, ...] = ()
    # Workspace-relative directory the workload's policy files live under,
    # guest-side (`/mnt/host/<policy_guest_dir>`) and host-side
    # (`<share_dir>/<policy_guest_dir>`).
    policy_guest_dir: str = LUA_LSM_TOOLS_EXAMPLES
    # Policy used when the profile / CLI did not name one.
    default_policy: str = DEFAULT_SMOKE_POLICY_FILE
    # True when every fixture the workload needs lives inside this
    # repository's checkout, so SHARE_DIR only has to contain
    # lua-lsm-testsuite/ (see matrix.required_share_entries).
    self_contained: bool = False


SPECS: dict[str, WorkloadSpec] = {}  # populated after the workload functions below


def spec_for(name: str) -> WorkloadSpec:
    if name not in SPECS:
        raise KeyError(f"unknown workload: {name}; known: {sorted(SPECS)}")
    return SPECS[name]


def normalize_policy_filename(name: str) -> str:
    """Short names (no .lua suffix) resolve to the on-disk filename."""
    return name if name.endswith(".lua") else f"{name}.lua"


def policy_guest_path(workload_name: str, profile_policy: str | None) -> str:
    """Absolute guest-side path of the policy file the workload registers.

    Absolute paths (a caller passing a full path through the share) pass
    through unchanged. Unknown workload names keep the historical
    lua-lsm-tools/examples resolution so the eventual `by_name` lookup is
    what reports the unknown name, not this helper.
    """
    spec = SPECS.get(workload_name)
    name = profile_policy or (spec.default_policy if spec else DEFAULT_SMOKE_POLICY_FILE)
    if "/" in name:
        return name  # caller passed an absolute path through the share
    guest_dir = spec.policy_guest_dir if spec else LUA_LSM_TOOLS_EXAMPLES
    return f"{GUEST_HOST_SHARE}/{guest_dir}/{normalize_policy_filename(name)}"


def policy_host_path(
    share_dir: Path | None, workload_name: str, policy_name: str | None
) -> tuple[Path, ...]:
    """Host-side policy path(s) a cell will register, relative to share_dir.

    Returns a tuple of paths suitable for BundleSources.policies. When
    share_dir is None, returns an empty tuple -- the runner can still
    proceed (the bundle just won't carry a policy copy). The default policy
    is workload-specific so the bundle always carries the policy the cell
    actually exercised. Passing the sentinel policy name "none" also yields
    an empty tuple: the cell runs without registering any policy (used by
    the no-policy UnixBench compare configs).
    """
    if share_dir is None:
        return ()
    spec = SPECS.get(workload_name)
    name = policy_name or (spec.default_policy if spec else None)
    if _policy_disabled(name):
        return ()
    guest_dir = spec.policy_guest_dir if spec else LUA_LSM_TOOLS_EXAMPLES
    return (Path(share_dir) / guest_dir / normalize_policy_filename(name),)


def _record(
    result: WorkloadResult, ctx: CellContext, log_name: str, cmd: str, ssh_result: ssh.SshResult
) -> None:
    """Append one (command, result) pair to the workload log + commands.sh."""
    ctx.record_command(cmd)
    entry = (
        f"# --- $ {cmd}\n"
        f"# returncode={ssh_result.returncode}\n"
        f"# --- stdout ---\n{ssh_result.stdout}\n"
        f"# --- stderr ---\n{ssh_result.stderr}\n"
    )
    with open(ctx.artifact_dir / log_name, "a", encoding="utf-8") as fh:
        fh.write(entry)
    result.returncode = ssh_result.returncode
    if ssh_result.returncode != 0 and not result.notes:
        result.notes = f"{result.name} step exited {ssh_result.returncode}"


def _policy_disabled(profile_policy: str | None) -> bool:
    return (
        isinstance(profile_policy, str)
        and profile_policy.strip().lower() == DISABLED_POLICY_SENTINEL
    )


def _policy_file_in_guest(profile_policy: str | None) -> str:
    """Return the absolute guest-side path of the policy file to register.

    Delegates to policy_guest_path for the smoke workload (whose
    lua-lsm-tools/examples directory and hello.lua default are the
    historical resolution this helper encoded). Kept as a named wrapper
    because its semantics -- policy name in, guest path out -- read better
    at the smoke/unixbench call sites than the workload-name-aware helper.
    """
    return policy_guest_path("smoke", profile_policy)


def _policy_short_name(profile_policy: str | None) -> str:
    """Short policy name (the `name = '...'` field) for unregister."""
    name = profile_policy or DEFAULT_SMOKE_POLICY_FILE
    base = name.rsplit("/", 1)[-1]
    if base.endswith(".lua"):
        base = base[: -len(".lua")]
    return base


def smoke(target: ssh.SshTarget, ctx: CellContext) -> WorkloadResult:
    """Light boot smoke test: register a Lua policy, idle briefly, unregister.

    Verifies that lua-lsm is loaded, that an example policy can be installed
    via the securityfs interface, and that unregister succeeds without
    leaking. The cell-level classifier picks up any kernel splat dmesg may
    surface during the round-trip.
    """
    out = WorkloadResult(name="smoke")
    policy_path = _policy_file_in_guest(ctx.profile.get("policy"))
    policy_name = _policy_short_name(ctx.profile.get("policy"))

    cmd_check = (
        f"set -euo pipefail; "
        f"test -d {shlex.quote(SECURITYFS_LUA)} && "
        f"test -r {shlex.quote(policy_path)} && "
        f"echo 'lua-lsm present'"
    )
    r = ssh.run(target, cmd_check, timeout_s=30.0)
    _record(out, ctx, "workload-smoke.log", cmd_check, r)
    if r.returncode != 0:
        return out

    cmd_register = f"cat {shlex.quote(policy_path)} > {shlex.quote(SECURITYFS_REGISTER)}"
    r = ssh.run(target, cmd_register, timeout_s=30.0)
    _record(out, ctx, "workload-smoke.log", cmd_register, r)
    if r.returncode != 0:
        return out

    cmd_idle = "sleep 2; cat /sys/kernel/security/lua/stats || true"
    r = ssh.run(target, cmd_idle, timeout_s=30.0)
    _record(out, ctx, "workload-smoke.log", cmd_idle, r)

    cmd_unregister = f"echo {shlex.quote(policy_name)} > {shlex.quote(SECURITYFS_UNREGISTER)}"
    r2 = ssh.run(target, cmd_unregister, timeout_s=30.0)
    _record(out, ctx, "workload-smoke.log", cmd_unregister, r2)

    # Surface a non-zero unregister rc only when register succeeded but
    # unregister did not -- otherwise the earlier register failure already
    # set the workload's rc.
    if out.returncode == 0 and r2.returncode != 0:
        out.returncode = r2.returncode
        out.notes = f"smoke unregister exited {r2.returncode}"
    return out


def functional(target: ssh.SshTarget, ctx: CellContext) -> WorkloadResult:
    """Run the self-contained Lua-LSM policy API and dispatch assertions."""
    out = WorkloadResult(name="functional")
    script = f"{GUEST_HOST_SHARE}/{LUA_LSM_TESTSUITE_FIXTURES}/guest/functional_policy.sh"
    timeout = float(ctx.profile.get("workload_timeout_s", 120.0))

    cmd = f"bash {shlex.quote(script)}"
    result = ssh.run(target, cmd, timeout_s=timeout)
    _record(out, ctx, "workload-functional.log", cmd, result)
    return out


def bench(target: ssh.SshTarget, ctx: CellContext) -> WorkloadResult:
    """Run lua-lsm-tools/tools/bench.lua inside the guest.

    The real bench.lua only accepts `cmd ∈ {"load", "unload"}` and exits
    non-zero with `Unknown cmd` on anything else, so the default is `load`.
    Callers that want a register/unregister round-trip in one cell should
    use bench_short() which issues both.

    Profile knobs:
        policy        policy file under examples/, default hello.lua
        bench_loops   passed as the `loop` arg to bench.lua, default 1
        bench_cmd     bench.lua subcommand, default 'load' (must be
                      'load' or 'unload')
    """
    out = WorkloadResult(name="bench")
    bench_lua = f"{GUEST_HOST_SHARE}/{LUA_LSM_TOOLS_TOOLS}/bench.lua"
    examples_dir = f"{GUEST_HOST_SHARE}/{LUA_LSM_TOOLS_EXAMPLES}"
    sub = str(ctx.profile.get("bench_cmd", "load"))
    loops = int(ctx.profile.get("bench_loops", 1))
    timeout = float(ctx.profile.get("workload_timeout_s", 1800.0))

    cmd = (
        f"set -euo pipefail; "
        f"lua {shlex.quote(bench_lua)} "
        f"{shlex.quote(sub)} {shlex.quote(examples_dir)} {loops}"
    )
    r = ssh.run(target, cmd, timeout_s=timeout)
    _record(out, ctx, "workload-bench.log", cmd, r)
    return out


def unixbench(target: ssh.SshTarget, ctx: CellContext) -> WorkloadResult:
    """Run UnixBench in the guest, bracketed by policy register/unregister.

    Perf cells need the selected Lua policy active during the workload so
    AC-5.1 hook deltas (e.g. denyfile.lua's `file_post_open.count`) are
    non-zero. We register the policy before invoking the wrapper, and
    we ALWAYS attempt the unregister step at the end — even when register
    itself failed, and even when the wrapper crashed. The unregister is
    a securityfs safety net: if a stale policy from a previous cell was
    already installed under the same name (which is what makes register
    fail in the first place), the safety-net unregister lets the next
    cell start clean. If the unregister has nothing to remove the kernel
    returns ENOENT, which we record but do not promote over the register
    or wrapper failure.

    Result-code precedence: register > wrapper > unregister > clean. The
    register rc is the load-bearing signal (no policy means the whole
    perf delta is meaningless), so even when both register AND unregister
    fail, the register failure is the cell rc. The wrapper failure ranks
    above unregister because the unregister is a safety net rather than
    a primary deliverable. See the rc-precedence test pin.

    The wrapper drops `system.txt`, `command.txt`, `unixbench.log`, and a
    copy of its latest result directory under whatever path is passed to
    `-o`. We point `-o` at the cell's artifact directory directly so those
    three top-level files land at the cell root, then move the copied
    result tree under `<cell>/results/<run-id>/` so the final on-host
    layout matches the documented contract:

        <cell>/system.txt
        <cell>/command.txt
        <cell>/unixbench.log
        <cell>/results/<run-id>/...

    Falls back to /tmp output when the cell has no guest_artifact_relpath
    (single-cell ad hoc runs).

    When the profile carries `policy: none`, the workload skips the
    register/unregister bracket entirely and runs UnixBench with no Lua policy
    active. This is the baseline path for comparing `lsm=...lua...` against an
    otherwise identical `lsm=` chain that omits `lua`.
    """
    out = WorkloadResult(name="unixbench")
    wrapper = f"{GUEST_HOST_SHARE}/{LUA_LSM_TOOLS_TOOLS}/lua_lsm_unixbench.sh"
    ub_dir = f"{GUEST_HOST_SHARE}/{UNIXBENCH_DIR}"

    cell_rel = ctx.profile.get("guest_artifact_relpath")
    out_dir = f"{GUEST_HOST_SHARE}/{cell_rel}" if cell_rel else "/tmp/lua-lsm-unixbench"

    cpus = int(ctx.profile.get("unixbench_cpus", 1))
    iters = int(ctx.profile.get("unixbench_iters", 1))
    timeout = float(ctx.profile.get("workload_timeout_s", 3600.0))
    policy_enabled = not _policy_disabled(ctx.profile.get("policy"))
    guest_local = bool(ctx.profile.get("unixbench_guest_local"))

    if guest_local:
        ub_dir = f"/tmp/{ctx.cell_id}-unixbench"
        out_dir = f"/tmp/{ctx.cell_id}-lua-lsm-unixbench"
        cmd_stage = (
            f"set -euo pipefail; "
            f"rm -rf {shlex.quote(ub_dir)} {shlex.quote(out_dir)}; "
            f"cp -a {shlex.quote(f'{GUEST_HOST_SHARE}/{UNIXBENCH_DIR}')} {shlex.quote(ub_dir)}"
        )
        r_stage = ssh.run(target, cmd_stage, timeout_s=120.0)
        _record(out, ctx, "workload-unixbench.log", cmd_stage, r_stage)
        if r_stage.returncode != 0:
            return out

    r_reg: ssh.SshResult | None = None
    if policy_enabled:
        policy_path = _policy_file_in_guest(ctx.profile.get("policy"))
        policy_name = _policy_short_name(ctx.profile.get("policy"))
        cmd_register = f"cat {shlex.quote(policy_path)} > {shlex.quote(SECURITYFS_REGISTER)}"
        r_reg = ssh.run(target, cmd_register, timeout_s=30.0)
        _record(out, ctx, "workload-unixbench.log", cmd_register, r_reg)

    cmd = (
        f"set -euo pipefail; "
        f"sh {shlex.quote(wrapper)} "
        f"-d {shlex.quote(ub_dir)} "
        f"-o {shlex.quote(out_dir)} "
        f"-c {cpus} -i {iters}"
    )
    wrapper_rc: int | None = None
    if not policy_enabled or (r_reg is not None and r_reg.returncode == 0):
        r = ssh.run(target, cmd, timeout_s=timeout)
        _record(out, ctx, "workload-unixbench.log", cmd, r)
        wrapper_rc = r.returncode

    r_unreg: ssh.SshResult | None = None
    if policy_enabled:
        cmd_unregister = f"echo {shlex.quote(policy_name)} > {shlex.quote(SECURITYFS_UNREGISTER)}"
        r_unreg = ssh.run(target, cmd_unregister, timeout_s=30.0)
        _record(out, ctx, "workload-unixbench.log", cmd_unregister, r_unreg)

    # Result-code precedence: register failure > wrapper failure > unregister
    # failure. _record() overwrites out.returncode on every call, so we
    # recompute the final value here from the per-step rcs we captured
    # rather than relying on the last _record call to leave it correct.
    # The register failure is the real story (no policy means the whole
    # perf delta is meaningless), and a wrapper failure must not be masked
    # by a successful unregister overwriting it.
    if not policy_enabled:
        out.returncode = wrapper_rc or 0
        if wrapper_rc not in (None, 0):
            out.notes = f"unixbench step exited {wrapper_rc}"
    elif r_reg is not None and r_reg.returncode != 0:
        out.returncode = r_reg.returncode
        out.notes = f"unixbench register exited {r_reg.returncode}"
    elif wrapper_rc not in (None, 0):
        out.returncode = wrapper_rc
        if not out.notes:
            out.notes = f"unixbench step exited {wrapper_rc}"
    elif r_unreg is not None and r_unreg.returncode != 0:
        out.returncode = r_unreg.returncode
        out.notes = f"unixbench unregister exited {r_unreg.returncode}"
    else:
        out.returncode = 0

    if guest_local:
        for name in ("system.txt", "command.txt", "unixbench.log"):
            text = ssh.fetch_text(target, f"{out_dir}/{name}")
            if text is not None:
                (ctx.artifact_dir / name).write_text(text)

    if cell_rel:
        _normalize_unixbench_layout(ctx.artifact_dir)
    return out


# Files the cell runner / workload writes at the cell root and which the
# unixbench normalizer must NOT move into results/.
_CELL_ROOT_RESERVED_NAMES: frozenset[str] = frozenset(
    {
        "cell.json",
        "result.json",
        "extra-cmdline.txt",
        "qemu-cmdline.txt",
        "serial.log",
        "dmesg.log",
        "journalctl-kb.txt",
        "stats-before.txt",
        "stats-after.txt",
        "lsm_funcs-before.txt",
        "lsm_funcs-after.txt",
        "workload-unixbench.log",
        "system.txt",
        "command.txt",
        "unixbench.log",
        "results",
        "bundles",
    }
)


def _normalize_unixbench_layout(cell_dir: Path) -> None:
    """Move the UnixBench result tree under <cell>/results/<run-id>/.

    `lua_lsm_unixbench.sh -o <cell>` produces system.txt, command.txt, and
    unixbench.log at the cell root plus one extra directory whose name is
    the UnixBench result-set name (e.g. `unixbench-2026-...`). Move that
    single extra directory to `<cell>/results/<name>/`.

    Multiple unknown directories (a developer copied something else in
    while the run was live) are all moved under results/ to keep the cell
    root tidy. Missing files are ignored -- a wrapper that failed before
    writing the result tree should not block the workload's verdict.
    """
    if not cell_dir.exists() or not cell_dir.is_dir():
        return
    target_results = cell_dir / "results"
    for child in cell_dir.iterdir():
        if not child.is_dir():
            continue
        if child.name in _CELL_ROOT_RESERVED_NAMES:
            continue
        target_results.mkdir(parents=True, exist_ok=True)
        dest = target_results / child.name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.move(str(child), str(dest))


def verify_cleanup(target: ssh.SshTarget, ctx: CellContext) -> WorkloadResult:
    """Run lua-lsm-tools/tools/verify_module_cleanup.sh inside the guest.

    The script registers a temp module, exercises a hook, unregisters, and
    verifies kvcache live-node counts before/after match. Exit 0 = clean
    cleanup, exit 1 = leak observed (which the cell records as a non-zero
    workload rc; the matrix-level classifier may further escalate to
    kernel-bug if dmesg also surfaces a splat).
    """
    out = WorkloadResult(name="verify-cleanup")
    script = f"{GUEST_HOST_SHARE}/{LUA_LSM_TOOLS_TOOLS}/verify_module_cleanup.sh"
    timeout = float(ctx.profile.get("workload_timeout_s", 300.0))

    cmd = f"bash {shlex.quote(script)}"
    r = ssh.run(target, cmd, timeout_s=timeout)
    _record(out, ctx, "workload-verify-cleanup.log", cmd, r)
    return out


def lkdtm(target: ssh.SshTarget, ctx: CellContext) -> WorkloadResult:
    """Trigger LKDTM and confirm classifier catches the splat (positive control).

    The cell-level expectation is INVERTED at the matrix layer: this cell
    PASSES when the classifier sees a kernel splat caused by LKDTM. When
    CONFIG_LKDTM is not built, the workload returns rc=77 and the matrix
    records skip:no-lkdtm.
    """
    out = WorkloadResult(name="lkdtm")
    target_kind = str(ctx.profile.get("lkdtm_kind", "WARNING"))
    cmd = (
        "set -eo pipefail; "
        "if [ ! -e /sys/kernel/debug/provoke-crash/DIRECT ]; then "
        "  echo 'LKDTM_PROVOKE_MISSING'; exit 77; "
        "fi; "
        f"echo {shlex.quote(target_kind)} > /sys/kernel/debug/provoke-crash/DIRECT || true"
    )
    r = ssh.run(target, cmd, timeout_s=30.0)
    _record(out, ctx, "workload-lkdtm.log", cmd, r)
    if r.returncode == 77:
        out.notes = "LKDTM provoke node missing (CONFIG_LKDTM not enabled)"
    return out


def bench_short(target: ssh.SshTarget, ctx: CellContext) -> WorkloadResult:
    """Bounded alias of `bench` that runs a paired load/unload round-trip.

    Used by the default smoke matrix so a developer can sweep the full
    policy x pool x kconfig x workload Cartesian product without paying the
    full perf-bench cost on every cell. The cell ends with the policy
    UNREGISTERED so the next cell's smoke register doesn't collide; the
    unload step runs even when load fails.

    Profile knobs that callers set explicitly still win (we only seed
    defaults). Callers cannot override `bench_cmd` here — bench_short
    always issues both load and unload.
    """
    profile = dict(ctx.profile)
    profile.setdefault("bench_loops", 1)
    profile.setdefault("workload_timeout_s", 60.0)

    ctx_load = ctx.with_profile(**{**profile, "bench_cmd": "load"})
    out = bench(target, ctx_load)
    out.name = "bench-short"

    ctx_unload = ctx.with_profile(**{**profile, "bench_cmd": "unload"})
    unload = bench(target, ctx_unload)
    # Surface a non-zero unload rc only when load succeeded; otherwise the
    # load failure is the real story and we don't want to clobber it.
    if out.returncode == 0 and unload.returncode != 0:
        out.returncode = unload.returncode
        out.notes = f"bench-short unload exited {unload.returncode}"
    return out


# The single source of truth for workload registration. Everything the
# harness needs beyond the callable itself -- guest fixture requirements,
# policy resolution, share-dir requirements, the CLI's --workload choices --
# derives from this table. Adding a workload means adding one entry here
# (plus a config that selects it).
SPECS.update(
    {
        "functional": WorkloadSpec(
            name="functional",
            fn=functional,
            guest_fixtures=(
                f"{GUEST_HOST_SHARE}/{LUA_LSM_TESTSUITE_FIXTURES}/guest/functional_policy.sh",
            ),
            policy_guest_dir=f"{LUA_LSM_TESTSUITE_FIXTURES}/policies",
            default_policy="smoke.lua",
            self_contained=True,
        ),
        "smoke": WorkloadSpec(
            name="smoke",
            fn=smoke,
            guest_fixtures=(f"{GUEST_HOST_SHARE}/{LUA_LSM_TOOLS_EXAMPLES}/hello.lua",),
        ),
        "bench": WorkloadSpec(
            name="bench",
            fn=bench,
            guest_fixtures=(f"{GUEST_HOST_SHARE}/{LUA_LSM_TOOLS_TOOLS}/bench.lua",),
        ),
        "bench-short": WorkloadSpec(
            name="bench-short",
            fn=bench_short,
            guest_fixtures=(f"{GUEST_HOST_SHARE}/{LUA_LSM_TOOLS_TOOLS}/bench.lua",),
        ),
        "unixbench": WorkloadSpec(
            name="unixbench",
            fn=unixbench,
            guest_fixtures=(f"{GUEST_HOST_SHARE}/{LUA_LSM_TOOLS_TOOLS}/lua_lsm_unixbench.sh",),
        ),
        "verify-cleanup": WorkloadSpec(
            name="verify-cleanup",
            fn=verify_cleanup,
            guest_fixtures=(f"{GUEST_HOST_SHARE}/{LUA_LSM_TOOLS_TOOLS}/verify_module_cleanup.sh",),
        ),
        "lkdtm": WorkloadSpec(
            name="lkdtm",
            fn=lkdtm,
            # Uses /sys/kernel/debug/provoke-crash; checked at workload time.
            guest_fixtures=(),
        ),
    }
)

# The callable registry (CLI --workload choices, by_name lookups) derives
# from SPECS so the two can never drift apart.
REGISTRY = {name: spec.fn for name, spec in SPECS.items()}


def by_name(name: str):
    if name not in REGISTRY:
        raise KeyError(f"unknown workload: {name}; known: {sorted(REGISTRY)}")
    return REGISTRY[name]
