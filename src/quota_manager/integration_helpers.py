from __future__ import annotations

import json
import math
import re
import shutil
import subprocess
import time
from typing import Any, Iterable, Sequence


def _has_tools(*names: str) -> bool:
    return all(shutil.which(n) for n in names)


def _cmd(
    args: Sequence[str],
    *,
    check: bool = True,
    capture: bool = True,
    timeout: float | None = None,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """
    Small wrapper for subprocess.run used in integration tests.
    - capture=True -> stdout/stderr captured as text
    - capture=False -> inherits stdout/stderr unless caller overrides
    """
    kwargs: dict[str, Any] = {
        "check": check,
        "timeout": timeout,
        "cwd": cwd,
        "env": env,
        "text": True,
    }
    if capture:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    return subprocess.run(list(args), **kwargs)


def _ceil_seconds(x: float, *, min_s: int = 1) -> str:
    # OpenWrt curl can choke on tiny fractional --max-time values (e.g. 0.5).
    # Always pass a small integer number of seconds.
    return str(max(min_s, int(math.ceil(x))))


def wait_http(url: str, *, ns: str | None = None, timeout_s: float = 6.0) -> None:
    """
    Poll until an HTTP server answers with HTTP 200.

    NOTE: OpenWrt curl commonly fails with:
      curl: (28) remaining timeout of 500 too small to resolve via SIGALRM method
    when --max-time is too small (e.g. 0.5). We only use integer seconds.
    """
    deadline = time.time() + timeout_s
    last: subprocess.CompletedProcess | None = None

    while time.time() < deadline:
        remaining = max(0.0, deadline - time.time())
        per_attempt = min(3.0, max(1.0, remaining))
        max_time = _ceil_seconds(per_attempt, min_s=2)
        connect_time = "2"

        # IMPORTANT:
        #  - Force direct connect (ignore proxy env)
        #  - Require real HTTP 200 (curl returns 0 even for 404 unless --fail or we check code)
        cmd = [
            "curl",
            "-sS",
            "--noproxy",
            "*",
            "--connect-timeout",
            connect_time,
            "--max-time",
            max_time,
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            url,
        ]
        if ns:
            cmd = ["ip", "netns", "exec", ns] + cmd

        last = _cmd(cmd, check=False, capture=True)
        if last.returncode == 0 and (last.stdout or "").strip() == "200":
            return

        time.sleep(0.05)

    msg = last.stderr if (last and getattr(last, "stderr", None)) else ""
    code = (last.stdout or "").strip() if last else ""
    raise RuntimeError(f"HTTP not ready: {url} (last_code={code})\n{msg}")


def curl_http_code(url: str, *, ns: str | None = None) -> str:
    cmd = [
        "curl",
        "-sS",
        "--noproxy",
        "*",
        "--connect-timeout",
        "3",
        "--max-time",
        "15",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        url,
    ]
    if ns:
        cmd = ["ip", "netns", "exec", ns] + cmd
    p = _cmd(cmd, check=False, capture=True)
    return (p.stdout or "").strip()


def ip_link_del(ifname: str) -> None:
    _cmd(["ip", "link", "del", ifname], check=False, capture=True)


def netns_del(ns: str) -> None:
    _cmd(["ip", "netns", "del", ns], check=False, capture=True)


def nft_delete_table(table: str) -> None:
    _cmd(["nft", "delete", "table", "inet", table], check=False, capture=True)


def _nft_try_add_chain(args: list[str]) -> None:
    # ignore "File exists" style errors
    _cmd(args, check=False, capture=True)


# ---------- fw4 helpers (OpenWrt firewall) ----------


def _fw4_exists() -> bool:
    return _cmd(["nft", "list", "table", "inet", "fw4"], check=False).returncode == 0


def fw4_insert_allow_input(tag: str, iifname: str) -> None:
    """
    Allow inbound packets from iifname in OpenWrt fw4 input chain.
    No-op on non-OpenWrt systems (no fw4 table).
    """
    if not _fw4_exists():
        return
    _cmd(
        [
            "nft",
            "insert",
            "rule",
            "inet",
            "fw4",
            "input",
            "iifname",
            iifname,
            "accept",
            "comment",
            tag,
        ],
        check=False,
    )


def fw4_insert_allow_forward(tag: str, iifname: str, oifname: str) -> None:
    """
    Allow forwarding from iifname -> oifname in OpenWrt fw4 forward chain.
    """
    if not _fw4_exists():
        return
    _cmd(
        [
            "nft",
            "insert",
            "rule",
            "inet",
            "fw4",
            "forward",
            "iifname",
            iifname,
            "oifname",
            oifname,
            "accept",
            "comment",
            tag,
        ],
        check=False,
    )


def fw4_delete_tagged_rules(tag: str) -> None:
    """
    Delete any fw4 rules containing comment "<tag>" in common chains.
    Safe to call even if fw4 doesn't exist.
    """
    if not _fw4_exists():
        return

    chains = ("input", "forward", "output")
    for ch in chains:
        out = _cmd(["nft", "-a", "list", "chain", "inet", "fw4", ch], check=False)
        if out.returncode != 0 or not out.stdout:
            continue

        handles: list[str] = []
        for line in out.stdout.splitlines():
            if f'comment "{tag}"' in line:
                m = re.search(r"#\s*handle\s+(\d+)", line)
                if m:
                    handles.append(m.group(1))

        for h in handles:
            _cmd(["nft", "delete", "rule", "inet", "fw4", ch, "handle", h], check=False)


# ---------- global tagged-rule helpers (for OpenWrt + custom rulesets) ----------


def nft_delete_tagged_rules_any(tag: str) -> None:
    """
    Delete rules with comment "<tag>" across *all* tables/chains in the ruleset.

    This is critical on systems like yours where a custom base forward chain (policy drop)
    exists outside fw4; fw4_delete_tagged_rules alone is not enough.
    """
    out = _cmd(["nft", "-a", "list", "ruleset"], check=False, capture=True)
    if out.returncode != 0 or not out.stdout:
        return

    fam = None
    tbl = None
    chn = None

    for line in out.stdout.splitlines():
        m = re.match(r"^\s*table\s+(\S+)\s+(\S+)\s*\{", line)
        if m:
            fam, tbl = m.group(1), m.group(2)
            chn = None
            continue

        m = re.match(r"^\s*chain\s+(\S+)\s*\{", line)
        if m:
            chn = m.group(1)
            continue

        if fam and tbl and chn and f'comment "{tag}"' in line:
            hm = re.search(r"#\s*handle\s+(\d+)", line)
            if not hm:
                continue
            handle = hm.group(1)
            _cmd(
                ["nft", "delete", "rule", fam, tbl, chn, "handle", handle],
                check=False,
                capture=True,
            )


def _iter_forward_base_chains() -> Iterable[tuple[str, str, str]]:
    """
    Yield (family, table, chain) for every base chain that hooks 'forward' in the ruleset.
    Prefer JSON for correctness; fall back to text.
    """
    j = _cmd(["nft", "-j", "list", "ruleset"], check=False, capture=True)
    if j.returncode == 0 and j.stdout:
        try:
            data = json.loads(j.stdout)
            for item in data.get("nftables", []):
                ch = item.get("chain")
                if not isinstance(ch, dict):
                    continue
                if ch.get("hook") != "forward":
                    continue
                fam = ch.get("family")
                tbl = ch.get("table")
                name = ch.get("name")
                if (
                    isinstance(fam, str)
                    and isinstance(tbl, str)
                    and isinstance(name, str)
                ):
                    yield fam, tbl, name
            return
        except Exception:
            pass

    # Fallback: text scrape minimal info
    out = _cmd(["nft", "list", "ruleset"], check=False, capture=True)
    if out.returncode != 0 or not out.stdout:
        return

    fam = None
    tbl = None
    chn = None
    in_chain_block = False
    chain_is_forward_base = False

    for line in out.stdout.splitlines():
        m = re.match(r"^\s*table\s+(\S+)\s+(\S+)\s*\{", line)
        if m:
            fam, tbl = m.group(1), m.group(2)
            chn = None
            in_chain_block = False
            chain_is_forward_base = False
            continue

        m = re.match(r"^\s*chain\s+(\S+)\s*\{", line)
        if m:
            chn = m.group(1)
            in_chain_block = True
            chain_is_forward_base = False
            continue

        if in_chain_block and "hook forward" in line:
            chain_is_forward_base = True

        if in_chain_block and line.strip() == "}":
            if chain_is_forward_base and fam and tbl and chn:
                yield fam, tbl, chn
            in_chain_block = False
            chain_is_forward_base = False


def nft_allow_veth_forward_globally(tag: str, veth_a: str, veth_b: str) -> None:
    """
    Make forwarding across veth_a <-> veth_b deterministic even when the system already
    has its own base forward chains (like your quota_manager_forward policy drop chain).

    We insert ACCEPT rules (tagged) into every forward-hook base chain we can find.
    """
    # fw4 is common on OpenWrt; add there explicitly too
    fw4_insert_allow_forward(tag, veth_a, veth_b)
    fw4_insert_allow_forward(tag, veth_b, veth_a)

    for fam, tbl, chn in _iter_forward_base_chains():
        _cmd(
            [
                "nft",
                "insert",
                "rule",
                fam,
                tbl,
                chn,
                "iifname",
                veth_a,
                "oifname",
                veth_b,
                "accept",
                "comment",
                tag,
            ],
            check=False,
            capture=True,
        )
        _cmd(
            [
                "nft",
                "insert",
                "rule",
                fam,
                tbl,
                chn,
                "iifname",
                veth_b,
                "oifname",
                veth_a,
                "accept",
                "comment",
                tag,
            ],
            check=False,
            capture=True,
        )


# ---------- nft helpers used by tests ----------


def nft_allow_local_veth_before_fw4(table: str, veth_host_ifname: str) -> None:
    """
    Backwards-compatible name used by your tests.

    1) Create a very-early INPUT base chain (priority -200) in the given table that
       accepts packets arriving on veth_host_ifname.
    2) Also punch a small fw4 INPUT hole (OpenWrt) as a backstop.

    This mirrors how your real system behaves (fw4 + your own rulesets).
    """
    # (1) our test table chain
    chain = f"in_pre_{re.sub(r'[^A-Za-z0-9_]', '_', veth_host_ifname)}"
    _nft_try_add_chain(
        [
            "nft",
            "add",
            "chain",
            "inet",
            table,
            chain,
            "{",
            "type",
            "filter",
            "hook",
            "input",
            "priority",
            "-200",
            ";",
            "policy",
            "accept",
            ";",
            "}",
        ]
    )
    _cmd(
        [
            "nft",
            "add",
            "rule",
            "inet",
            table,
            chain,
            "iifname",
            veth_host_ifname,
            "accept",
        ],
        check=False,
        capture=True,
    )
    _cmd(
        ["nft", "add", "rule", "inet", table, chain, "return"],
        check=False,
        capture=True,
    )

    # (2) fw4 backstop
    fw4_insert_allow_input(f"qmtest-{table}-{veth_host_ifname}", veth_host_ifname)


def nft_forward_pre_fw4_chain(
    table: str,
    chain: str,
    veth_a: str,
    veth_b: str,
    *,
    accept_by_default: bool = True,
) -> None:
    """
    Create a pre-fw4 FORWARD base chain (priority -200).
    Adds accept rules for veth_a <-> veth_b traffic, then a final return.
    """
    _nft_try_add_chain(
        [
            "nft",
            "add",
            "chain",
            "inet",
            table,
            chain,
            "{",
            "type",
            "filter",
            "hook",
            "forward",
            "priority",
            "-200",
            ";",
            "policy",
            "accept" if accept_by_default else "drop",
            ";",
            "}",
        ]
    )

    _cmd(
        [
            "nft",
            "add",
            "rule",
            "inet",
            table,
            chain,
            "iifname",
            veth_a,
            "oifname",
            veth_b,
            "accept",
        ],
        check=False,
        capture=True,
    )
    _cmd(
        [
            "nft",
            "add",
            "rule",
            "inet",
            table,
            chain,
            "iifname",
            veth_b,
            "oifname",
            veth_a,
            "accept",
        ],
        check=False,
        capture=True,
    )
    _cmd(
        ["nft", "add", "rule", "inet", table, chain, "return"],
        check=False,
        capture=True,
    )


def nft_get_set_elem_bytes(table: str, set_name: str, ip: str) -> int:
    """
    Robust-ish: prefer nft JSON output; fallback to text regex.
    Requires the set to be defined with 'counter;' to expose bytes.
    """
    j = _cmd(
        ["nft", "-j", "list", "set", "inet", table, set_name], check=False, capture=True
    )
    if j.returncode == 0 and j.stdout:
        try:
            data = json.loads(j.stdout)
        except json.JSONDecodeError:
            data = None

        if data is not None:

            def walk(x: Any) -> Iterable[dict[str, Any]]:
                if isinstance(x, dict):
                    yield x
                    for v in x.values():
                        yield from walk(v)
                elif isinstance(x, list):
                    for v in x:
                        yield from walk(v)

            for obj in walk(data):
                elem = obj.get("elem")
                if not isinstance(elem, dict):
                    continue
                val = elem.get("val")
                if val == ip:
                    counter = elem.get("counter")
                    if isinstance(counter, dict) and "bytes" in counter:
                        return int(counter["bytes"])

                if isinstance(val, dict):
                    addr = val.get("addr") or val.get("ip") or val.get("value")
                    if addr == ip:
                        counter = elem.get("counter")
                        if isinstance(counter, dict) and "bytes" in counter:
                            return int(counter["bytes"])

    out = _cmd(
        ["nft", "list", "set", "inet", table, set_name], check=True, capture=True
    ).stdout
    m = re.search(rf"\b{re.escape(ip)}\b.*?\bbytes\s+(\d+)\b", out, flags=re.DOTALL)
    if not m:
        raise RuntimeError(
            f"Cannot find bytes counter for {ip} in {table}:{set_name}\n{out}"
        )
    return int(m.group(1))


def nft_add_ipv4_set(
    table: str,
    set_name: str,
    *,
    counter: bool = False,
    family: str = "inet",
) -> None:
    parts = [
        "nft",
        "add",
        "set",
        family,
        table,
        set_name,
        "{",
        "type",
        "ipv4_addr",
        ";",
    ]
    if counter:
        parts += ["counter", ";"]
    parts += ["}"]
    _cmd(parts)


def nft_add_element(
    table: str,
    set_name: str,
    ip: str,
    *,
    family: str = "inet",
) -> None:
    _cmd(["nft", "add", "element", family, table, set_name, "{", ip, "}"])


def nft_flush_set(table: str, set_name: str, *, family: str = "inet") -> None:
    _cmd(["nft", "flush", "set", family, table, set_name], check=False)


def nft_get_set_element_bytes(
    table: str,
    set_name: str,
    ip: str,
    *,
    family: str = "inet",
) -> int:
    """
    Read per-element counter bytes from an nft set element.
    Requires the set to be created with `counter;`.
    Uses JSON output when available; falls back to text parsing.
    """
    j = _cmd(
        ["nft", "-j", "list", "set", family, table, set_name], check=False, capture=True
    )
    if j.returncode == 0 and j.stdout:
        try:
            data = json.loads(j.stdout)
            for item in data.get("nftables", []):
                s = item.get("set")
                if not s or s.get("name") != set_name:
                    continue
                for elem in s.get("elem", []) or []:
                    e = elem.get("elem") or elem
                    val = e.get("val")
                    if isinstance(val, str) and val == ip:
                        ctr = e.get("counter") or {}
                        b = ctr.get("bytes")
                        if isinstance(b, int):
                            return b
                        raise RuntimeError(f"Element has no bytes counter: {ip}")
            raise RuntimeError(f"Cannot find element {ip} in {table}:{set_name}")
        except Exception:
            pass

    out = (
        _cmd(
            ["nft", "list", "set", family, table, set_name], check=False, capture=True
        ).stdout
        or ""
    )
    m = re.search(rf"\b{re.escape(ip)}\b.*?\bbytes\s+(\d+)\b", out)
    if not m:
        raise RuntimeError(
            f"Cannot find bytes counter for {ip} in {table}:{set_name}\n{out}"
        )
    return int(m.group(1))
