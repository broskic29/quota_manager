from __future__ import annotations

import os
import platform
import subprocess
import tempfile
import time

import pytest

import quota_manager.integration_helpers as h


def _suffix() -> str:
    return f"{os.getpid() % 10000:04d}{int(time.time() * 1000) % 10000:04d}"


@pytest.mark.integration
@pytest.mark.skipif(platform.system() != "Linux", reason="needs Linux netns")
@pytest.mark.skipif(os.geteuid() != 0, reason="needs root")
@pytest.mark.skipif(
    not h._has_tools("nft", "ip", "curl", "dd", "python3"),
    reason="needs nft+ip+curl+dd+python3",
)
def test_forward_end_to_end_quota_enforcement_blocks_forwarded_http(
    db_paths, monkeypatch
):
    _usage_db, _ = db_paths  # fixture parity

    sfx = _suffix()
    table = f"qm_fwd_e2e_{sfx}"
    acct_set = "acct_users"
    drop_set = "drop_users"

    lan_ns = f"lan_{sfx}"
    wan_ns = f"wan_{sfx}"

    veth_lh, veth_ln = f"lh{sfx}", f"ln{sfx}"
    veth_wh, veth_wn = f"wh{sfx}", f"wn{sfx}"

    host_lan = "10.27.1.1"
    lan_ip = "10.27.1.2"
    host_wan = "10.27.2.1"
    wan_ip = "10.27.2.2"
    port = "8080"

    fw_tag = f"qmtest-fwd-e2e-{sfx}"

    with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
        old_fwd = f.read().strip()

    def cleanup():
        h.nft_delete_tagged_rules_any(fw_tag)
        h.fw4_delete_tagged_rules(fw_tag)

        h.netns_del(lan_ns)
        h.netns_del(wan_ns)
        h.ip_link_del(veth_lh)
        h.ip_link_del(veth_wh)
        h.nft_delete_table(table)

        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write(old_fwd)

    cleanup()
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")

        # LAN
        h._cmd(["ip", "netns", "add", lan_ns])
        h._cmd(["ip", "link", "add", veth_lh, "type", "veth", "peer", "name", veth_ln])
        h._cmd(["ip", "link", "set", veth_ln, "netns", lan_ns])
        h._cmd(["ip", "addr", "add", f"{host_lan}/24", "dev", veth_lh])
        h._cmd(["ip", "link", "set", veth_lh, "up"])
        h._cmd(
            [
                "ip",
                "netns",
                "exec",
                lan_ns,
                "ip",
                "addr",
                "add",
                f"{lan_ip}/24",
                "dev",
                veth_ln,
            ]
        )
        h._cmd(["ip", "netns", "exec", lan_ns, "ip", "link", "set", veth_ln, "up"])
        h._cmd(["ip", "netns", "exec", lan_ns, "ip", "link", "set", "lo", "up"])
        h._cmd(
            [
                "ip",
                "netns",
                "exec",
                lan_ns,
                "ip",
                "route",
                "add",
                "default",
                "via",
                host_lan,
            ]
        )

        # WAN
        h._cmd(["ip", "netns", "add", wan_ns])
        h._cmd(["ip", "link", "add", veth_wh, "type", "veth", "peer", "name", veth_wn])
        h._cmd(["ip", "link", "set", veth_wn, "netns", wan_ns])
        h._cmd(["ip", "addr", "add", f"{host_wan}/24", "dev", veth_wh])
        h._cmd(["ip", "link", "set", veth_wh, "up"])
        h._cmd(
            [
                "ip",
                "netns",
                "exec",
                wan_ns,
                "ip",
                "addr",
                "add",
                f"{wan_ip}/24",
                "dev",
                veth_wn,
            ]
        )
        h._cmd(["ip", "netns", "exec", wan_ns, "ip", "link", "set", veth_wn, "up"])
        h._cmd(["ip", "netns", "exec", wan_ns, "ip", "link", "set", "lo", "up"])
        h._cmd(
            [
                "ip",
                "netns",
                "exec",
                wan_ns,
                "ip",
                "route",
                "add",
                "default",
                "via",
                host_wan,
            ]
        )

        # Punch forward holes into *all* forward-hook base chains on the box
        h.nft_allow_veth_forward_globally(fw_tag, veth_lh, veth_wh)

        # nft: forward accounting + drop set (pre-fw4)
        h._cmd(["nft", "add", "table", "inet", table])
        h.nft_add_ipv4_set(table, acct_set, counter=True)
        h.nft_add_ipv4_set(table, drop_set, counter=False)
        h.nft_add_element(table, acct_set, lan_ip)

        chain = "fwd_pre"
        h._cmd(
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
                "-250",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ]
        )
        h._cmd(
            ["nft", "add", "rule", "inet", table, chain, "ip", "saddr", "@" + acct_set]
        )
        h._cmd(
            [
                "nft",
                "add",
                "rule",
                "inet",
                table,
                chain,
                "ip",
                "saddr",
                "@" + drop_set,
                "drop",
            ]
        )
        h._cmd(
            [
                "nft",
                "add",
                "rule",
                "inet",
                table,
                chain,
                "iifname",
                veth_lh,
                "oifname",
                veth_wh,
                "accept",
            ]
        )
        h._cmd(
            [
                "nft",
                "add",
                "rule",
                "inet",
                table,
                chain,
                "iifname",
                veth_wh,
                "oifname",
                veth_lh,
                "accept",
            ]
        )
        h._cmd(["nft", "add", "rule", "inet", table, chain, "return"])

        with tempfile.TemporaryDirectory() as td:
            blob = f"{td}/blob"
            h._cmd(
                ["dd", "if=/dev/zero", f"of={blob}", "bs=1M", "count=2"], capture=False
            )

            srv = subprocess.Popen(
                [
                    "ip",
                    "netns",
                    "exec",
                    wan_ns,
                    "python3",
                    "-m",
                    "http.server",
                    port,
                    "--bind",
                    wan_ip,
                ],
                cwd=td,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                h.wait_http(f"http://{wan_ip}:{port}/blob", ns=lan_ns, timeout_s=15.0)

                before = h.nft_get_set_elem_bytes(table, acct_set, lan_ip)

                h._cmd(
                    [
                        "ip",
                        "netns",
                        "exec",
                        lan_ns,
                        "curl",
                        "-sS",
                        "--noproxy",
                        "*",
                        "--connect-timeout",
                        "3",
                        "--max-time",
                        "20",
                        f"http://{wan_ip}:{port}/blob",
                        "-o",
                        "/dev/null",
                    ],
                    check=True,
                    capture=True,
                )

                after = h.nft_get_set_elem_bytes(table, acct_set, lan_ip)
                assert after > before

                # "Quota enforcement": add to drop_set
                h.nft_add_element(table, drop_set, lan_ip)
                fail = h._cmd(
                    [
                        "ip",
                        "netns",
                        "exec",
                        lan_ns,
                        "curl",
                        "-sS",
                        "--noproxy",
                        "*",
                        "--connect-timeout",
                        "2",
                        "--max-time",
                        "6",
                        f"http://{wan_ip}:{port}/blob",
                        "-o",
                        "/dev/null",
                    ],
                    check=False,
                    capture=True,
                )
                assert fail.returncode != 0
            finally:
                srv.terminate()
                try:
                    srv.wait(timeout=1.5)
                except subprocess.TimeoutExpired:
                    srv.kill()
    finally:
        cleanup()
