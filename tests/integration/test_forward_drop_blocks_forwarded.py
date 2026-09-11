# tests/integration/test_forward_drop_blocks_forwarded.py
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


def _port(base: int, sfx: str) -> str:
    return str(base + (int(sfx[-4:], 10) % 400))


@pytest.mark.integration
@pytest.mark.skipif(platform.system() != "Linux", reason="needs Linux netns")
@pytest.mark.skipif(os.geteuid() != 0, reason="needs root")
@pytest.mark.skipif(
    not h._has_tools("nft", "ip", "curl", "dd", "python3"),
    reason="needs nft+ip+curl+dd+python3",
)
def test_forward_drop_blocks_lan_to_wan_http():
    sfx = _suffix()

    table = f"qmfd{sfx}"
    drop_set = "drop_users"

    lan_ns = f"lan{sfx}"
    wan_ns = f"wan{sfx}"

    veth_lh, veth_ln = f"lh{sfx}", f"ln{sfx}"
    veth_wh, veth_wn = f"wh{sfx}", f"wn{sfx}"

    host_lan = "10.251.1.1"
    lan_ip = "10.251.1.2"
    host_wan = "10.251.2.1"
    wan_ip = "10.251.2.2"
    port = _port(8090, sfx)

    fw_tag = f"qmtest-fwd-drop-{sfx}"

    with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
        old_fwd = f.read().strip()

    def cleanup():
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

        # ---------- LAN ----------
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

        # ---------- WAN ----------
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

        # Deterministic reply route back to LAN subnet
        h._cmd(
            [
                "ip",
                "netns",
                "exec",
                wan_ns,
                "ip",
                "route",
                "add",
                "10.251.1.0/24",
                "via",
                host_wan,
            ],
            check=False,
        )

        # fw4 backstop: allow forward across veths
        h.fw4_insert_allow_forward(fw_tag, veth_lh, veth_wh)
        h.fw4_insert_allow_forward(fw_tag, veth_wh, veth_lh)

        # ---------- nft pre-fw4 forward drop ----------
        h._cmd(["nft", "add", "table", "inet", table])
        h.nft_add_ipv4_set(table, drop_set, counter=False)

        chain = "fwd_pre"
        h.nft_forward_pre_fw4_chain(
            table, chain, veth_lh, veth_wh, accept_by_default=True
        )

        # Drop if src in drop_set (must be before accepts)
        h._cmd(
            [
                "nft",
                "insert",
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

        with tempfile.TemporaryDirectory() as td:
            blob = f"{td}/blob"
            h._cmd(
                ["dd", "if=/dev/zero", f"of={blob}", "bs=1M", "count=1"], capture=False
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
                url = f"http://{wan_ip}:{port}/blob"
                h.wait_http(url, ns=lan_ns, timeout_s=15.0)
                assert h.curl_http_code(url, ns=lan_ns, max_time_s=8) == "200"

                # Works
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
                        "12",
                        url,
                        "-o",
                        "/dev/null",
                    ],
                    check=True,
                    capture=True,
                )

                # Add to drop set -> fail
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
                        "3",
                        "--max-time",
                        "6",
                        url,
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
                    srv.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    srv.kill()
    finally:
        cleanup()
