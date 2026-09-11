from __future__ import annotations

import os
import platform
import subprocess
import tempfile
import time

import pytest

import quota_manager.integration_helpers as h


def _suffix() -> str:
    # Interface name limit is 15 chars; keep suffix short.
    return f"{os.getpid() % 10000:04d}{int(time.time() * 1000) % 10000:04d}"


@pytest.mark.integration
@pytest.mark.skipif(platform.system() != "Linux", reason="needs Linux netns")
@pytest.mark.skipif(os.geteuid() != 0, reason="needs root")
@pytest.mark.skipif(
    not h._has_tools("nft", "ip", "curl", "dd", "python3"),
    reason="needs nft+ip+curl+dd+python3",
)
def test_two_clients_counted_separately(db_paths, monkeypatch):
    _usage_db, _ = db_paths

    sfx = _suffix()
    table = f"qm_test_{sfx}"
    hs_set = "hs_users"

    ns1, ns2 = f"qmns1_{sfx}", f"qmns2_{sfx}"
    vethh1, vethn1 = f"vh1_{sfx}", f"vn1_{sfx}"
    vethh2, vethn2 = f"vh2_{sfx}", f"vn2_{sfx}"

    host_ip1, client_ip1 = "10.210.1.1", "10.210.1.2"
    host_ip2, client_ip2 = "10.210.2.1", "10.210.2.2"

    fw_tag1 = f"qmtest-{sfx}-1"
    fw_tag2 = f"qmtest-{sfx}-2"

    def cleanup():
        h.fw4_delete_tagged_rules(fw_tag1)
        h.fw4_delete_tagged_rules(fw_tag2)
        h._cmd(["ip", "netns", "del", ns1], check=False)
        h._cmd(["ip", "netns", "del", ns2], check=False)
        h._cmd(["ip", "link", "del", vethh1], check=False)
        h._cmd(["ip", "link", "del", vethh2], check=False)
        h._cmd(["nft", "delete", "table", "inet", table], check=False)

    cleanup()
    try:
        for ns, vethh, vethn, host_ip, client_ip, fwtag in [
            (ns1, vethh1, vethn1, host_ip1, client_ip1, fw_tag1),
            (ns2, vethh2, vethn2, host_ip2, client_ip2, fw_tag2),
        ]:
            h._cmd(["ip", "netns", "add", ns])
            h._cmd(["ip", "link", "add", vethh, "type", "veth", "peer", "name", vethn])
            h._cmd(["ip", "link", "set", vethn, "netns", ns])

            h._cmd(["ip", "addr", "add", f"{host_ip}/24", "dev", vethh])
            h._cmd(["ip", "link", "set", vethh, "up"])

            h._cmd(
                [
                    "ip",
                    "netns",
                    "exec",
                    ns,
                    "ip",
                    "addr",
                    "add",
                    f"{client_ip}/24",
                    "dev",
                    vethn,
                ]
            )
            h._cmd(["ip", "netns", "exec", ns, "ip", "link", "set", vethn, "up"])
            h._cmd(["ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"])
            h._cmd(
                ["ip", "netns", "exec", ns, "ip", "route", "add", host_ip, "dev", vethn]
            )

            # Allow host services reachable from this veth through fw4
            h.nft_allow_local_veth_before_fw4(fwtag, vethh)

        # nft: one table + counter set; count host output to each client IP
        h._cmd(["nft", "add", "table", "inet", table])
        h.nft_add_ipv4_set(table, hs_set, counter=True)
        for ip in (client_ip1, client_ip2):
            h.nft_add_element(table, hs_set, ip)

        h._cmd(
            [
                "nft",
                "add",
                "chain",
                "inet",
                table,
                "out",
                "{",
                "type",
                "filter",
                "hook",
                "output",
                "priority",
                "0",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ]
        )
        h._cmd(
            ["nft", "add", "rule", "inet", table, "out", "ip", "daddr", "@" + hs_set]
        )

        with tempfile.TemporaryDirectory() as td:
            f1, f2 = f"{td}/a", f"{td}/b"
            h._cmd(
                ["dd", "if=/dev/zero", f"of={f1}", "bs=1M", "count=5"], capture=False
            )
            h._cmd(
                ["dd", "if=/dev/zero", f"of={f2}", "bs=1M", "count=12"], capture=False
            )

            s1 = subprocess.Popen(
                ["python3", "-m", "http.server", "8001", "--bind", host_ip1],
                cwd=td,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            s2 = subprocess.Popen(
                ["python3", "-m", "http.server", "8002", "--bind", host_ip2],
                cwd=td,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                h.wait_http(f"http://{host_ip1}:8001/", ns=ns1, timeout_s=5.0)
                h.wait_http(f"http://{host_ip2}:8002/", ns=ns2, timeout_s=5.0)

                h._cmd(
                    [
                        "ip",
                        "netns",
                        "exec",
                        ns1,
                        "curl",
                        "-sS",
                        "--max-time",
                        "10",
                        f"http://{host_ip1}:8001/a",
                        "-o",
                        "/dev/null",
                    ]
                )
                h._cmd(
                    [
                        "ip",
                        "netns",
                        "exec",
                        ns2,
                        "curl",
                        "-sS",
                        "--max-time",
                        "10",
                        f"http://{host_ip2}:8002/b",
                        "-o",
                        "/dev/null",
                    ]
                )

                b1 = h.nft_get_set_element_bytes(table, hs_set, client_ip1)
                b2 = h.nft_get_set_element_bytes(table, hs_set, client_ip2)

                assert b1 >= 5 * 1024 * 1024
                assert b2 >= 12 * 1024 * 1024
            finally:
                s1.terminate()
                s2.terminate()
                s1.wait(timeout=2)
                s2.wait(timeout=2)
    finally:
        cleanup()
