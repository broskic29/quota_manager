# tests/integration/test_nft_usage_pipeline.py
from __future__ import annotations

import os
import platform
import subprocess
import tempfile

import pytest

import quota_manager.integration_helpers as h


markskip = pytest.mark.skipif  # tiny convenience


@pytest.mark.integration
@pytest.mark.integration
@markskip(
    platform.system() != "Linux",
    reason="integration tests require Linux network namespaces",
)
@markskip(os.geteuid() != 0, reason="integration tests require root")
@markskip(
    not h._has_tools("nft", "ip", "curl", "dd", "python3"),
    reason="requires nft + ip + curl + dd + python3",
)
def test_accounting_increments_and_db_pipeline_and_enforcement_and_reset(
    db_paths, monkeypatch
):
    usage_db, _ = db_paths  # fixture parity
    pid = os.getpid()

    table = f"qm_test_{pid}"
    hs_set = "hs_users"
    drop_set = "drop_users"

    ns = f"qmns_{pid}"
    veth_host = f"vethh_{pid}"
    veth_ns = f"vethn_{pid}"
    host_ip = "10.200.1.1"
    client_ip = "10.200.1.2"
    port = "8000"

    def cleanup():
        h.netns_del(ns)
        h.ip_link_del(veth_host)
        h.nft_delete_table(table)

    cleanup()
    try:
        h.ip_link_del(veth_host)
        h.netns_del(ns)

        # Create netns + veth
        h._cmd(["ip", "netns", "add", ns])
        h._cmd(
            ["ip", "link", "add", veth_host, "type", "veth", "peer", "name", veth_ns]
        )
        h._cmd(["ip", "link", "set", veth_ns, "netns", ns])

        h._cmd(["ip", "addr", "add", f"{host_ip}/24", "dev", veth_host])
        h._cmd(["ip", "link", "set", veth_host, "up"])

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
                veth_ns,
            ]
        )
        h._cmd(["ip", "netns", "exec", ns, "ip", "link", "set", veth_ns, "up"])
        h._cmd(["ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"])
        h._cmd(
            ["ip", "netns", "exec", ns, "ip", "route", "add", host_ip, "dev", veth_ns]
        )

        # nft table + sets (hs_set MUST have counter)
        h._cmd(["nft", "add", "table", "inet", table])
        h._cmd(
            [
                "nft",
                "add",
                "set",
                "inet",
                table,
                hs_set,
                "{",
                "type",
                "ipv4_addr",
                ";",
                "counter",
                ";",
                "}",
            ]
        )
        h._cmd(
            [
                "nft",
                "add",
                "set",
                "inet",
                table,
                drop_set,
                "{",
                "type",
                "ipv4_addr",
                ";",
                "}",
            ]
        )
        h._cmd(["nft", "add", "element", "inet", table, hs_set, "{", client_ip, "}"])

        # Count bytes sent TO the client (host output)
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

        # Drop responses when client in drop_set
        h._cmd(
            [
                "nft",
                "add",
                "rule",
                "inet",
                table,
                "out",
                "ip",
                "daddr",
                "@" + drop_set,
                "drop",
            ]
        )

        # Allow host INPUT from veth (server reachability)
        h.nft_allow_local_veth_before_fw4(table, veth_host)

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "blob")
            h._cmd(
                ["dd", "if=/dev/zero", f"of={path}", "bs=1M", "count=20"], capture=False
            )

            server = subprocess.Popen(
                ["python3", "-m", "http.server", port, "--bind", host_ip],
                cwd=td,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                h.wait_http(f"http://{host_ip}:{port}/blob", ns=ns, timeout_s=8.0)

                before = h.nft_get_set_elem_bytes(table, hs_set, client_ip)
                h._cmd(
                    [
                        "ip",
                        "netns",
                        "exec",
                        ns,
                        "curl",
                        "-sS",
                        "--connect-timeout",
                        "2",
                        "--max-time",
                        "20",
                        f"http://{host_ip}:{port}/blob",
                        "-o",
                        "/dev/null",
                    ],
                    check=True,
                    capture=True,
                )
                after = h.nft_get_set_elem_bytes(table, hs_set, client_ip)
                assert after > before

                # Enforce "quota" by adding to drop_set
                h._cmd(
                    [
                        "nft",
                        "add",
                        "element",
                        "inet",
                        table,
                        drop_set,
                        "{",
                        client_ip,
                        "}",
                    ]
                )
                fail = h._cmd(
                    [
                        "ip",
                        "netns",
                        "exec",
                        ns,
                        "curl",
                        "-sS",
                        "--connect-timeout",
                        "1",
                        "--max-time",
                        "2",
                        f"http://{host_ip}:{port}/blob",
                        "-o",
                        "/dev/null",
                    ],
                    check=False,
                    capture=True,
                )
                assert fail.returncode != 0

                # Reset should restore connectivity
                h._cmd(["nft", "flush", "set", "inet", table, drop_set])
                ok = h._cmd(
                    [
                        "ip",
                        "netns",
                        "exec",
                        ns,
                        "curl",
                        "-sS",
                        "--connect-timeout",
                        "2",
                        "--max-time",
                        "10",
                        f"http://{host_ip}:{port}/blob",
                        "-o",
                        "/dev/null",
                    ],
                    check=True,
                    capture=True,
                )
                assert ok.returncode == 0

            finally:
                server.terminate()
                try:
                    server.wait(timeout=1.5)
                except subprocess.TimeoutExpired:
                    server.kill()

    finally:
        cleanup()
