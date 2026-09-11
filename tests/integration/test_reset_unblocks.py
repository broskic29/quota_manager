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
def test_flush_drop_set_restores_connectivity():
    sfx = _suffix()
    table = f"qm_test_{sfx}"
    drop_set = "drop_users"

    ns = f"qmns_{sfx}"
    vethh = f"vh_{sfx}"
    vethn = f"vn_{sfx}"
    host_ip = "10.240.1.1"
    client_ip = "10.240.1.2"
    port = "8020"

    fw4_tag = f"qmtest-{sfx}-{vethh}"

    def cleanup():
        h.fw4_delete_tagged_rules(fw4_tag)
        h._cmd(["ip", "netns", "del", ns], check=False)
        h._cmd(["ip", "link", "del", vethh], check=False)
        h._cmd(["nft", "delete", "table", "inet", table], check=False)

    cleanup()
    try:
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
        h._cmd(["ip", "netns", "exec", ns, "ip", "route", "add", host_ip, "dev", vethn])

        h.nft_allow_local_veth_before_fw4(fw4_tag, vethh)

        h._cmd(["nft", "add", "table", "inet", table])
        h.nft_add_ipv4_set(table, drop_set)

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

        with tempfile.TemporaryDirectory() as td:
            blob = f"{td}/blob"
            h._cmd(
                ["dd", "if=/dev/zero", f"of={blob}", "bs=1M", "count=1"], capture=False
            )

            srv = subprocess.Popen(
                ["python3", "-m", "http.server", port, "--bind", host_ip],
                cwd=td,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                h.wait_http(f"http://{host_ip}:{port}/blob", ns=ns, timeout_s=5.0)

                # Drop -> fail
                h.nft_add_element(table, drop_set, client_ip)
                fail = h._cmd(
                    [
                        "ip",
                        "netns",
                        "exec",
                        ns,
                        "curl",
                        "-sS",
                        "--max-time",
                        "3",
                        f"http://{host_ip}:{port}/blob",
                        "-o",
                        "/dev/null",
                    ],
                    check=False,
                )
                assert fail.returncode != 0

                # Flush set -> ok
                h.nft_flush_set(table, drop_set)
                ok = h._cmd(
                    [
                        "ip",
                        "netns",
                        "exec",
                        ns,
                        "curl",
                        "-sS",
                        "--max-time",
                        "5",
                        f"http://{host_ip}:{port}/blob",
                        "-o",
                        "/dev/null",
                    ],
                    check=True,
                )
                assert ok.returncode == 0
            finally:
                srv.terminate()
                srv.wait(timeout=2)
    finally:
        cleanup()
