# tests/integration/test_baseline_prevents_billing_history.py
from __future__ import annotations

import os
import platform
import subprocess
import tempfile
import time

import pytest

import quota_manager.integration_helpers as h


def _suffix() -> str:
    # keep interface names <= 15 chars and avoid collisions across tests
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
def test_login_baseline_prevents_billing_preexisting_counter_history(db_paths):
    # fixture kept for parity with your suite
    usage_db, _ = db_paths
    _ = usage_db

    sfx = _suffix()

    table = f"qm_hist_{sfx}"
    hs_set = "hs_users"

    ns = f"qmns{sfx}"
    vethh = f"vh{sfx}"
    vethn = f"vn{sfx}"

    host_ip = "10.252.1.1"
    client_ip = "10.252.1.2"
    port = _port(8050, sfx)

    fw_tag = f"qmtest-hist-{sfx}"

    def cleanup():
        h.fw4_delete_tagged_rules(fw_tag)
        h.netns_del(ns)
        h.ip_link_del(vethh)
        h.nft_delete_table(table)

    cleanup()
    try:
        # netns + veth
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

        # nft output accounting to client_ip using counters attached to set elements
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
        h._cmd(["nft", "add", "element", "inet", table, hs_set, "{", client_ip, "}"])

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

        # Make host server reachable from ns (fw4 can otherwise drop veth traffic on OpenWrt)
        h.nft_allow_local_veth_before_fw4(table, vethh)
        h.fw4_insert_allow_input(fw_tag, vethh)

        with tempfile.TemporaryDirectory() as td:
            blob_path = f"{td}/blob"
            h._cmd(
                ["dd", "if=/dev/zero", f"of={blob_path}", "bs=1M", "count=5"],
                capture=False,
            )

            srv = subprocess.Popen(
                ["python3", "-m", "http.server", port, "--bind", host_ip],
                cwd=td,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                url = f"http://{host_ip}:{port}/blob"

                # Wait until /blob is actually available from inside the namespace
                h.wait_http(url, ns=ns, timeout_s=12.0)

                # Sanity: must be 200 (this is where proxies used to trick you into 404)
                code1 = h.curl_http_code(url, ns=ns)
                assert code1 == "200", f"Expected 200 for /blob, got {code1}"

                # Pre-login traffic: download once (build counter history)
                h._cmd(
                    [
                        "ip",
                        "netns",
                        "exec",
                        ns,
                        "curl",
                        "-sS",
                        "--noproxy",
                        "*",
                        "--max-time",
                        "15",
                        url,
                        "-o",
                        "/dev/null",
                    ],
                    check=True,
                )
                baseline = h.nft_get_set_element_bytes(table, hs_set, client_ip)
                assert baseline > 0

                # "Login baseline" moment: baseline snapshot prevents billing old history.
                # Now download again; the increment should be roughly the blob size.
                h._cmd(
                    [
                        "ip",
                        "netns",
                        "exec",
                        ns,
                        "curl",
                        "-sS",
                        "--noproxy",
                        "*",
                        "--max-time",
                        "15",
                        url,
                        "-o",
                        "/dev/null",
                    ],
                    check=True,
                )
                after = h.nft_get_set_element_bytes(table, hs_set, client_ip)
                assert after > baseline

                billed = after - baseline
                assert billed > 0
                # Should be roughly one more 5MiB transfer (+ overhead). Give generous slack.
                assert billed >= 4 * 1024 * 1024
            finally:
                srv.terminate()
                try:
                    srv.wait(timeout=2)
                except Exception:
                    srv.kill()
    finally:
        cleanup()
