#!/usr/bin/env python3
"""Findet Keys in OpenBao/Vault, deren Wert exakt dem Suchwert entspricht."""
from __future__ import annotations

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Optional

from bao_inventory import (
    Config,
    VaultClient,
    discover_mounts,
    discover_namespaces,
    walk_paths,
)


@dataclass(frozen=True)
class Match:
    namespace: str
    mount: str
    path: str
    key: str

    @property
    def full_path(self) -> str:
        return f"{self.mount}{self.path}"


def comparable_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def search_secret(
    client: VaultClient,
    namespace: str,
    mount: str,
    kv_version: int,
    path: str,
    needle: str,
) -> tuple[list[Match], Optional[str]]:
    status, body = client.read_data(mount, kv_version, path, namespace)
    if status != 200 or not body:
        if status == 404:
            return [], None
        return [], f"[{namespace}] {mount}{path}: HTTP {status}"

    if kv_version == 2:
        data = body.get("data", {}).get("data", {}) or {}
    else:
        data = body.get("data", {}) or {}

    matches = [
        Match(namespace, mount, path, key)
        for key, value in data.items()
        if comparable_value(value) == needle
    ]
    return matches, None


def run(cfg: Config, needle: str) -> int:
    client = VaultClient(cfg)
    status, body = client.request("GET", "auth/token/lookup-self")
    if status != 200:
        errors = "; ".join(body.get("errors", [])) if body else ""
        message = f"Fehler beim Verbinden (HTTP {status}) {errors}".rstrip()
        print(message, file=sys.stderr)
        return 2

    namespaces = (
        discover_namespaces(client, cfg.namespace)
        if cfg.recurse_namespaces
        else [cfg.namespace]
    )
    tasks: list[tuple[str, str, int, str]] = []
    for namespace in namespaces:
        mounts = discover_mounts(client, namespace)
        if cfg.mounts:
            selected = {mount.rstrip("/") + "/" for mount in cfg.mounts}
            mounts = [
                (mount, version)
                for mount, version in mounts
                if mount in selected
            ]
        for mount, version in mounts:
            tasks.extend(
                (namespace, mount, version, path)
                for path in walk_paths(client, mount, version, namespace)
            )

    if not tasks:
        print("Keine lesbaren KV-Secret-Pfade gefunden.", file=sys.stderr)
        return 1

    matches: list[Match] = []
    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=cfg.workers) as executor:
        futures = {
            executor.submit(search_secret, client, *task, needle): task
            for task in tasks
        }
        for future in as_completed(futures):
            found, error = future.result()
            matches.extend(found)
            if error:
                errors.append(error)

    def sort_key(item: Match) -> tuple[str, str, str]:
        return item.namespace, item.full_path, item.key

    for match in sorted(matches, key=sort_key):
        print(
            f"Namespace: {match.namespace or '/'} | "
            f"Pfad: {match.full_path} | Key: {match.key}"
        )

    print(f"\nDurchsucht: {len(tasks)} Secrets; Treffer: {len(matches)}")
    if errors:
        print(f"Nicht lesbar/fehlerhaft: {len(errors)}", file=sys.stderr)
    return 0 if matches else 1


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Durchsucht alle KV-Secrets nach einem exakten Feldwert."
    )
    parser.add_argument(
        "value",
        nargs="?",
        help="Exakter Suchwert (sonst VAULT_SEARCH_VALUE).",
    )
    parser.add_argument("--addr", help="Vault-Adresse (sonst VAULT_ADDR).")
    parser.add_argument(
        "--namespace", help="Namespace (sonst VAULT_NAMESPACE)."
    )
    parser.add_argument("--token", help="Token (sonst VAULT_TOKEN).")
    parser.add_argument(
        "--mounts", help="Kommagetrennte Liste zu durchsuchender Mounts."
    )
    parser.add_argument(
        "--ca-cert", help="Pfad zum CA-Bundle (sonst VAULT_CACERT)."
    )
    parser.add_argument(
        "--insecure", action="store_true", help="TLS-Pruefung deaktivieren."
    )
    parser.add_argument(
        "--workers", type=int, default=8, help="Parallele Requests."
    )
    parser.add_argument(
        "--recurse-namespaces",
        action="store_true",
        help="Auch Sub-Namespaces rekursiv durchsuchen.",
    )
    args = parser.parse_args(argv)

    needle = args.value or os.environ.get("VAULT_SEARCH_VALUE")
    if needle is None:
        parser.error(
            "Suchwert fehlt: als Argument oder VAULT_SEARCH_VALUE angeben."
        )

    addr = args.addr or os.environ.get("VAULT_ADDR", "")
    token = args.token or os.environ.get("VAULT_TOKEN", "")
    if not addr or not token:
        parser.error("VAULT_ADDR und VAULT_TOKEN muessen gesetzt sein.")

    cfg = Config(
        addr=addr,
        namespace=args.namespace or os.environ.get("VAULT_NAMESPACE", ""),
        token=token,
        mounts=(
            [item.strip() for item in args.mounts.split(",")]
            if args.mounts
            else None
        ),
        ca_cert=args.ca_cert or os.environ.get("VAULT_CACERT"),
        insecure=args.insecure,
        workers=args.workers,
        recurse_namespaces=args.recurse_namespaces,
    )
    return run(cfg, needle)


if __name__ == "__main__":
    raise SystemExit(main())
