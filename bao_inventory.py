#!/usr/bin/env python3
"""OpenBao / HashiCorp Vault - Bestandsaufnahme (Inventory) Tool.

Liest rekursiv alle KV-Secrets eines Namespaces aus, erstellt eine
strukturierte Bestandsaufnahme und findet exakte Duplikate (Secrets mit
identischen Feldern und Werten).

Sicherheit:
- Secret-WERTE werden standardmaessig NICHT im Klartext gespeichert,
  sondern nur als (gesalzener) SHA-256-Hash. Der Salt wird pro Lauf
  zufaellig erzeugt und nicht persistiert -> Hashes sind nur innerhalb
  eines Laufs vergleichbar und nicht per Rainbow-Table angreifbar.
- Das Token wird nur aus der Umgebung gelesen und niemals ausgegeben.

Aufruf-Beispiel:
    set VAULT_ADDR=https://emea02-prod.rb-secrets.app.bosch.com:8200
    set VAULT_NAMESPACE=hv_066ee8cc-119b-48f0-b056-f1f0872cb46c
    set VAULT_TOKEN=hvs.xxxxxxxx
    uv run bao_inventory.py
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import secrets as _secrets
import sys
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

import requests
from requests.adapters import HTTPAdapter

try:  # urllib3 wird von requests mitgeliefert
    from urllib3.util.retry import Retry
except Exception:  # pragma: no cover
    Retry = None  # type: ignore

# Optional: Firmen-/System-Zertifikatsspeicher nutzen (praktisch bei interner CA).
# Wird nur aktiv, wenn das Paket "truststore" installiert ist.
try:
    import truststore  # type: ignore

    truststore.inject_into_ssl()
    _TRUSTSTORE = True
except Exception:
    _TRUSTSTORE = False

# Optional: .env laden, falls python-dotenv installiert ist.
try:
    from dotenv import load_dotenv  # type: ignore

    load_dotenv()
except Exception:
    pass


# --------------------------------------------------------------------------- #
# Konfiguration
# --------------------------------------------------------------------------- #
@dataclass
class Config:
    addr: str
    namespace: str
    token: str
    values_mode: str = "hash"  # none | hash | plain
    output_dir: Path = Path("out")
    mounts: Optional[list[str]] = None
    ca_cert: Optional[str] = None
    insecure: bool = False
    workers: int = 8
    max_secrets: Optional[int] = None
    recurse_namespaces: bool = False
    timeout: float = 30.0


# --------------------------------------------------------------------------- #
# Datenmodell
# --------------------------------------------------------------------------- #
@dataclass
class SecretRecord:
    namespace: str
    mount: str
    kv_version: int
    path: str
    fields: list[str] = field(default_factory=list)
    field_hashes: dict[str, str] = field(default_factory=dict)
    field_lengths: dict[str, int] = field(default_factory=dict)
    field_values: dict[str, str] = field(default_factory=dict)  # nur bei plain
    username: Optional[str] = None  # Klartext aus Feld "username"/"user"
    content_hash: str = ""
    created_time: Optional[str] = None
    updated_time: Optional[str] = None
    current_version: Optional[int] = None
    version_count: Optional[int] = None
    custom_metadata: Optional[dict[str, Any]] = None
    error: Optional[str] = None

    @property
    def full_path(self) -> str:
        return f"{self.mount}{self.path}"


# --------------------------------------------------------------------------- #
# Vault-Client
# --------------------------------------------------------------------------- #
class VaultClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.base = cfg.addr.rstrip("/") + "/v1/"
        self._local = threading.local()

    def _session(self) -> requests.Session:
        # Eine Session pro Thread (requests.Session ist nicht thread-safe fuer
        # parallele Requests ueber dieselbe Instanz).
        s = getattr(self._local, "session", None)
        if s is None:
            s = requests.Session()
            if Retry is not None:
                retry = Retry(
                    total=4,
                    backoff_factor=0.6,
                    status_forcelist=(429, 500, 502, 503, 504),
                    allowed_methods=frozenset(["GET", "LIST"]),
                    respect_retry_after_header=True,
                )
                adapter = HTTPAdapter(max_retries=retry, pool_maxsize=self.cfg.workers * 2)
                s.mount("https://", adapter)
                s.mount("http://", adapter)
            self._local.session = s
        return s

    @property
    def _verify(self):
        if self.cfg.insecure:
            return False
        if self.cfg.ca_cert:
            return self.cfg.ca_cert
        return True

    def _headers(self, namespace: Optional[str] = None) -> dict[str, str]:
        return {
            "X-Vault-Token": self.cfg.token,
            "X-Vault-Namespace": namespace if namespace is not None else self.cfg.namespace,
        }

    def request(
        self,
        method: str,
        api_path: str,
        namespace: Optional[str] = None,
        params: Optional[dict] = None,
    ) -> tuple[int, Optional[dict]]:
        url = self.base + api_path.lstrip("/")
        try:
            resp = self._session().request(
                method,
                url,
                headers=self._headers(namespace),
                params=params,
                verify=self._verify,
                timeout=self.cfg.timeout,
            )
        except requests.exceptions.SSLError as exc:
            raise SystemExit(
                "\nTLS-Zertifikatsfehler beim Verbinden mit dem Vault:\n"
                f"  {exc}\n\n"
                "Moegliche Loesungen:\n"
                "  * Bosch-CA in den Windows-Zertifikatsspeicher importieren "
                "(truststore nutzt ihn automatisch)\n"
                "  * CA-Bundle angeben:  --ca-cert C:\\pfad\\zur\\ca.pem  (oder VAULT_CACERT)\n"
                "  * NUR zum Testen:     --insecure  (deaktiviert die Pruefung)\n"
            )
        except requests.exceptions.RequestException as exc:
            return -1, {"errors": [str(exc)]}

        if resp.status_code == 200:
            try:
                return 200, resp.json()
            except ValueError:
                return 200, None
        try:
            body = resp.json()
        except ValueError:
            body = {"errors": [resp.text[:200]]}
        return resp.status_code, body

    # -- KV-spezifische Helfer ------------------------------------------------
    def list_keys(self, mount: str, kv_version: int, path: str, namespace: str) -> list[str]:
        if kv_version == 2:
            api = f"{mount}metadata/{path}"
        else:
            api = f"{mount}{path}"
        status, body = self.request("LIST", api, namespace=namespace, params={"list": "true"})
        if status == 200 and body:
            return list(body.get("data", {}).get("keys", []))
        return []

    def read_metadata(self, mount: str, path: str, namespace: str) -> tuple[int, Optional[dict]]:
        return self.request("GET", f"{mount}metadata/{path}", namespace=namespace)

    def read_data(
        self, mount: str, kv_version: int, path: str, namespace: str
    ) -> tuple[int, Optional[dict]]:
        api = f"{mount}data/{path}" if kv_version == 2 else f"{mount}{path}"
        return self.request("GET", api, namespace=namespace)


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #
def discover_mounts(client: VaultClient, namespace: str) -> list[tuple[str, int]]:
    """Liefert Liste von (mount_path, kv_version) fuer alle KV-Engines."""
    for api in ("sys/internal/ui/mounts", "sys/mounts"):
        status, body = client.request("GET", api, namespace=namespace)
        if status != 200 or not body:
            continue
        data = body.get("data", {})
        # sys/internal/ui/mounts -> data["secret"], sys/mounts -> data direkt
        secrets_map = data.get("secret", data)
        mounts: list[tuple[str, int]] = []
        for mount_path, info in secrets_map.items():
            if not isinstance(info, dict):
                continue
            mtype = info.get("type", "")
            if mtype not in ("kv", "generic"):
                continue
            options = info.get("options") or {}
            version = 2 if str(options.get("version", "1")) == "2" else 1
            mounts.append((mount_path, version))
        if mounts:
            return sorted(mounts)
    return []


def discover_namespaces(client: VaultClient, root_ns: str) -> list[str]:
    """Ermittelt rekursiv alle (Sub-)Namespaces ab root_ns."""
    found = [root_ns]
    queue = [root_ns]
    while queue:
        current = queue.pop()
        status, body = client.request(
            "LIST", "sys/namespaces", namespace=current, params={"list": "true"}
        )
        if status != 200 or not body:
            continue
        for child in body.get("data", {}).get("keys", []):
            child_ns = f"{current.rstrip('/')}/{child.rstrip('/')}"
            if child_ns not in found:
                found.append(child_ns)
                queue.append(child_ns)
    return found


def walk_paths(
    client: VaultClient, mount: str, kv_version: int, namespace: str
) -> Iterable[str]:
    """Generator, der rekursiv alle Secret-Pfade eines Mounts liefert."""
    stack = [""]
    while stack:
        prefix = stack.pop()
        for key in client.list_keys(mount, kv_version, prefix, namespace):
            full = prefix + key
            if key.endswith("/"):
                stack.append(full)
            else:
                yield full


# --------------------------------------------------------------------------- #
# Auslesen & Hashing
# --------------------------------------------------------------------------- #
class Hasher:
    def __init__(self, salt: bytes):
        self.salt = salt

    def hash(self, value: str) -> str:
        h = hashlib.sha256()
        h.update(self.salt)
        h.update(value.encode("utf-8", errors="replace"))
        return h.hexdigest()


def fetch_secret(
    client: VaultClient,
    hasher: Hasher,
    namespace: str,
    mount: str,
    kv_version: int,
    path: str,
    values_mode: str,
) -> SecretRecord:
    rec = SecretRecord(
        namespace=namespace, mount=mount, kv_version=kv_version, path=path
    )

    # Metadaten (nur KVv2) - liefert Zeitstempel & Versionshistorie.
    if kv_version == 2:
        status, body = client.read_metadata(mount, path, namespace)
        if status == 200 and body:
            md = body.get("data", {})
            rec.created_time = md.get("created_time")
            rec.updated_time = md.get("updated_time")
            rec.current_version = md.get("current_version")
            versions = md.get("versions") or {}
            rec.version_count = len(versions)
            rec.custom_metadata = md.get("custom_metadata")
        elif status == 403:
            rec.error = "keine Leserechte (metadata)"

    # Werte (fuer Feldnamen und Hash-Analyse).
    if values_mode != "none":
        status, body = client.read_data(mount, kv_version, path, namespace)
        if status == 200 and body:
            if kv_version == 2:
                data = body.get("data", {}).get("data", {}) or {}
                if rec.created_time is None:
                    meta = body.get("data", {}).get("metadata", {}) or {}
                    rec.created_time = meta.get("created_time")
                    rec.current_version = meta.get("version")
            else:
                data = body.get("data", {}) or {}

            rec.fields = sorted(data.keys())
            parts = []
            for k in rec.fields:
                v = data[k]
                v_str = v if isinstance(v, str) else json.dumps(v, sort_keys=True, ensure_ascii=False)
                vh = hasher.hash(v_str)
                rec.field_hashes[k] = vh
                rec.field_lengths[k] = len(v_str)
                if values_mode == "plain":
                    rec.field_values[k] = v_str
                parts.append(f"{k}={vh}")
            rec.content_hash = hashlib.sha256("|".join(parts).encode()).hexdigest()

            # Username im Klartext erfassen (Feld "username" bevorzugt, sonst "user").
            lower_map = {k.lower(): k for k in data}
            for cand in ("username", "user"):
                if cand in lower_map:
                    uval = data[lower_map[cand]]
                    rec.username = (
                        uval if isinstance(uval, str)
                        else json.dumps(uval, ensure_ascii=False)
                    )
                    break
        elif status == 403:
            rec.error = "keine Leserechte (data)"
        elif status not in (200, 404):
            rec.error = f"HTTP {status}"

    return rec


# --------------------------------------------------------------------------- #
# Analyse
# --------------------------------------------------------------------------- #
def analyze(records: list[SecretRecord]) -> dict[str, Any]:
    valid = [r for r in records if not r.error]

    # Exakte Duplikate: identischer Content-Hash (gleiche Felder & Werte).
    by_content: dict[str, list[SecretRecord]] = defaultdict(list)
    for r in valid:
        if r.content_hash:
            by_content[r.content_hash].append(r)
    exact_dupes = {
        h: recs for h, recs in by_content.items() if len(recs) > 1
    }

    return {
        "exact_duplicates": exact_dupes,
    }


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #
def write_reports(
    cfg: Config, records: list[SecretRecord], analysis: dict[str, Any]
) -> None:
    out = cfg.output_dir
    out.mkdir(parents=True, exist_ok=True)

    # -- inventory.json -------------------------------------------------------
    inv = []
    for r in records:
        item = {
            "namespace": r.namespace,
            "mount": r.mount,
            "kv_version": r.kv_version,
            "path": r.path,
            "full_path": r.full_path,
            "username": r.username,
            "fields": r.fields,
            "field_lengths": r.field_lengths,
            "content_hash": r.content_hash,
            "created_time": r.created_time,
            "updated_time": r.updated_time,
            "current_version": r.current_version,
            "version_count": r.version_count,
            "custom_metadata": r.custom_metadata,
            "error": r.error,
        }
        if cfg.values_mode == "hash":
            item["field_hashes"] = r.field_hashes
        if cfg.values_mode == "plain":
            item["field_values"] = r.field_values
        inv.append(item)
    (out / "inventory.json").write_text(
        json.dumps(inv, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # -- inventory.csv --------------------------------------------------------
    with (out / "inventory.csv").open("w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(
            [
                "namespace", "mount", "kv_version", "path", "username",
                "field_count", "fields", "created_time", "updated_time",
                "current_version", "version_count", "content_hash", "error",
            ]
        )
        for r in records:
            w.writerow(
                [
                    r.namespace, r.mount, r.kv_version, r.path, r.username or "",
                    len(r.fields), ", ".join(r.fields), r.created_time or "",
                    r.updated_time or "", r.current_version or "",
                    r.version_count or "", r.content_hash[:16], r.error or "",
                ]
            )

    # -- duplicates_exact.csv -------------------------------------------------
    with (out / "duplicates_exact.csv").open("w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(["content_hash", "count", "paths"])
        for h, recs in sorted(
            analysis["exact_duplicates"].items(), key=lambda kv: -len(kv[1])
        ):
            w.writerow([h[:16], len(recs), " | ".join(r.full_path for r in recs)])

    # -- duplicates_matrix.csv ------------------------------------------------
    write_matrix(out, records)


def write_matrix(out: Path, records: list[SecretRecord]) -> None:
    """Schreibt eine quadratische Duplikat-Matrix (duplicates_matrix.csv).

    Zeilen und Spalten sind identisch: jeder Secret-Pfad (full_path). Eine
    Zelle erhaelt ein "X", wenn beide Pfade denselben SHA-256-Content-Hash
    haben; die Diagonale ist damit immer gesetzt. Pfade ohne Hash (nicht
    lesbar oder Werte-Modus "none") bekommen nur ihr Diagonalkreuz.
    Die Zeilen/Spalten sind nach Duplikat-Cluster gruppiert (groesste Gruppen
    zuerst), sodass die Kreuze zusammenhaengende Bloecke bilden.
    """
    # Cluster je (nicht-leerem) Content-Hash sammeln.
    by_hash: dict[str, list[SecretRecord]] = defaultdict(list)
    for r in records:
        if r.content_hash:
            by_hash[r.content_hash].append(r)

    def sort_key(r: SecretRecord) -> tuple[int, str, str]:
        size = len(by_hash[r.content_hash]) if r.content_hash else 1
        # Leere Hashes (Fehler) ans Ende der jeweiligen Groessenklasse.
        return (-size, r.content_hash or "\uffff", r.full_path)

    ordered = sorted(records, key=sort_key)
    paths = [r.full_path for r in ordered]

    # Spaltenindizes je Hash fuer schnelle Kreuz-Bestimmung.
    cols_by_hash: dict[str, set[int]] = defaultdict(set)
    for j, r in enumerate(ordered):
        if r.content_hash:
            cols_by_hash[r.content_hash].add(j)

    with (out / "duplicates_matrix.csv").open(
        "w", newline="", encoding="utf-8-sig"
    ) as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(["path"] + paths)
        for i, r in enumerate(ordered):
            crosses = cols_by_hash[r.content_hash] if r.content_hash else {i}
            row = [paths[i]]
            row.extend("X" if j in crosses else "" for j in range(len(ordered)))
            w.writerow(row)


# --------------------------------------------------------------------------- #
# Hauptablauf
# --------------------------------------------------------------------------- #
def run(cfg: Config) -> int:
    client = VaultClient(cfg)
    hasher = Hasher(_secrets.token_bytes(16))

    # Verbindung testen (Token-Info).
    status, body = client.request("GET", "auth/token/lookup-self")
    if status == 403:
        print("Fehler: Token ungueltig oder abgelaufen (403).", file=sys.stderr)
        return 2
    if status != 200:
        detail = ""
        if body and body.get("errors"):
            detail = " - " + "; ".join(body["errors"])
        print(f"Fehler beim Verbinden (HTTP {status}){detail}", file=sys.stderr)
        return 2
    print("Verbindung ok. Token gueltig.")

    # Namespaces bestimmen.
    if cfg.recurse_namespaces:
        namespaces = discover_namespaces(client, cfg.namespace)
        print(f"Namespaces gefunden: {len(namespaces)}")
    else:
        namespaces = [cfg.namespace]

    # (namespace, mount, version, path) Aufgaben sammeln.
    tasks: list[tuple[str, str, int, str]] = []
    for ns in namespaces:
        if cfg.mounts:
            mounts = []
            for m in cfg.mounts:
                m = m if m.endswith("/") else m + "/"
                # KV-Version raten: wird beim Lesen ggf. korrigiert; Default 2.
                mounts.append((m, 2))
        else:
            mounts = discover_mounts(client, ns)
        if not mounts:
            print(f"  [{ns}] Keine KV-Mounts gefunden (oder keine Rechte).")
            continue
        print(f"  [{ns}] KV-Mounts: " + ", ".join(f"{m}(v{v})" for m, v in mounts))
        for mount, version in mounts:
            count = 0
            for path in walk_paths(client, mount, version, ns):
                tasks.append((ns, mount, version, path))
                count += 1
                if cfg.max_secrets and len(tasks) >= cfg.max_secrets:
                    break
            print(f"      {mount}: {count} Secret-Pfade")
            if cfg.max_secrets and len(tasks) >= cfg.max_secrets:
                break

    if not tasks:
        print("Keine Secrets gefunden. Nichts zu tun.")
        return 1

    print(f"\nLese {len(tasks)} Secrets (Werte-Modus: {cfg.values_mode}) …")
    records: list[SecretRecord] = []
    done = 0
    with ThreadPoolExecutor(max_workers=cfg.workers) as ex:
        futures = {
            ex.submit(
                fetch_secret, client, hasher, ns, mount, version, path, cfg.values_mode
            ): (mount, path)
            for ns, mount, version, path in tasks
        }
        for fut in as_completed(futures):
            records.append(fut.result())
            done += 1
            if done % 25 == 0 or done == len(tasks):
                print(f"  … {done}/{len(tasks)}", end="\r", flush=True)
    print()

    print("Analysiere Redundanzen …")
    analysis = analyze(records)

    print(f"Schreibe Reports nach '{cfg.output_dir}/' …")
    write_reports(cfg, records, analysis)

    print("\nFertig. Ergebnisse:")
    print(f"  - {cfg.output_dir / 'inventory.csv'}       (alle Secrets, Excel)")
    print(f"  - {cfg.output_dir / 'inventory.json'}      (vollstaendig)")
    print(f"  - {cfg.output_dir / 'duplicates_exact.csv'} (identische Secrets)")
    print(f"  - {cfg.output_dir / 'duplicates_matrix.csv'} (Duplikat-Matrix)")
    return 0


def build_config(args: argparse.Namespace) -> Config:
    addr = args.addr or os.environ.get("VAULT_ADDR", "")
    namespace = args.namespace or os.environ.get("VAULT_NAMESPACE", "")
    token = args.token or os.environ.get("VAULT_TOKEN", "")

    missing = []
    if not addr:
        missing.append("VAULT_ADDR (--addr)")
    if not token:
        missing.append("VAULT_TOKEN (--token)")
    if missing:
        raise SystemExit(
            "Fehlende Konfiguration: " + ", ".join(missing) + "\n"
            "Setze die Umgebungsvariablen oder nutze die passenden Argumente.\n"
            "Siehe README.md."
        )

    return Config(
        addr=addr,
        namespace=namespace,
        token=token,
        values_mode=args.values,
        output_dir=Path(args.output_dir),
        mounts=[m.strip() for m in args.mounts.split(",")] if args.mounts else None,
        ca_cert=args.ca_cert or os.environ.get("VAULT_CACERT"),
        insecure=args.insecure,
        workers=args.workers,
        max_secrets=args.max_secrets,
        recurse_namespaces=args.recurse_namespaces,
    )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="OpenBao/Vault Bestandsaufnahme & Redundanz-Analyse.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--addr", help="Vault-Adresse (sonst VAULT_ADDR).")
    parser.add_argument("--namespace", help="Namespace (sonst VAULT_NAMESPACE).")
    parser.add_argument("--token", help="Token (sonst VAULT_TOKEN). Besser per Umgebung!")
    parser.add_argument(
        "--values",
        choices=["none", "hash", "plain"],
        default="hash",
        help="none=nur Struktur, hash=Werte als Hash (sicher), plain=Klartext-Export.",
    )
    parser.add_argument("--output-dir", default="out", help="Zielordner fuer Reports.")
    parser.add_argument(
        "--mounts",
        help="Kommagetrennte Mount-Liste (sonst automatische Erkennung).",
    )
    parser.add_argument("--ca-cert", help="Pfad zu CA-Bundle (sonst VAULT_CACERT).")
    parser.add_argument(
        "--insecure", action="store_true", help="TLS-Pruefung deaktivieren (nur Test!)."
    )
    parser.add_argument("--workers", type=int, default=8, help="Parallele Requests.")
    parser.add_argument(
        "--max-secrets", type=int, help="Obergrenze (z. B. 50) fuer einen schnellen Testlauf."
    )
    parser.add_argument(
        "--recurse-namespaces",
        action="store_true",
        help="Auch Sub-Namespaces rekursiv einbeziehen.",
    )
    args = parser.parse_args(argv)

    if args.values == "plain":
        print(
            "WARNUNG: --values plain schreibt Secrets im KLARTEXT in die Reports.\n"
            "         Stelle sicher, dass der Ordner geschuetzt ist.\n",
            file=sys.stderr,
        )

    cfg = build_config(args)
    try:
        return run(cfg)
    except KeyboardInterrupt:
        print("\nAbgebrochen.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
