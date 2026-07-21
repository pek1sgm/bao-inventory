# OpenBao / Vault - Bestandsaufnahme

Werkzeug, um ein unübersichtliches OpenBao/Vault (KV) über die HTTP-API
auszulesen, eine **Bestandsaufnahme** zu erstellen und **exakte Duplikate**
(identische Secrets) zu finden.

OpenBao ist API-kompatibel zu HashiCorp Vault – die gleichen Endpunkte gelten.

## Was das Tool macht

1. Verbindet sich mit der Vault-API (`$VAULT_ADDR/v1/...`) im angegebenen Namespace.
2. Erkennt automatisch alle KV-Secret-Engines (Mounts) und deren Version (v1/v2).
3. Läuft **rekursiv** durch alle Pfade und liest Metadaten (Zeitstempel, Versionen).
4. Liest die Werte und speichert davon **nur gesalzene SHA-256-Hashes** – kein
   Klartext landet auf der Platte (Standard). Der Salt ist pro Lauf zufällig,
   also sind die Hashes nur intern vergleichbar und nicht per Rainbow-Table
   angreifbar.
5. Analysiert **exakte Duplikate** – identische Felder *und* Werte an mehreren
   Pfaden.
6. Schreibt die Ergebnisse nach `out/`:
   `inventory.csv`, `inventory.json`, `duplicates_exact.csv`,
   `duplicates_matrix.csv`.

Die `duplicates_matrix.csv` ist eine quadratische Matrix: alle Secret-Pfade
stehen sowohl als Zeilen- als auch als Spaltenüberschrift. Ein `X` markiert
Pfade mit identischem SHA-256-Inhalts-Hash (die Diagonale zeigt jeden Pfad auf
sich selbst). Duplikat-Cluster werden so als zusammenhängende Blöcke sichtbar.
Hinweis: Bei sehr vielen Secrets kann die Spaltenzahl das Excel-Limit von
16.384 Spalten überschreiten.

## Installation

```powershell
cd c:\code\snippets_vault\openbao
uv sync
```

> `uv sync` erstellt `.venv`, installiert die Abhängigkeiten aus
> `pyproject.toml` und schreibt `uv.lock`. `truststore` sorgt dafür, dass der
> Windows-Zertifikatsspeicher (inkl. Bosch-interner CA) genutzt wird.

## Konfiguration

Token in der Web-UI holen: oben rechts auf dein Profil → **Copy token**.

Variante A – `.env`-Datei (bequem):

```powershell
copy .env.example .env
# .env öffnen und VAULT_TOKEN eintragen
```

Variante B – Umgebungsvariablen (cmd):

```bat
set VAULT_ADDR=https://emea02-prod.rb-secrets.app.bosch.com:8200
set VAULT_NAMESPACE=hv_066ee8cc-119b-48f0-b056-f1f0872cb46c
set VAULT_TOKEN=hvs.DEIN_TOKEN
```

## Ausführen

Erst ein kleiner Testlauf (nur 30 Secrets, prüft Verbindung & Rechte):

```powershell
uv run bao_inventory.py --max-secrets 30
```

Voller Lauf:

```powershell
uv run bao_inventory.py
```

Danach `out/inventory.csv` bzw. `out/duplicates_exact.csv` öffnen.

## Nützliche Optionen

| Option | Zweck |
| --- | --- |
| `--values none` | Nur Struktur/Metadaten, Werte werden **nicht** gelesen. |
| `--values hash` | Standard: Werte als Hash (Duplikat-Erkennung ohne Klartext). |
| `--values plain` | Klartext-Export (⚠ Secrets landen in der Datei). |
| `--mounts kv,secret` | Nur bestimmte Mounts statt Auto-Erkennung. |
| `--recurse-namespaces` | Auch Sub-Namespaces einbeziehen. |
| `--max-secrets 50` | Obergrenze für schnellen Test. |
| `--workers 4` | Parallelität (Standard 8) reduzieren, um den Server zu schonen. |
| `--ca-cert PFAD` | CA-Bundle angeben (Alternative zu truststore). |
| `--insecure` | TLS-Prüfung aus – **nur** zum Testen. |

## Sicherheitshinweise

- Das Token ist kurzlebig und mächtig – nicht committen, nicht teilen.
- `.env` und `out/` sind per `.gitignore` ausgeschlossen.
- Das Tool **liest nur** (GET/LIST) und verändert **nichts** im Vault.
- Für die eigentliche Aufräum-Aktion (Löschen/Zusammenführen) später ein
  separates Skript – erst nach Review der Ergebnisse.

## Fehlerbehebung

- **403 / permission denied:** Token abgelaufen → neues Token aus der UI holen.
  Einzelne Pfade mit 403 landen mit Fehlertext in `inventory.csv`/`inventory.json`
  (fehlende Policy).
- **TLS-/Zertifikatsfehler:** `--ca-cert PFAD` angeben oder die Bosch-CA in den
  Windows-Zertifikatsspeicher legen (`truststore` nutzt ihn automatisch).
- **Sehr viele Secrets:** mit `--max-secrets` testen, `--workers` anpassen.
