# OpenBao / Vault Tools

Zwei lokale Read-only-Skripte:

- `bao_inventory.py`: Inventar und Duplikate erstellen
- `bao_find_value.py`: Pfad und Key zu einem exakten Wert finden

## Einrichten

```bat
uv sync
copy .env.example .env
```

In `.env` eintragen:

```dotenv
VAULT_ADDR=https://...
VAULT_NAMESPACE=...
VAULT_TOKEN=...
```

## Inventar

```bat
uv run bao_inventory.py
```

Ergebnisse liegen in `out/`. Kurzer Testlauf:

```bat
uv run bao_inventory.py --max-secrets 30
```

## Wert suchen

```bat
set VAULT_SEARCH_VALUE=SUCHWERT
uv run bao_find_value.py
```

Mit Sub-Namespaces:

```bat
uv run bao_find_value.py --recurse-namespaces
```

Die Ausgabe zeigt Namespace, Secret-Pfad und Key.

## Probleme

- `403 permission denied`: Neues Token holen und `VAULT_TOKEN` in `.env` ersetzen.
- `VIRTUAL_ENV ... does not match`: `set VIRTUAL_ENV=` ausführen.
- TLS-Fehler: `--ca-cert PFAD` verwenden; nur zum Testen `--insecure`.

Alle Optionen: `uv run bao_inventory.py --help` beziehungsweise
`uv run bao_find_value.py --help`.
