# API package

Local development:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn aigov.main:app --reload --app-dir src
```

Operator CLI (after `pip install -e .`):

```bash
python -m aigov.cli health
python -m aigov.cli me
python -m aigov.cli gate <systemId>
python -m aigov.cli migrate
python -m aigov.cli outbox publish
python -m aigov.cli github check <systemId> --sha <sha> --repo owner/name
```

Gate exit codes: `0` ALLOW, `1` BLOCK, `2` REVIEW. Optional Kafka publishing requires `pip install -e ".[events]"` and `AIGOV_KAFKA_BOOTSTRAP_SERVERS`.
