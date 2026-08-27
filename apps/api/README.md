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
python -m aigov.cli bind <systemId> --provider aws --resource fraud-endpoint --region us-east-1
python -m aigov.cli discover <systemId>
python -m aigov.cli collect <systemId> --scenario in_sync
python -m aigov.cli enforce <systemId> --action CONTAIN
```

Gate exit codes: `0` ALLOW, `1` BLOCK, `2` REVIEW. Optional Kafka publishing requires `pip install -e ".[events]"` and `AIGOV_KAFKA_BOOTSTRAP_SERVERS`. Live cloud adapters require `AIGOV_CLOUD_ADAPTER_MODE=live` and `pip install -e ".[aws]"` / `".[azure]"` / `".[gcp]"`; without them discover/collect/enforce fail closed.
