# API package

Local development:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn aigov.main:app --reload --app-dir src
```
