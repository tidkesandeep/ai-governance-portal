.PHONY: install test api web compose-up compose-down opa-test migrate

install:
	python3 -m pip install -e "apps/api[dev]"
	cd apps/web && npm install

test:
	cd apps/api && python3 -m pytest -q

api:
	cd apps/api && AIGOV_DATABASE_URL=$${AIGOV_DATABASE_URL:-sqlite+aiosqlite:///./aigov.db} python3 -m uvicorn aigov.main:app --reload --host 0.0.0.0 --port 8000

web:
	cd apps/web && NEXT_PUBLIC_API_URL=$${NEXT_PUBLIC_API_URL:-http://localhost:8000} npm run dev

migrate:
	cd apps/api && python3 -m aigov.cli migrate

compose-up:
	docker compose -f infra/local/docker-compose.yml up --build

compose-down:
	docker compose -f infra/local/docker-compose.yml down -v

opa-test:
	opa test policies/rego
