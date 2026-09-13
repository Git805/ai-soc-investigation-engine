install:
	python -m pip install -e './backend[test]'

test:
	cd backend && pytest -q

run:
	cd backend && uvicorn app.main:app --reload

compose-up:
	docker compose up --build

compose-down:
	docker compose down
