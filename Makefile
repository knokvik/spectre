.PHONY: build up down logs restart clean

build:
	docker-compose build

up:
	docker-compose up -d

down:
	docker-compose down

logs:
	docker-compose logs -f

restart: down up

clean:
	docker-compose down -v
