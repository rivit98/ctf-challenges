.PHONY: run healthcheck

ARGS?=

run:
	docker compose --profile enabled up -d

run-rebuild:
	docker compose --profile enabled up -d --build --force-recreate

healthcheck:
	docker build -t healthcheck-challs -f healthcheck.Dockerfile .
	docker run -it --rm -v $(shell pwd):/w -w /w --network=host healthcheck-challs python3 healthcheck.py $(ARGS)

