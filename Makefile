
IMAGE_NAME:=dcso/tiffy

build:
	docker build -t $(IMAGE_NAME) -f .dockerfile/Dockerfile .

test: build
	@echo
	docker run --rm --name=tiffy $(IMAGE_NAME)
	@echo
	docker exec -ti tiffy /tiffy/venv/bin/pytest