
all: build run

build:
	docker build --tag ${CTR} .

run:
	docker run ${CTR}

shell:
	docker run -i -t ${CTR} bash
