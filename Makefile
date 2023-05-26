install: build
	sudo systemctl restart ccc-uiltra

build:
	sudo docker build --no-cache --pull --tag ccc-uiltra:latest
