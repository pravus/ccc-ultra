install: build
	sudo systemctl restart ccc-ultra

build:
	sudo docker build --no-cache --pull --tag ccc-ultra:latest .
