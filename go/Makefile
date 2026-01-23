BIN=sim

all:
	go build -o ${BIN}
#	sudo ./${BIN}
	./${BIN} --ip 127.0.0.1:22 --user jiho.jung --clients 10 --cmd "hostname -i | awk '{print $1}'"
#	./${BIN} --ip 127.0.0.1:22 --user jiho.jung --clients 1 --cmd "ip -o -4 addr list eno1 | awk '{print $4}' | cut -d/ -f1"
#	go test
