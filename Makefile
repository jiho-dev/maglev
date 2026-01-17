BIN=sim

all:
	ctags -R
	gcc -msse4.2 -std=gnu99 -o ${BIN} main.c hash.c maglev_hash.c jhash.c log.c util.c
	./${BIN}
