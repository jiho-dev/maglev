BIN=sim
tv_file="../test_vector/test_vector1.txt"

all:
	ctags -R
	gcc -msse4.2 -std=gnu99 -o ${BIN} main.c hash.c maglev_hash.c jhash.c log.c util.c test_vector.c
	./${BIN} -f ${tv_file}
