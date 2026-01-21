BIN=sim
tv_file_jhash="../test_vector/test_vector1.txt"
tv_file_mhash="../test_vector/test_vector2.txt"

CFLAGS += -msse4.2
CFLAGS += -std=gnu99

all:
	ctags -R
	gcc ${CFLAGS} -o ${BIN} main.c hash.c maglev_hash.c jhash.c log.c util.c test_vector.c murmur_hash.c
	./${BIN} -f ${tv_file_jhash}
	#./${BIN} -f ${tv_file_mhash}
