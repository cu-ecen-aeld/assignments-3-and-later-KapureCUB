#Compiler
CROSS_COMPILE =
CC = gcc

#Enabling compiler warnings and debug info
CFLAGS = -Wall -Werror

#Target
Target = writer

all:${Target}
${Target}:${Target}.c
	${CROSS_COMPILE}${CC} ${CFLAGS} -o ${Target} ${Target}.c
clean:
	${RM} ${Target} *.o

