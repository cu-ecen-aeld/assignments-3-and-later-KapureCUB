#Compiler
CROSS_COMPILE =
CC = gcc

#Enabling compiler warnings and debug info
CFLAGS = -Wall -Werror

#Target
Target = aesdsocket

#default
default:${Target}

#all
all:${Target}
${Target}:${Target}.c
	${CROSS_COMPILE}${CC} ${CFLAGS} -o ${Target} ${Target}.c
clean:
	${RM} ${Target} *.o


