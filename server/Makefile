#Compiler
CC ?= $(CROSS_COMPILE)gcc

#Enabling compiler warnings and debug info
CFLAGS = -g -Wall -Werror -pthread

#Target
Target = aesdsocket

#default
default:${Target}

#all
all:${Target}
${Target}:${Target}.c
	${CC} ${CFLAGS} -o ${Target} ${Target}.c -lrt 
clean:
	${RM} ${Target} *.o


