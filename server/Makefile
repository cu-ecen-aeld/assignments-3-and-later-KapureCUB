#Compiler
CC ?= $(CROSS_COMPILE)gcc

#Enabling compiler warnings and debug info
CFLAGS = -g -pthread

#Target
Target = aesdsocket

#default
default:${Target}

#all
all:${Target}
${Target}:${Target}.c
	 ${CC} ${CFLAGS} $(LDFLAGS) -o ${Target} ${Target}.c -lrt 
clean:
	${RM} ${Target} *.o


