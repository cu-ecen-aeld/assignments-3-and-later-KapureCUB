#!/bin/sh

case "$1" in
    # Start case -- daemon mode
    start)
        echo "Starting aesdsocket server as daemon"
        start-stop-daemon --start -n aesdsocket --startas /usr/bin/aesdsocket -- -d
        ;;
    # Stop aesdsocket 
    stop)
        echo "Stopping aesdsocket server"
        start-stop-daemon -K -n aesdsocket --signal SIGTERM
	;;
    *)
        echo "Usage: $0 {start|stop}"
    exit 1
esac
