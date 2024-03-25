#!/bin/sh

case "$1" in
    # start - load aesdchar module
    start)
        echo "Loading aesdchar module"
        aesdchar_load
        ;;
    # shutdown - unload aesdchar module
    stop)
        echo "Unloading aesdchar module"
        aesdchar_unload
        ;;
    *)
        echo "Usage: $0 {start|stop}"
    exit 1
esac
