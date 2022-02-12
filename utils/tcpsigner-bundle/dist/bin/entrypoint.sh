#!/bin/bash

help() {
    echo
    echo "TCPSigner bundle docker runner help"
    echo "==================================="
    echo "Use '-p' to change the port on which the manager listens."
    echo "All other options are forwarded to the TCPSigner process."
    echo "Relevant options to operation are usually -c, -d and -n."
    echo
    echo "TCPSigner help:"
    echo "==============="

    /bins/tcpsigner --help

    exit 1
}

stop() {
   killall -q manager-tcp
   killall -q tcpsigner

   exit
}

trap stop SIGTERM SIGINT SIGQUIT SIGHUP ERR

# ==========================================================
# ==========================================================
while getopts ":p:h" opt; do
    case "$opt" in
    p)
        PORT=$OPTARG 
        ;;
    h)
        help
        ;;
    esac
done
# ==========================================================
# ==========================================================

# Start the TCPSigner
/bins/tcpsigner $@ -p8888 > /bundle/tcpsigner.log 2>&1 &

# Wait for it to be up and running
sleep 2
  
# Start the manager for the TCPSigner
/bins/manager-tcp -b0.0.0.0 -p$PORT &
  
# Wait for any process to exit
wait -n
  
# Exit with status of process that exited first
exit $?
