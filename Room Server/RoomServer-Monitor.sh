#!/bin/bash

declare -a ARGS
COUNT=$#
for ((INDEX=0; INDEX<COUNT; ++INDEX))
do
    ARG="$(printf "%q" "$1")"
    ARGS[INDEX]="$(printf "%q" "$ARG")"
    shift
done

# set to match ARGS
ROUTER_PORT=25080
INSPECTOR_PORT=11080

while true
do
    python RoomServer.py ${ARGS[*]} & main_pid="${!}" || exit 1
    current_epoch=$(date +%s)
    target_epoch=$(date -d 'today 3:30:00' +%s)
    if [[ $(( $current_epoch + 60 )) -gt $target_epoch ]]
    then
        target_epoch=$(( $target_epoch + 86400 ))
    fi
    sleep_seconds=$(( $target_epoch - $current_epoch ))
    # sleep_seconds=10  # uncomment for testing restart mechanism
    echo Monitor: Executing Command: python RoomServer.py ${ARGS[*]} ...
    ( sleep $sleep_seconds ; kill -15 "${main_pid}" || kill "${main_pid}" ) & monitor_pid="${!}"
    sleep 5
    echo Monitor: Server PID: "${main_pid}"
    echo Monitor: Monitor PID: "${monitor_pid}"
    echo Monitor: Waiting $sleep_seconds Seconds Until Restart ... 
    wait "${main_pid}"
    kill "${monitor_pid}" 2> /dev/null
    wait "${monitor_pid}"
    while netstat -antpu 2>/dev/null | grep 0.0.0.0:${INSPECTOR_PORT}
    do
        echo "Waiting 10 seconds for port ${INSPECTOR_PORT} to be freed ..."
        sleep 10
    done
    while netstat -antpu 2>/dev/null | grep 0.0.0.0:${ROUTER_PORT}
    do
        echo "Waiting 10 seconds for port ${ROUTER_PORT} to be freed ..."
        sleep 10
    done
done
