#!/bin/sh
# Run two validator seats in one rehearsal container without sharing process state.
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 FIRST_SEAT SECOND_SEAT BOOTSTRAP_HOST" >&2
    exit 2
fi

first=$1
second=$2
bootstrap_host=$3
ceremony=/home/budlum/ceremony
data=/home/budlum/data
bootstrap=$(cat "$ceremony/$bootstrap_host.bootnode")

start_seat() {
    seat=$1
    p2p_port=$2
    rpc_port=$3
    operator_port=$4
    metrics_port=$5
    budlum-core --network=testnet \
        --genesis-file="$ceremony/genesis.json" \
        --consensus=pos --role=validator \
        --validator-key-file="$ceremony/validator$seat.key" \
        --p2p-identity-file="$ceremony/validator$seat.p2p" \
        --port="$p2p_port" --db-path="$data/validator$seat/db" \
        --rpc-public-listener="127.0.0.1:$rpc_port" \
        --rpc-operator-listener="127.0.0.1:$operator_port" \
        --metrics-listener="0.0.0.0:$metrics_port" \
        --bootstrap="$bootstrap" &
}

start_seat "$first" 5001 8545 8546 9090
first_pid=$!
start_seat "$second" 5002 8555 8556 9091
second_pid=$!

status=1
shutdown() {
    status=0
    kill "$first_pid" "$second_pid" 2>/dev/null || true
}
trap shutdown TERM INT

while kill -0 "$first_pid" 2>/dev/null && kill -0 "$second_pid" 2>/dev/null; do
    sleep 1
done

# A seat exiting unexpectedly must not leave an apparently healthy container
# with only half of its genesis seats online.
kill "$first_pid" "$second_pid" 2>/dev/null || true
wait "$first_pid" || true
wait "$second_pid" || true
exit "$status"
