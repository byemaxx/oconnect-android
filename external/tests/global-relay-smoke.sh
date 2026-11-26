#!/system/bin/sh
set -eu
# Run under su on a Qualcomm test phone with an active reverse rmnet interface.
broker=$1
client=$2
wifi=octestwifi
target=192.0.2.241
name=oconnect-root-54a72200000000000000000000000000
test -z "$(ip -brief link show | grep -E 'octestwifi|octestvpn|ocd54a722' || :)"
if ip -4 rule show | grep -Fq "$target"; then exit 2; fi
ip link add "$wifi" type dummy
cleanup() {
    if [ -n "${broker_pid:-}" ]; then kill "$broker_pid" 2>/dev/null || :; fi
    ip link del "$wifi"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
ip addr add 192.0.2.10/24 dev "$wifi"
ip link set "$wifi" up
tc qdisc add dev "$wifi" clsact
launch() {
    "$broker" "$name" 29001 198.18.240.17/32 1300 --epdg-global \
        "$wifi" 192.0.2.10 192.0.2.53 - epdg.example.test "$target" &
    broker_pid=$!
    sleep 1
}
check_clean() {
    if ip -4 rule show | grep -Fq "$target"; then return 1; fi
    if ip -brief link show | grep -q 'ocd54a722'; then return 1; fi
    if tc filter show dev "$wifi" egress | grep -q '800::811'; then return 1; fi
}

launch
"$client" "$name" success &
client_pid=$!
sleep 1
ip -4 rule show | grep "$target"
tc filter show dev "$wifi" egress | grep '800::811'
tc filter show dev "$wifi" egress | grep '800::812'
wait "$client_pid"
wait "$broker_pid"
broker_pid=
check_clean
if tc filter show dev "$wifi" egress | grep -q '800::812'; then exit 1; fi
echo "Global descriptor, rules and close passed"

tc filter add dev "$wifi" egress protocol ip pref 19421 handle 800::812 u32 \
    match ip dst 198.51.100.70/32 action mirred egress redirect dev dummy0
launch
"$client" "$name" failure
if wait "$broker_pid"; then exit 1; fi
broker_pid=
check_clean
tc filter show dev "$wifi" egress | grep '800::812'
echo "Partial setup rolled back and existing filter preserved"
