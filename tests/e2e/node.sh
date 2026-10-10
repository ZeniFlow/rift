#!/bin/sh
# node.sh <я> <пир>: публикует свой NodeID в /shared, ждёт NodeID пира, поднимает VPN.
# GATEWAY — роутер с NAT, RELAY — адрес relay, RIFT_RELAY_CA — CA relay (сценарий nat).
set -e
[ -n "$GATEWAY" ] && ip route replace default via "$GATEWAY"
[ -n "$RIFT_RELAY_CA" ] && while [ ! -s "$RIFT_RELAY_CA" ]; do sleep 0.2; done
riftd --home /data id > "/shared/$1.id"
while [ ! -s "/shared/$2.id" ]; do sleep 0.2; done
exec riftd --home /data --relay "${RELAY:-http://relay:3340}" vpn --peer "$(cat "/shared/$2.id")"
