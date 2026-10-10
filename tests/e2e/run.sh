#!/bin/sh
# e2e mesh-VPN. Сценарии:
#   flat — ноды в разных сетях, связь только через relay
#   nat  — каждая нода за своим NAT-роутером; ждём пробития NAT (прямой путь)
set -eu
cd "$(dirname "$0")"
SCENARIO=${1:-flat}
FILE=compose.yaml; [ "$SCENARIO" = nat ] && FILE=compose.nat.yaml
dc() { docker compose -p "rift-e2e-$SCENARIO" -f "$FILE" "$@"; }
trap 'dc logs --no-color > "e2e-$SCENARIO.log" 2>&1; dc down -v >/dev/null 2>&1' EXIT

dc build -q
dc up -d
vpn_addr() { dc logs "$1" 2>/dev/null | sed -n 's/^.*VPN: *\(fd72[0-9a-f:]*\).*$/\1/p' | head -1; }
for i in $(seq 60); do
  A=$(vpn_addr a); B=$(vpn_addr b)
  [ -n "$A" ] && [ -n "$B" ] && break; sleep 1
done
[ -n "$A" ] && [ -n "$B" ] || { echo "FAIL: VPN не поднялся (a='$A' b='$B')"; exit 1; }
echo "[$SCENARIO] b = $B"

dc exec -T a ping -6 -c 5 -W 5 "$B" || { echo "FAIL: ping6"; exit 1; }

dc exec -dT b sh -c 'echo rift-ok | nc -6 -l -N -p 7000'
sleep 1
GOT=$(dc exec -T a sh -c "nc -6 -w 5 $B 7000 </dev/null")
[ "$GOT" = "rift-ok" ] || { echo "FAIL: tcp, получено '$GOT'"; exit 1; }

if [ "$SCENARIO" = nat ]; then
  # Отдельная нода за NAT a пингует b по NodeID: путь должен стать прямым (NAT пробит).
  # Пробитие занимает несколько секунд после старта — даём до 3 попыток.
  for try in 1 2 3; do
    PATHS=$(dc exec -T a sh -c 'riftd --home /tmp/p --relay "$RELAY" ping "$(cat /shared/b.id)" -c 6')
    echo "$PATHS" | tail -2
    echo "$PATHS" | tail -1 | grep -q "напрямую" && break
    [ "$try" = 3 ] && { echo "FAIL: NAT не пробит, остались на relay"; exit 1; }
  done
fi
echo "OK [$SCENARIO]: ping6 и TCP через mesh-VPN"
