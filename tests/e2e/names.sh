#!/bin/bash
# e2e «имена + логи + хост»: вся цепочка доверия по сети, всё в одном контейнере.
#   церемония через сетевые логи и двух свидетелей → хост (приложение / заголовки / статика) →
#   клиент открывает rift://test.brand → takedown доходит через сплетню резолверов и не «забывается» клиентом.
set -euo pipefail
W=${W:-/tmp/rift-names}; rm -rf "$W"; mkdir -p "$W"; cd "$W"
RELAY=http://127.0.0.1:3340
RIFT=${RIFT:-riftd}; CA=${CA:-rift-ca}
declare -A PID

stop_all() { for p in "${PID[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap stop_all EXIT
fail() { echo "FAIL: $*" >&2; for f in *.log; do echo "--- $f" >&2; tail -n 8 "$f" >&2; done; exit 1; }
ok() { echo "ok: $*"; }

# up <имя> <маркер в первой строке вывода> <команда…>: запускает и ждёт, пока нода напечатает маркер.
up() {
  local name=$1 marker=$2; shift 2
  "$@" >"$name.log" 2>&1 &
  PID[$name]=$!
  for _ in $(seq 160); do grep -q "^$marker" "$name.log" 2>/dev/null && return 0; sleep 0.25; done
  fail "$name не стартовал"
}
stop() { kill "${PID[$1]}" 2>/dev/null || true; wait "${PID[$1]}" 2>/dev/null || true; }
wait_for() { # wait_for <секунд> <описание> <команда…>
  local secs=$1 what=$2; shift 2
  for _ in $(seq $((secs * 4))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done
  fail "не дождались: $what"
}
contains() { grep -qiF -- "$2" <<<"$1" || fail "$3: нет «$2» в ответе: $(head -c 300 <<<"$1")"; }
absent()   { ! grep -qiF -- "$2" <<<"$1" || fail "$3: неожиданно «$2» в ответе"; }

# ---------------------------------------------------------------- ключи и сеть
ROOT=$($CA keygen root.key); CTL=$($CA keygen control.key); ZON=$($CA keygen zone.key)
OWN=$($CA keygen owner.key); W1=$($CA keygen w1.key); W2=$($CA keygen w2.key)
APP=$($CA keygen app.key); STR=$($CA keygen stranger.key); HOST=$($RIFT --home h id)
T="--root $ROOT --witness $W1 --witness $W2 --threshold 2"

iroh-relay --dev >relay.log 2>&1 &
PID[relay]=$!
wait_for 20 "relay (порт 3340)" bash -c 'exec 3<>/dev/tcp/127.0.0.1/3340'
up w1 "Свидетель:" $RIFT --key w1.key --home w1 --relay $RELAY witness --log $CTL --log $ZON
up w2 "Свидетель:" $RIFT --key w2.key --home w2 --relay $RELAY witness --log $CTL --log $ZON
up cl "Лог:" $RIFT --key control.key --home cl --relay $RELAY log --appender $APP --witness $W1 --witness $W2
up zl "Лог:" $RIFT --key zone.key --home zl --relay $RELAY log --appender $APP --witness $W1 --witness $W2
ok "2 свидетеля, лог control, лог зоны"

# ---------------------------------------------------------------- церемония по сети
$CA control --root-key root.key --control $CTL -o control.json >/dev/null
$CA zone --control-key control.key --zone brand --owner $ZON -o zone.json >/dev/null
$CA domain --signer-key zone.key --name test.brand --owner $OWN -o domain.json >/dev/null
A() { $RIFT --key app.key --home app --relay $RELAY "$@" 2>&1; }
# Вывод — в переменную, а не в канал с grep -q: grep закрывает канал, и пишущий процесс падает на pipefail.
A_has() { local pat=$1 what=$2 out; shift 2; out=$(A "$@") || fail "$what: команда упала: $out"; contains "$out" "$pat" "$what"; }

A_has "0  (размер" "log-add зоны" log-add --log $CTL --kind zone --cert zone.json
A_has "подписей: 2" "доказательство зоны" log-proof --log $CTL --index 0 -o zone-proof.json
A_has "0  (размер" "log-add домена" log-add --log $ZON --kind domain --cert domain.json
A_has "подписей: 2" "доказательство домена" log-proof --log $ZON --index 0 -o domain-proof.json
$CA dns --owner-key owner.key --name test.brand --host $HOST --seq 1 -o dns.json >/dev/null
$CA bundle --control control.json --zone zone.json --zone-proof zone-proof.json \
  --domain domain.json --domain-proof domain-proof.json --dns dns.json -o bundle.json >/dev/null
OUT=$($CA verify --root $ROOT --witness $W1 --witness $W2 --threshold 2 --bundle bundle.json) || fail "verify цепочки"; contains "$OUT" "OK  test.brand" "verify цепочки"
ok "цепочка с доказательствами от двух свидетелей проходит проверку"

OUT=$($RIFT --key stranger.key --home st --relay $RELAY log-add --log $ZON --kind domain --cert domain.json 2>&1 || true)
contains "$OUT" "не разрешено" "посторонний добавляет в лог"
ok "посторонний ключ не может писать в лог"

# Лог переживает перезапуск; свидетели не мешают.
stop zl
up zl2 "Лог:" $RIFT --key zone.key --home zl --relay $RELAY log --appender $APP --witness $W1 --witness $W2
A_has "подписей: 2" "доказательство после перезапуска лога" log-proof --log $ZON --index 0 -o domain-proof2.json
ok "лог зоны перезапущен, доказательства выдаются"

# ---------------------------------------------------------------- резолверы
up r1 "Резолвер:" $RIFT --home r1 --relay $RELAY resolver $T
R1=$(sed -n 's/^Резолвер: //p' r1.log | head -1)
up r2 "Резолвер:" $RIFT --home r2 --relay $RELAY resolver $T --peer "$R1" --sync-secs 2
R2=$(sed -n 's/^Резолвер: //p' r2.log | head -1)
up r3 "Резолвер:" $RIFT --home r3 --relay $RELAY resolver $T      # изолированный: без соседей
R3=$(sed -n 's/^Резолвер: //p' r3.log | head -1)
RES="$R1,$R2,$R3"

get() { local home=$1 url=$2 res=$3; $RIFT --home "$home" --relay $RELAY get "$url" $T --resolver "$res" 2>&1 || true; }

# ---------------------------------------------------------------- хост: приложение за прокси
mkdir -p www dist/assets
echo '<h1>from busybox</h1>' > www/index.html
echo '<div id=root></div><script src="/assets/app.js"></script>' > dist/index.html
echo 'console.log("spa")' > dist/assets/app.js
busybox httpd -f -p 127.0.0.1:3000 -h www >httpd.log 2>&1 &
PID[httpd]=$!

host() { # host <имя> <аргументы upstream/static…>
  up "$1" "Ctrl-C" $RIFT --home h --relay $RELAY host $T --bundle bundle.json --resolver "$RES" "${@:2}"
  wait_for 20 "публикация хоста" grep -q "опубликовано: 3/3" "$1.log"
}
host h1 --upstream http://127.0.0.1:3000
OUT=$(get c rift://test.brand/ "$R2"); contains "$OUT" "from busybox" "приложение за прокси"; contains "$OUT" "200 OK" "статус приложения"
OUT=$(get c rift://test.brand/nope.txt "$R2"); contains "$OUT" "404" "404 проходит от приложения"
ok "rift://test.brand отдаёт приложение (прокси), 404 доходит до клиента"
stop h1

# ---------------------------------------------------------------- заголовки (приложение — одноразовый nc)
printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok' > resp.bin
nc -l -p 3002 -q1 < resp.bin > req.txt 2>/dev/null &
sleep 0.3
host h2 --upstream 127.0.0.1:3002
CID=$($RIFT --home c id)
get c rift://test.brand/api/me "$R2" >/dev/null
wait_for 10 "запрос дошёл до приложения" test -s req.txt
REQ=$(cat req.txt)
contains "$REQ" "rift-client-id: $CID" "Rift-Client-Id = NodeID клиента"
contains "$REQ" "host: 127.0.0.1:3002" "Host переписан на upstream"
contains "$REQ" "x-forwarded-host: test.brand" "исходное имя в X-Forwarded-Host"
ok "приложение видит настоящий NodeID клиента и правильные Host/X-Forwarded-Host"
stop h2

# ---------------------------------------------------------------- rift deploy (статика, SPA)
host h3 --static dist
OUT=$(get c rift://test.brand/cart/42 "$R2"); contains "$OUT" 'id=root' "SPA-маршрут отдаёт index.html"
OUT=$(get c rift://test.brand/assets/app.js "$R2"); contains "$OUT" 'console.log("spa")' "ассет"
OUT=$(get c rift://test.brand/missing.js "$R2"); contains "$OUT" "404" "несуществующий файл"
OUT=$(get c "rift://test.brand/../../etc/passwd" "$R2"); absent "$OUT" "root:x:" "выход из папки"
ok "rift deploy: SPA, ассеты, 404, защита от выхода из папки"

# ---------------------------------------------------------------- прокси для браузера (curl как браузер)
up px "Прокси:" $RIFT --home px --relay $RELAY proxy $T --resolver "$RES" --listen 127.0.0.1:18080
PX="-x http://127.0.0.1:18080"
OUT=$(curl -s -m 20 $PX http://test.brand.rift/cart/42 || true); contains "$OUT" "id=root" "сайт через прокси"
OUT=$(curl -s -m 20 $PX http://test.brand.rift/assets/app.js || true); contains "$OUT" 'console.log("spa")' "ассет через прокси"
CODE=$(curl -s -m 10 -o /dev/null -w '%{http_code}' $PX http://example.com/ || true)
[ "$CODE" = 403 ] || fail "прокси не должен выпускать в интернет: код $CODE"
OUT=$(curl -sS -m 10 -o /dev/null $PX https://test.brand.rift/ 2>&1 || true); contains "$OUT" "501" "HTTPS через прокси честно не поддержан"
OUT=$($RIFT --home px --relay $RELAY proxy $T --resolver "$RES" --listen 0.0.0.0:18099 2>&1 || true); contains "$OUT" "loopback" "прокси не слушает наружу"
ok "прокси: *.rift открывается, интернет закрыт (403), HTTPS — 501, не-loopback запрещён"

# ---------------------------------------------------------------- takedown и сплетня
OUT=$(get c2 rift://test.brand/ "$R2"); contains "$OUT" "id=root" "до заморозки домен открывается"

$CA notice --key root.key --freeze test.brand -o freeze.json >/dev/null
OUT=$($RIFT --home pub --relay $RELAY publish --resolver "$R1" --notice freeze.json 2>&1); contains "$OUT" "принято 1/1" "публикация заморозки на R1"

# Заморозка опубликована ТОЛЬКО на R1; R2 берёт её сплетней.
frozen_via_r2() { local out; out=$(get c3 rift://test.brand/ "$R2"); grep -qF "заморожен" <<<"$out"; }
wait_for 30 "заморозка дошла до R2 через сплетню" frozen_via_r2
ok "заморозка, опубликованная одному резолверу, дошла до соседа"

# Клиент c4 видел заморозку у R1 — и после этого не открывает домен даже через изолированный R3, который о ней не знает.
OUT=$(get c4 rift://test.brand/ "$R1"); contains "$OUT" "заморожен" "R1 с объявлением"
OUT=$(get c4 rift://test.brand/ "$R3"); contains "$OUT" "заморожен" "кэш клиента против отстающего резолвера"
test -s c4/notices.json || fail "кэш объявлений не сохранён"
ok "клиент не «забывает» заморозку: отстающий резолвер её не отменяет"

# Свежий клиент подтягивает объявления заранее, не открывая сайтов.
OUT=$($RIFT --home c5 --relay $RELAY notices $T --resolver "$R2" 2>&1); contains "$OUT" "новых: 1" "riftd notices"
OUT=$(get c5 rift://test.brand/ "$R3"); contains "$OUT" "заморожен" "объявления подтянуты заранее"
ok "riftd notices: клиент подтянул заморозку заранее"

# Прокси, поднятый ПОСЛЕ заморозки, отвечает 451 (а не 502): заморозка — это решение, а не поломка.
up px2 "Прокси:" $RIFT --home px2 --relay $RELAY proxy $T --resolver "$R2" --listen 127.0.0.1:18081
CODE=$(curl -s -m 20 -o /dev/null -w '%{http_code}' -x http://127.0.0.1:18081 http://test.brand.rift/ || true)
[ "$CODE" = 451 ] || fail "замороженный домен через прокси: ожидался 451, получено $CODE"
ok "прокси отвечает 451 на замороженный домен"

# ---------------------------------------------------------------- снятие заморозки
sleep 2   # `since` — секунды: снятие должно быть позже заморозки
$CA notice --key root.key --unfreeze test.brand -o unfreeze.json >/dev/null
OUT=$($RIFT --home pub --relay $RELAY publish --resolver "$R1" --notice unfreeze.json 2>&1); contains "$OUT" "принято 1/1" "публикация снятия на R1"
opens_via_r2() { local out; out=$(get c3 rift://test.brand/ "$R2"); grep -qF "id=root" <<<"$out"; }
wait_for 30 "снятие заморозки дошло до R2 через сплетню" opens_via_r2
ok "снятие заморозки дошло до соседа"
# Клиент c4 держит заморозку в кэше: снятие с большим временем её перекрывает, домен снова открывается.
OUT=$(get c4 rift://test.brand/ "$R1"); contains "$OUT" "id=root" "клиент со старой заморозкой в кэше после снятия"
OUT=$(get c4 rift://test.brand/ "$R3"); contains "$OUT" "id=root" "кэш с заморозкой и снятием через отставший резолвер"
ok "снятие заморозки действует и у клиента с заморозкой в кэше"
# И прокси: после снятия домен открывается (кэш имён хранит только успехи).
open_via_px2() { [ "$(curl -s -m 20 -o /dev/null -w '%{http_code}' -x http://127.0.0.1:18081 http://test.brand.rift/ || true)" = 200 ]; }
wait_for 30 "прокси открывает домен после снятия" open_via_px2
ok "прокси открывает домен после снятия заморозки"

echo "OK [names]: цепочка доверия по сети: логи, свидетели, резолверы, хост, takedown"
