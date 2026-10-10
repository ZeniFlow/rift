# Rift

Своя оверлейная сеть поверх интернета: ноды с публичным IP строят мосты, ноды за NAT подключаются к ним.
Поверх сети работают VPN, сайты `rift://` и кошелёк. Архитектура описана в [docs/](docs/README.md).

Лицензия — AGPL-3.0.

## Статус: фаза 3 (идёт)

- Фаза 0: ключ ноды, соединение по NodeID через relay с переходом на прямое (hole punching), `riftd ping`. Проверено в e2e: ноды за разными NAT.
- Фаза 1: mesh-VPN `riftd vpn`. Устройства за NAT видят друг друга по IPv6 `fd72:…`, ноды в LAN находят друг друга через mDNS. Проверено в e2e: ping6 и TCP через туннель.
- Фаза 2 (начата): `--proxy` — трафик к relay через маскирующий транспорт, см. [docs/bridge.md](docs/bridge.md).
- Фаза 3 (идёт): доверие и имена. `rift-trust` (цепочка root → control → зона → регистратор → домен, проверка оффлайн), `rift-ca` (оффлайн-выпуск), `riftd resolver / host / publish / get`. Сайт открывается при выключенном control.

## Сборка

```bash
cargo build --release
```

## Запуск

Relay (на сервере с публичным IP; `--dev` — без TLS, для тестов):

```bash
cargo install iroh-relay --features server
iroh-relay --dev                      # слушает :3340
```

Нода A:

```bash
riftd --relay http://RELAY:3340 listen
```

Нода B (выводит RTT и путь: «через relay» или «напрямую»):

```bash
riftd --relay http://RELAY:3340 ping <NodeID ноды A>
```

Свои relay с собственным CA (без Let's Encrypt): `--relay-ca ca.pem`, тогда нода доверяет только этому CA.

Ключ ноды лежит в `~/.rift/key`. Каталог меняется через `--home` или `RIFT_HOME`, relay задаётся через `RIFT_RELAY`.
Без `--relay` используются публичные relay n0 (только для разработки).

## Mesh-VPN

Нужны права root. `--home` указывается явно, чтобы под sudo использовался твой ключ, а не ключ root:

```bash
riftd id                                         # узнать свой NodeID
sudo riftd --home ~/.rift --relay http://RELAY:3340 vpn --peer <NodeID другой ноды>
```

То же самое запускается на второй ноде, с первой нодой в `--peer`. Адреса обеих нод выводятся при старте, дальше обычные `ping6 fd72:…` и `ssh user@fd72:…`.

## Тесты

```bash
cargo test                  # юнит-тесты
tests/e2e/run.sh flat       # e2e в Docker: две ноды в разных сетях, VPN через relay
tests/e2e/run.sh nat        # e2e: ноды за NAT-роутерами, проверка пробития NAT
```

## Имена и сайты (фаза 3)

Выпуск — оффлайн, на машине без сети (`rift-ca`); root-ключ там же. Каждый выданный сертификат зоны/домена
записывается в лог выпустившего и подтверждается свидетелями (подробнее: [docs/trust.md](docs/trust.md) §3):

```bash
# ключи
ROOT=$(rift-ca keygen root.key); CTL=$(rift-ca keygen control.key); ZON=$(rift-ca keygen zone.key)
OWN=$(rift-ca keygen owner.key); W1=$(rift-ca keygen w1.key); W2=$(rift-ca keygen w2.key)

# root → control → зона (зона записывается в лог control)
rift-ca control --root-key root.key --control $CTL -o control.json
rift-ca zone --control-key control.key --zone brand --owner $ZON -o zone.json
rift-ca log-add --log control-log.json --kind zone --cert zone.json              # индекс записи
rift-ca log-head --log control-log.json --key control.key -o ch1.json            # подписанная голова лога
rift-ca cosign --witness-key w1.key --state w1.state --log control-log.json --head ch1.json -o ch1.w1
rift-ca cosign --witness-key w2.key --state w2.state --log control-log.json --head ch1.json -o ch1.w2
rift-ca log-prove --log control-log.json --index 0 --head ch1.json --cosig ch1.w1 --cosig ch1.w2 -o zone-proof.json

# зона → домен (домен записывается в лог владельца зоны), владелец домена → записи
rift-ca domain --signer-key zone.key --name shop.brand --owner $OWN -o domain.json
rift-ca log-add --log zone-log.json --kind domain --cert domain.json
rift-ca log-head --log zone-log.json --key zone.key -o zh1.json
#   …cosign обоими свидетелями и log-prove --out domain-proof.json — как выше
rift-ca dns --owner-key owner.key --name shop.brand --host <NodeID хоста> --seq 1 -o dns.json

rift-ca bundle --control control.json --zone zone.json --zone-proof zone-proof.json \
  --domain domain.json --domain-proof domain-proof.json --dns dns.json -o bundle.json
rift-ca verify --root $ROOT --witness $W1 --witness $W2 --threshold 2 --bundle bundle.json
```

Свидетель сам проверяет, что новая голова честно продолжает виденное, и отказывается подписывать
переписанную историю и «раздвоение» (два разных корня одного размера).

Сеть (любая нода может быть резолвером; ему нужны только публичные root и свидетели):

```bash
T="--root $ROOT --witness $W1 --witness $W2 --threshold 2"
riftd --relay $RELAY resolver $T                                        # печатает NodeID@relay
riftd --relay $RELAY host $T --bundle bundle.json --upstream 127.0.0.1:3000 --resolver $RESOLVER
riftd --relay $RELAY get rift://shop.brand/ $T --resolver $RESOLVER
rift-ca notice --key root.key --freeze shop.brand -o freeze.json        # takedown (control: + --control-cert control.json)
riftd --relay $RELAY publish --resolver $RESOLVER --notice freeze.json
```

`--threshold 0` отключает проверку свидетелей (только для отладки: защиты от выпуска задним числом нет).
