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

Выпуск — оффлайн, на машине без сети (`rift-ca`); root-ключ там же:

```bash
rift-ca keygen root.key                       # печатает публичный ключ root
rift-ca control  --root-key root.key --control $(rift-ca keygen control.key) -o control.json
rift-ca zone     --control-key control.key --zone brand --owner $(rift-ca keygen zone.key) -o zone.json
rift-ca domain   --signer-key zone.key --name shop.brand --owner $(rift-ca keygen owner.key) -o domain.json
rift-ca dns      --owner-key owner.key --name shop.brand --host <NodeID хоста> --seq 1 -o dns.json
rift-ca bundle   --control control.json --zone zone.json --domain domain.json --dns dns.json -o bundle.json
rift-ca verify   --root <root.pub> --bundle bundle.json
```

Сеть (любая нода может быть резолвером; ему нужен только публичный root):

```bash
riftd --relay $RELAY resolver --root $ROOT                                    # печатает NodeID@relay
riftd --relay $RELAY host --root $ROOT --bundle bundle.json --upstream 127.0.0.1:3000 --resolver $RESOLVER
riftd --relay $RELAY get rift://shop.brand/ --root $ROOT --resolver $RESOLVER
rift-ca notice --key root.key --freeze shop.brand -o freeze.json              # takedown
riftd --relay $RELAY publish --resolver $RESOLVER --notice freeze.json
```
