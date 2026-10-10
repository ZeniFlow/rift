# Rift

Своя оверлейная сеть поверх интернета: ноды с публичным IP строят мосты, ноды за NAT подключаются к ним.
Поверх сети работают VPN, сайты `rift://` и кошелёк. Архитектура описана в [docs/](docs/README.md).

Лицензия — AGPL-3.0.

## Статус: фаза 2

- Фаза 0: ключ ноды, соединение по NodeID через relay с переходом на прямое (hole punching), `riftd ping`.
- Фаза 1: mesh-VPN `riftd vpn`. Устройства за NAT видят друг друга по IPv6 `fd72:…`, ноды в LAN находят друг друга через mDNS.
- Фаза 2 (начата): `--proxy` — трафик к relay через маскирующий транспорт, см. [docs/bridge.md](docs/bridge.md).

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

Ключ ноды лежит в `~/.rift/key`. Каталог меняется через `--home` или `RIFT_HOME`, relay задаётся через `RIFT_RELAY`.
Без `--relay` используются публичные relay n0 (только для разработки).

## Mesh-VPN

Нужны права root. `--home` указывается явно, чтобы под sudo использовался твой ключ, а не ключ root:

```bash
riftd id                                         # узнать свой NodeID
sudo riftd --home ~/.rift --relay http://RELAY:3340 vpn --peer <NodeID другой ноды>
```

То же самое запускается на второй ноде, с первой нодой в `--peer`. Адреса обеих нод выводятся при старте, дальше обычные `ping6 fd72:…` и `ssh user@fd72:…`.
