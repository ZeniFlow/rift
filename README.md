# Rift

Своя оверлейная сеть поверх интернета: ноды с публичным IP строят мосты, ноды за NAT подключаются к ним.
Поверх сети работают VPN, сайты `rift://` и кошелёк. Архитектура описана в [docs/](docs/README.md).

Лицензия — AGPL-3.0.

## Статус: фаза 0

Готово: ключ ноды, соединение по NodeID через relay с переходом на прямое соединение (hole punching), `riftd ping`.

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
