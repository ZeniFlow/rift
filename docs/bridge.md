# Мост: маскировка трафика к relay (фаза 2, шаг 1)

Связь с relay — это TLS/WebSocket поверх TCP. Если DPI её режет, весь этот трафик заворачивается в маскирующий транспорт:

```
riftd ──HTTP CONNECT──► локальный клиент ──REALITY──► мост ──► relay
          (--proxy)       (127.0.0.1:1080)     (для DPI выглядит как
                                              TLS к www.microsoft.com)
```

Пока транспорт внешний: подойдёт любой клиент с HTTP-входом (shoes, Xray, sing-box). Ниже пример на [shoes](https://github.com/cfal/shoes) (Rust, MIT): он совместим с Xray. Встроить его в riftd — следующий шаг.

## Сервер-мост

Ключи:

```bash
shoes generate-reality-keypair   # → private_key / public_key
uuidgen                          # → user_id
openssl rand -hex 8              # → short_id
```

`bridge.yaml` — пропускает **только** до relay, иначе мост станет открытым прокси:

```yaml
- address: "0.0.0.0:443"
  protocol:
    type: tls
    reality_targets:
      "www.microsoft.com":
        private_key: "<private_key>"
        short_ids: ["<short_id>"]
        dest: "www.microsoft.com:443"   # чужой ключ / активное зондирование → настоящий сайт
        vision: true
        protocol:
          type: vless
          user_id: "<uuid>"
  rules:
    - masks: ["relay.example.com", "127.0.0.1"]
      action: allow
    - masks: ["0.0.0.0/0", "::/0"]
      action: block
```

## Клиент

`client.yaml`:

```yaml
- address: "127.0.0.1:1080"
  protocol:
    type: http
  rules:
    - masks: ["0.0.0.0/0", "::/0"]
      action: allow
      client_chain:
        address: "<IP моста>:443"
        protocol:
          type: reality
          public_key: "<public_key>"
          short_id: "<short_id>"
          sni_hostname: "www.microsoft.com"
          vision: true
          protocol:
            type: vless
            user_id: "<uuid>"
```

```bash
shoes client.yaml &
riftd --relay https://relay.example.com --proxy http://127.0.0.1:1080 vpn --peer <NodeID>
```

## Что пока утекает мимо моста

- **Прямые UDP-пути** (hole punching) идут как есть. Если UDP режут, они просто не установятся, и трафик пойдёт через relay → через мост. Это и есть автоподбор: iroh держит все пути и выбирает рабочий.
- **DNS-запрос** имени relay делается системным резолвером.
- **QUIC address discovery** к relay (UDP). Если сервер relay поднят без QUIC, этого нет.

Тест `relay_traffic_goes_through_proxy` проверяет, что подключение к relay идёт только через прокси.
