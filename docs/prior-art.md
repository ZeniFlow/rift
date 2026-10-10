# Что уже есть

То, что описано в идее (публичные ноды-мосты + ноды за NAT + VPN поверх), уже частично существует.
Это хорошо: берём куски, не тратим год на транспорт.

| Проект | Что делает | Что берём |
|---|---|---|
| **iroh** (Rust) | QUIC-соединения по ключу ноды, hole punching, relay-серверы при неудаче | Почти готовый слой 0: ровно «публичные relay + NAT-ноды». Кандидат №1 на основу |
| **libp2p** (Go/Rust/JS) | Модульный P2P-стек: транспорты, Kademlia DHT, relay v2, DCUtR (hole punch) | Альтернатива iroh, тяжелее, но больше готового (DHT, pubsub) |
| **Tailscale** (DERP) | Mesh-VPN, WireGuard, relay при неудаче P2P | UX эталон для mesh-VPN; схема DERP |
| **Nebula** (Slack) | Mesh-VPN с собственным CA: ноды доверяют сертификатам, выданным CA | Очень близко к нашей модели root → сертификаты нод |
| **ZeroTier** | Виртуальная L2-сеть, планеты/луны (свои корневые серверы) | Идея «свои root-серверы» = наша control-федерация |
| **Yggdrasil / cjdns** | IPv6-адрес выводится из ключа, mesh-маршрутизация | Адресация `fd…` из ключа |
| **WireGuard / boringtun / wireguard-go** | VPN-туннель, Noise IK | Крипта и TUN-часть для VPN |
| **Certificate Transparency, Sigsum, Trillian** | Append-only Merkle-логи, witness'ы | Логи для trust.md §2 |
| **TUF** | Ротация и пороговые root-ключи для обновлений | Схема root-ключей, и заодно — безопасные автообновления приложения |
| **ENS / Handshake / Namecoin** | Децентрализованные имена | Что делать *не* надо: аукционы и блокчейн ради DNS. У нас есть control — проще |
| **Lightning, payment channels** | Офф-чейн микроплатежи | Модель «чеков» за VPN |
| **Mysterium, Sentinel, Orchid** | Децентрализованный платный VPN с токеном | Как они решают оплату exit-нод и почему у них мало пользователей |
| **Xray REALITY, Hysteria2** | Маскировка трафика: TLS под чужой сайт; QUIC под HTTP/3 | Fallback-транспорт и анти-DPI (architecture.md §4.4) |
| **Tor bridges** | Непубличные входы, адреса раздаются по одному | Мосты при блокировке relay по IP |
| **FROST** (frost-ed25519, ZF) | Пороговые Ed25519-подписи | Control-ключ 2-из-3 (trust.md §1) |
| **cloudflared tunnel, ngrok** | Выставить localhost-приложение наружу через туннель | Модель `rift host --upstream` (architecture.md §6) |
| **Tor, I2P** | Анонимная оверлей-сеть, свои домены (`.onion`, `.i2p`) | Опыт с exit-нодами и злоупотреблениями |
