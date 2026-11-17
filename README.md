# Key Checker

Асинхронный проверщик ключей на Rust с поддержкой **двух ядер**: `xray.exe` и
`sing-box.exe`. Для каждого ключа автоматически выбирается движок, генерируется
временный JSON-конфиг, поднимается локальный SOCKS5-прокси, через него скачивается
тестовый файл, после чего процесс гарантированно останавливается, а конфиг удаляется.

## Требования

- Windows x64
- Rust stable (`cargo`)
- Оба бинарника в корне проекта (рядом с `Cargo.toml` или готовым `.exe`):
  - `xray.exe` — [Xray-core releases](https://github.com/XTLS/Xray-core/releases)
  - `sing-box.exe` — [sing-box releases](https://github.com/SagerNet/sing-box/releases)

Проверено с `Xray 26.11.9` и `sing-box 1.14.4`.

Скачайте `Xray-windows-64.zip` и `sing-box-*-windows-amd64.zip`, распакуйте и положите
`xray.exe` и `sing-box.exe` в папку проекта. При запуске готового `.exe` из другой папки
положите оба бинарника рядом с ним.

## Файлы

- `keys.txt` — входной файл (создаётся вручную)
- `alive_keys.txt` — результат: только рабочие ключи
- `xray.exe` — ядро для XHTTP / finalmask-ключей
- `sing-box.exe` — ядро для остальных ключей

## Запуск

```powershell
cargo run --release
```

или:

```powershell
cargo build --release
.\target\release\vpn-key-checker.exe
```

## Выбор ядра

| Признак в ключе                                   | Ядро       |
| ------------------------------------------------- | ---------- |
| `type=xhttp`, `type=splithttp`                     | `xray.exe` |
| параметр `fragment`                                | `xray.exe` |
| параметр `fm` (finalmask)                          | `xray.exe` |
| всё остальное: VMess, VLESS ws/grpc/tcp, Trojan, SS | `sing-box.exe` |

Для Clash/YAML те же признаки определяются по `network: xhttp` / `network: splithttp`,
`xhttp-opts`, `fragment`, `fm` и `finalmask`.

## Поддерживаемый вход

`keys.txt` может содержать в любом сочетании:

- `vmess://...` (base64 JSON и URL-формат)
- `vless://...`
- `trojan://...`
- `ss://...` (SIP002 и legacy base64)
- base64-подписки с URI-ключами
- Clash/YAML (`proxies:`) как целиком, так и вставленный блоком вместе с обычными ключами
- base64-подписки, внутри которых лежит Clash/YAML

Извлекаются: сервер, порт, UUID/пароль, метод шифрования SS, SNI, uTLS fingerprint,
Reality `publicKey`/`shortId`, `flow`, `path`, `host`, `serviceName`. Неизвестные
параметры (`packetEncoding`, `alpn`, `mode`, `extra`, `fm`, `fragment` и т. п.)
игнорируются и не ломают разбор.

Поддерживаются TLS, Reality, uTLS fingerprint, WS, gRPC, HTTP Upgrade, TCP, QUIC
(sing-box), Shadowsocks-плагины (базово). Неподдерживаемые/битые ключи пропускаются
и не попадают в результат.

## XHTTP и finalmask

Для XHTTP генерируется Xray-конфиг вида:

```json
"streamSettings": {
  "network": "xhttp",
  "security": "tls",
  "tlsSettings": { "serverName": "example.com", "fingerprint": "chrome" },
  "xhttpSettings": {
    "host": "cdn.example.com",
    "path": "/api",
    "mode": "auto",
    "extra": { "noGRPCHeader": true, "xmux": { "maxConnections": 16 } }
  }
}
```

- `type=splithttp` — алиас XHTTP.
- `extra` из ключа передаётся в `xhttpSettings.extra` как JSON-объект.
- `fm` (готовый JSON finalmask) передаётся в `streamSettings.finalmask`.
- `fragment=length,delay,packets[,maxSplit]` (например,
  `fragment=3-3,0-1,tlshello,null`) превращается в TCP-маску:

```json
"finalmask": {
  "tcp": [{
    "type": "fragment",
    "settings": { "length": "3-3", "delay": "0-1", "packets": "tlshello" }
  }]
}
```

Если заданы и `fm`, и `fragment`, приоритет у `fm`.

## Как работает проверка

1. Разбирается ключ, определяется ядро и генерируется его outbound-конфиг.
2. Из диапазона `10000..=60000` выбирается свободный локальный порт.
3. Запускается `xray.exe run -c <temp.json>` или `sing-box.exe run -c <temp.json>`
   со скрытым окном консоли (`CREATE_NO_WINDOW` / `0x08000000`).
4. Ожидание 1.5 секунды.
5. Через `socks5h://127.0.0.1:<port>` скачивается
   `https://speed.cloudflare.com/__down?bytes=200000`.
6. Ключ считается рабочим, если получено **не менее 150 КБ**.
7. Процесс ядра убивается, временный конфиг удаляется.
8. Рабочий ключ сразу дописывается в `alive_keys.txt` под мьютексом.

Параллельность — 80 ключей (`CONCURRENCY` в `src/main.rs`).
Таймаут одного запроса — 10 секунд, соединения — 6 секунд.

## Формат результата

```text
[1/1000] vless://... -> OK (Xray)
[2/1000] vmess://... -> FAIL
[3/1000] ss://...    -> OK (Sing-box)
```

URI-ключи сохраняются в исходном виде, по одной строке на ключ. Для ключей из Clash/YAML
сохраняется сам YAML-прокси в виде элемента списка:

```yaml
- name: node
  type: trojan
  server: example.com
  port: 443
  password: secret
```

## Настройки

В `src/main.rs` можно изменить:

- `CONCURRENCY` — количество одновременных проверок
- `STARTUP_DELAY` — задержку запуска ядра
- `REQUEST_TIMEOUT` — таймаут HTTP-запроса
- `PORT_MIN` / `PORT_MAX` — диапазон локальных портов

## Важно

Не запускайте проверку на огромной конкуренции без необходимости: каждый ключ создаёт
отдельный процесс выбранного ядра. Значение 80 — безопасный компромисс между скоростью
и нагрузкой на систему.
