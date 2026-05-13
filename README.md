"# WireGuard-OE (Obfuscated Edition)

> **WireGuard-OE** — форк [AmneziaWG 2.0](https://github.com/amnezia-vpn/amneziawg-go) с полной модульной обфускацией, vanilla fallback, активной защитой от probing и WebSocket обходом.

## Оглавление
- [Фичи](#фичи)
- [Режимы обфускации](#режимы-обфускации)
- [Быстрый старт](#быстрый-старт)
- [Структура репозитория](#структура-репозитория)
- [Сборка](#сборка)
- [Документация](#документация)
- [Лицензия](#лицензия)

## Фичи

- **5 модульных режимов обфускации**: vanilla → light → balanced → maximum → auto
- **Pure userspace**: работает на Linux, Windows, Android без kernel-модуля
- **Vanilla fallback**: режим 0 полностью совместим со стандартным WireGuard
- **TLS 1.3 mimicry**: Handshake маскируется под TLS ClientHello
- **QUIC data channel**: Data-пакеты маскируются под QUIC short header
- **Active probing protection**: cookie-based защита от DPI probing
- **WebSocket over TLS over TCP**: режим 3 для обхода HTTP-прокси
- **Windows .exe + NSIS installer**: клиент с UI в системном трее
- **Android APK**: split-tunneling, always-on, kill switch

## Режимы обфускации

```
┌─────────────────────────────────────────────┐
│  Режим 0: vanilla   — чистый WireGuard     │
│  Режим 1: light     — только padding       │
│  Режим 2: balanced  — TLS mimicry + pad    │  ← ОСНОВНОЙ
│  Режим 3: maximum   — +WebSocket fallback  │
│  Режим 4: auto      — режим 2 с детектом   │
│                       блокировки → режим 3 │
└─────────────────────────────────────────────┘
```

## Быстрый старт

### Linux Server
```bash
git clone https://github.com/kernelpanic700/wireguard-oe
cd wireguard-oe
make build-server
sudo ./bin/wireguard-oe-server --config config.yaml
```

### Windows Client
```bash
# Coming soon (Неделя 9)
```

### Android Client
```bash
cd client-android
./gradlew assembleRelease
```

## Структура репозитория

```
wireguard-oe/
├── common/          # Общая библиотека обфускации (Go)
├── server/          # Linux userspace daemon + optional kernel patch
├── client-windows/  # Windows client (Go + NSIS installer)
├── client-android/  # Android client (Kotlin + JNI)
├── docs/            # Документация
├── scripts/         # Сборка + DPI эмулятор
└── test/            # Интеграционные тесты
```

Подробнее: [PLAN.md](PLAN.md), [ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Документация

- [Архитектура](docs/ARCHITECTURE.md)
- [Спецификация обфускации](docs/OBFUSCATION_SPEC.md)
- [DPI тестирование](docs/DPI_TESTING.md)
- [Сборка сервера](docs/BUILD_SERVER.md)
- [Сборка Windows](docs/BUILD_WINDOWS.md)
- [Сборка Android](docs/BUILD_ANDROID.md)
- [Безопасность](docs/SECURITY.md)

## Лицензия

WireGuard-OE распространяется под лицензией GNU General Public License v2.0 (GPLv2), как и оригинальный WireGuard.

См. файл [LICENSE](LICENSE).
"