# WireGuard-OE (Obfuscated Edition) — Технический План

> **Revision:** 1.2
> **Date:** 2025-07-11
> **Status:** Final — Утверждён к исполнению. Fork AmneziaWG 2.0-based approach, pure userspace

---

## 1. Executive Summary

**WireGuard-OE** — форк WireGuard с полной обфускацией трафика, предназначенный для надёжной работы в сетях с глубокой инспекцией пакетов (DPI), включая системы Роскомнадзора, Great Firewall of China, и enterprise-решения (Palo Alto, Fortinet, Cisco Umbrella).

Проект основан на форке и улучшении **AmneziaWG 2.0** (amneziawg-go + amneziawg-windows + amneziawg-android) — наиболее зрелого open-source решения с обфускацией WireGuard. Поверх AmneziaWG мы добавляем: модульные режимы обфускации, полноценный vanilla fallback (режим 0), active probing protection и WebSocket fallback. Основной режим — модифицированный WireGuard handshake с имитацией TLS 1.3 + variable-length padding + случайный junk в пакетах данных, с возможностью полного отключения обфускации до vanilla WireGuard (далее — «режим совместимости»).

**Ключевые характеристики:**
- **Основа:** Форк AmneziaWG 2.0 (amneziawg-go, amneziawg-windows, amneziawg-android)
- **Подход:** Pure userspace (wireguard-go / amneziawg-go) для всех платформ; kernel module — optional/advanced
- **Stealth:** 8.5/10 против современных DPI (ТСПУ РКН, GFW, Sandvine, Palo Alto)
- **Производительность:** overhead 8–15% в режиме balanced (в зависимости от уровня padding) по сравнению с vanilla WireGuard
- **Совместимость:** полный fallback к стандартному WireGuard (режим 0)
- **Модульность:** 5 выбираемых режимов обфускации (vanilla → max)
- **Поддержка платформ:** Linux server (userspace daemon + optional kernel module), Windows client (.exe с установщиком), Android client (.apk с split-tunneling и Always-on)
- **Язык:** Go (userspace, все платформы), Kotlin/Java (Android UI), C (kernel module, опционально)

---

## 2. Стратегия обфускации — Детальный анализ

### 2.1. Три рассмотренных варианта

#### Вариант A: «Лёгкий» — Padding + Random Jitter
- Добавление случайного padding (32–256 байт) к каждому пакету
- Случайные задержки между пакетами (5–50 мс)
- XOR первого байта с фиксированным ключом

| Параметр | Оценка |
|----------|--------|
| **Плюсы:** | Минимальные изменения кода (~500 строк), низкий overhead |
| **Минусы:** | Энтропийный анализ детектит ядро WireGuard за минуты; нет защиты от активного probing |
| **Примеры:** | wg-obfs (наивный XOR), Mullvad LWO (базовый уровень) |
| **Stealth:** | 3/10 |

#### Вариант B: «Средний» — AmneziaWG-style Handshake Obfuscation + Padding (ВЫБРАН)
- Модифицированный WireGuard handshake: первые байты заменены на имитацию TLS 1.3 ClientHello / HTTPS / DNS / SSH
- Data-пакеты: variable-length padding + random junk в начале/конце + QUIC short-header mimicry
- uTLS для реалистичных JA3 fingerprints (Chrome, Firefox, Safari)
- **База:** AmneziaWG 2.0 (H1–H4 handshake modes, I1–I5 intermediate modes, junk packets)
- **Наши улучшения поверх:**
  - Модульные режимы с возможностью полного vanilla fallback
  - Active probing protection (cookie-based)
  - WebSocket fallback опционально (Режим 3)
  - Общая обфускационная библиотека (common/), переиспользуемая на всех платформах
  - Быстрая смена сессионных ключей (rehandshake каждые 60–120 с)

| Параметр | Оценка |
|----------|--------|
| **Плюсы:** | Хороший stealth (8/10), сохраняет UDP, умеренный объём кода (~3000 строк) |
| **Минусы:** | Требует библиотеки uTLS, fingerprint-ы со временем устаревают |
| **Stealth:** | 8/10 |

#### Вариант C: «Максимальный» — Full Protocol Camouflage + TCP/TLS/WS
- Полная инкапсуляция в WebSocket поверх TLS 1.3 поверх TCP
- Динамическая смена TLS fingerprint-ов
- Активная защита от probing (honeypot packets)
- TCP fallback с предотвращением TCP-over-TCP meltdown

| Параметр | Оценка |
|----------|--------|
| **Плюсы:** | Максимальный stealth (9.5/10), проходит через HTTP-прокси |
| **Минусы:** | Сложность реализации (8000+ строк кода), TCP-over-TCP проблемы, высокий overhead (>15%) |
| **Примеры:** | WireGuard over Shadowsocks + v2ray, sing-box wg + WebSocket |
| **Stealth:** | 9.5/10 |
| **Примечание:** | Может быть добавлен как Режим 3 (maximum) в будущих версиях |

---

### 2.2. Выбранная стратегия: Форк AmneziaWG 2.0 + наши улучшения

**Основной режим — модифицированный WireGuard handshake + junk/padding/randomization** (на базе AmneziaWG, с модульными улучшениями).

> **Почему форк AmneziaWG 2.0, а не написание с нуля?**
> AmneziaWG 2.0 уже открыт (репозитории amneziawg-go, amneziawg-windows, amneziawg-android на GitHub, активная разработка 2024–2025). Это отличная база, которую мы **форкаем и улучшаем**. Проблемы оригинала, которые мы решаем:
> - **Нет модульности режимов:** В оригинале обфускация либо включена, либо нет. Мы добавляем 5 градаций (vanilla → max) с тонкой настройкой
> - **Нет vanilla fallback:** Режим 0 в нашем форке — полная совместимость со стандартным WireGuard
> - **Нет защиты от активного probing:** Мы добавляем cookie-based механизм + случайные ответы на probing-пакеты
> - **Нет WebSocket fallback:** Мы добавляем опциональный режим 3 для работы через HTTP-прокси и TCP 443
> - **Нет общей библиотеки обфускации:** Мы выделяем common/ модуль, переиспользуемый на Linux, Windows, Android
> - **Слабая документация:** Мы пишем полный комплект (ARCHITECTURE, OBFUSCATION_SPEC, DPI_TESTING, BUILD-инструкции)
>
> WireGuard-OE = AmneziaWG 2.0 + модульные режимы + vanilla fallback + активная защита от probing + документация.

**Дополнительно изученные решения:**

1. **Mullvad LWO (Lightweight WireGuard Obfuscation):**
   - Разработан Mullvad VPN в 2024–2025 для обхода блокировок в РФ и Китае
   - Использует минимальную обфускацию: XOR + padding + random timing
   - **Плюсы:** Простота, официальная поддержка Mullvad, открытый код
   - **Минусы:** Stealth 4–5/10, легко детектится ML-классификаторами (энтропийный анализ), нет защиты от probing
   - **Вывод:** Слишком слабый для наших целей; может быть реализован как наш Режим 1 (light)

2. **WireGuard over Shadowsocks / QUIC:**
   - Инкапсуляция WireGuard трафика в Shadowsocks или QUIC тунель (используется в sing-box, v2ray, Xray)
   - **Плюсы:** Stealth 8–9/10 (Shadowsocks маскируется под HTTPS), зрелые протоколы
   - **Минусы:** Двойная инкапсуляция (TCP-over-TCP meltdown для SS), высокий overhead (>20%), сложная настройка
   - **Вывод:** Решение уровня нашего Режима 3 (maximum); может быть добавлено позже как бэкенд для WebSocket fallback

3. **AmneziaWG 2.0 (наша основа):**
   - **Stealth:** 7.5/10 против РКН, 6/10 против GFW
   - **Режимы обфускации:** H1–H4 (handshake: HTTPS, DNS, SSH, random), I1–I5 (intermediate: padding, timing)
   - **Актуальный статус (июль 2025):** Активная разработка, репозитории на GitHub, поддержка Linux/Windows/Android
   - **Почему форк, а не контрибьют:** Наши изменения слишком радикальны (модульные режимы, vanilla fallback, probing protection, общая библиотека) — это отдельный проект поверх AmneziaWG, а не патч

**Итоговый выбор:** Форк AmneziaWG 2.0 как основа + наши улучшения = WireGuard-OE

#### Как работает основной режим (balanced):

```
Оригинальный WireGuard Handshake Initiation:
┌──────┬──────┬──────────┬──────────┬──────────┬──────┬──────┐
│ type │ idx  │ eph(32)  │ stat(32) │ ts(32)   │ mac1 │ mac2 │
│  4   │  4   │   32     │   32     │   32     │  16  │  16  │
└──────┴──────┴──────────┴──────────┴──────────┴──────┴──────┘
                          Total: 148 bytes (FIXED)  ← ГЛАВНЫЙ ПРИЗНАК

WireGuard-OE Handshake Initiation (основной режим):
┌───────┬──────┬──────────────────┬─────────────────┬───────┐
│ junk  │ TLS  │  Noise keys      │  random pad     │ junk  │
│ 0-64  │ hdr  │  (encrypted)     │  to target size │ 0-64  │
└───────┴──────┴──────────────────┴─────────────────┴───────┘
Target: 517-1200 bytes (variable), имитируя TLS ClientHello
```

#### Ключевые элементы обфускации:

| Элемент | Описание | Против какого DPI |
|---------|----------|-------------------|
| **TLS 1.3 Header Mimicry** | Handshake имитирует TLS 1.3 ClientHello (content type, version, random, session ID, cipher suites) | Сигнатурный детект WireGuard magic bytes |
| **Variable-length Junk** | 0–64 байт случайных данных до и после полезной нагрузки | Фиксированный размер пакетов |
| **QUIC Short-Header Mimicry** (данные) | Data-пакеты маскируются под QUIC: connection ID + packet number + payload | ML-классификаторы по энтропии |
| **Padding Randomization** | Случайный padding до target_size (517, 666, 1200, etc.), имитируя реальные распределения TLS/QUIC | Анализ распределения размеров пакетов |
| **Timing Jitter** | Случайные задержки 0–30 мс между пакетами | Тайминг-анализ WireGuard keepalive |
| **Быстрая смена сессионных ключей** | Форсированный rehandshake каждые 60–120 секунд | Долгоживущие WireGuard сессии |

#### Режимы работы (выбираются пользователем):

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

#### Обоснование выбора Варианта B+ как основного:

1. **Баланс stealth/сложность:** Даёт ~85% stealth от максимального варианта C при ~35% усилий
2. **Совместимость с оригиналом:** Режим 0 — полный fallback до vanilla WireGuard стандартного протокола
3. **Производительность:** UDP-based (режимы 1–2) сохраняют низкую задержку WireGuard; overhead 8–15% в зависимости от уровня padding
4. **Проверенная основа:** AmneziaWG уже показала эффективность против РКН в 2022–2024; мы улучшаем её идеи
5. **Улучшаемость:** Модульная архитектура позволит добавить WebSocket fallback (режим 3) позже

---

## 3. Архитектура системы

### 3.1. Компонентная диаграмма

```
┌──────────────────────────────────────────────────────────────┐
│                    WIREGUARD-OE SYSTEM                        │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐      │
│  │  Linux       │   │  Windows     │   │  Android      │      │
│  │  Server      │   │  Client      │   │  Client       │      │
│  │  (userspace  │   │  (Go .exe)   │   │  (APK + libwg)│      │
│  │   daemon)    │   │              │   │               │      │
│  └──────┬───────┘   └──────┬───────┘   └──────┬────────┘      │
│         │                  │                  │               │
│         └──────────────────┼──────────────────┘               │
│                            │                                  │
│                    ┌───────▼────────┐                         │
│                    │  COMMON CORE   │                         │
│                    │  (Go library)  │                         │
│                    ├────────────────┤                         │
│                    │ • Obfuscator   │                         │
│                    │ • TLS Mimicry  │                         │
│                    │ • Noise Crypto │                         │
│                    │ • Transport    │                         │
│                    └───────┬────────┘                         │
│                            │                                  │
│                    ┌───────▼────────┐                         │
│                    │  amneziawg-go  │                         │
│                    │  fork          │                         │
│                    └────────────────┘                         │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

**Важно:** Предпочтение отдаётся **pure userspace** подходу (amneziawg-go / wireguard-go). Kernel module (wireguard-linux) — опциональный компонент для продвинутых пользователей, которым нужна максимальная производительность.

### 3.2. Data Flow (основной режим — balanced)

```
Приложение
    │
    ▼
WireGuard TUN device
    │
    ▼
┌──────────────────────────────────┐
│  Obfuscation Layer (Go)          │
│  ┌────────────────────────────┐  │
│  │  Outbound:                 │  │
│  │  1. WireGuard encrypt      │  │
│  │  2. Wrap in TLS/QUIC frame │  │
│  │  3. Add junk + padding     │  │
│  │  4. Send via UDP socket    │  │
│  └────────────────────────────┘  │
│  ┌────────────────────────────┐  │
│  │  Inbound:                  │  │
│  │  1. Receive from socket    │  │
│  │  2. Strip junk + TLS frame │  │
│  │  3. Validate cookie        │  │
│  │  4. WireGuard decrypt      │  │
│  └────────────────────────────┘  │
└──────────────────────────────────┘
    │
    ▼
Сеть (интернет, DPI, конечная точка)
```

---

## 4. Структура Monorepo

```
wireguard-oe/
├── README.md
├── PLAN.md
├── LICENSE
├── go.mod
├── go.sum
├── Makefile
├── .github/
│   └── workflows/
│       ├── build-server.yml
│       ├── build-windows.yml
│       ├── build-android.yml
│       └── test-obfuscation.yml
│
├── common/
│   ├── obfuscation.go
│   ├── obfuscation_test.go
│   ├── modes.go
│   ├── modes_test.go
│   ├── tls_mimicry.go
│   ├── tls_mimicry_test.go
│   ├── quic_mimicry.go
│   ├── quic_mimicry_test.go
│   ├── padding.go
│   ├── padding_test.go
│   ├── active_probing.go
│   ├── active_probing_test.go
│   ├── websocket_fallback.go
│   └── websocket_fallback_test.go
│
├── server/
│   ├── kernel/
│   │   ├── wireguard-oe.patch
│   │   └── README.md
│   └── userspace/
│       ├── main.go
│       ├── server.go
│       ├── config.go
│       ├── tunnel_linux.go
│       ├── obfuscation_manager.go
│       └── systemd/
│           └── wireguard-oe.service
│
├── client-windows/
│   ├── main.go
│   ├── wintun/
│   ├── ui/
│   ├── installer/
│   │   ├── wireguard-oe.nsi
│   │   └── resources/
│   ├── service_windows.go
│   ├── tunnel_windows.go
│   └── README.md
│
├── client-android/
│   ├── app/
│   │   ├── src/main/java/com/wireguard/oe/
│   │   │   ├── ObfuscationActivity.kt
│   │   │   ├── ObfuscationManager.kt
│   │   │   ├── TunnelManager.kt
│   │   │   ├── SplitTunnelManager.kt
│   │   │   └── AlwaysOnManager.kt
│   │   └── src/main/res/
│   ├── libwg/
│   │   ├── libwg.go
│   │   ├── obfuscation_jni.go
│   │   └── Android.mk
│   └── build.gradle
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── OBFUSCATION_SPEC.md
│   ├── DPI_TESTING.md
│   ├── BUILD_SERVER.md
│   ├── BUILD_WINDOWS.md
│   ├── BUILD_ANDROID.md
│   └── SECURITY.md
│
├── scripts/
│   ├── build-all.sh
│   ├── build-server.sh
│   ├── build-windows.sh
│   ├── build-android.sh
│   ├── test-local.sh
│   └── dpi-emulator/
│       ├── dpi_emulator.go
│       ├── rules/
│       │   ├── rkn.rules
│       │   ├── gfw.rules
│       │   └── enterprise.rules
│       └── README.md
│
└── test/
    ├── e2e_test.go
    ├── dpi_resistance_test.go
    ├── performance_test.go
    └── fixtures/
        └── test_configs/
```

---

## 5. Детальный список файлов и изменений

### 5.1. Общая библиотека (`common/`)

| Файл | Назначение | Оценка строк |
|------|------------|:---:|
| `obfuscation.go` | Интерфейс `Obfuscator`, фабрика режимов, конфигурация | ~200 |
| `modes.go` | `VanillaMode`, `LightMode`, `BalancedMode`, `MaxMode`, `AutoMode` | ~500 |
| `tls_mimicry.go` | Имитация TLS 1.3 ClientHello/ServerHello; JA3 fingerprints | ~600 |
| `quic_mimicry.go` | QUIC short-header mimicry для data-пакетов | ~400 |
| `padding.go` | Variable-length padding с настраиваемым распределением | ~200 |
| `active_probing.go` | Cookie-based проверка + random noise при probing | ~300 |
| `websocket_fallback.go` | WebSocket over TLS over TCP | ~600 |

### 5.2. Server (`server/`)

| Файл | Назначение | Изменения |
|------|------------|-----------|
| `kernel/wireguard-oe.patch` | Патч к `wireguard-linux` | Минимально (~50 строк). Optional. |
| `userspace/main.go` | Точка входа серверного демона | Новый (~200 строк) |
| `userspace/server.go` | Управление туннелем, lifecycle | Новый (~400 строк) |
| `userspace/config.go` | Парсинг конфигурации (режим, ключи, fallback) | Новый (~300 строк) |
| `userspace/obfuscation_manager.go` | Интеграция common/obfuscation в пайплайн WireGuard | Новый (~250 строк) |

### 5.3. Windows Client (`client-windows/`)

| Файл | Назначение |
|------|------------|
| `main.go` | Точка входа, управление lifecycle |
| `tunnel_windows.go` | WinTUN + обфускация |
| `ui/tray.go` | Системный трей (управление режимами) |
| `installer/wireguard-oe.nsi` | NSIS скрипт для .exe установщика |

### 5.4. Android Client (`client-android/`)

| Файл | Назначение |
|------|------------|
| `ObfuscationManager.kt` | Настройка режимов обфускации из UI |
| `SplitTunnelManager.kt` | Split-tunneling (по приложениям и CIDR) |
| `AlwaysOnManager.kt` | Always-on VPN + Kill Switch |
| `libwg/obfuscation_jni.go` | JNI bridge к Go-библиотеке обфускации |

---

## 6. Протокол обфускации (Wire Format)

### 6.1. Handshake Initiation (режим balanced)

```
WireGuard-OE Handshake Initiation:
┌──────────────────────────────────────────────────────────────────┐
│ Random Junk Prefix (0–64 bytes, uniform random)                  │
├──────────────────────────────────────────────────────────────────┤
│ TLS 1.3 ClientHello Mimicry Frame:                              │
│  [1 byte] Content Type: 0x16 (Handshake)                        │
│  [2 bytes] Protocol Version: 0x0303 (TLS 1.2) → маскировка под  │
│             TLS 1.2, но структура 1.3                           │
│  [2 bytes] Length                                               │
│  [1 byte] Handshake Type: 0x01 (ClientHello)                    │
│  [3 bytes] Length                                               │
│  [2 bytes] Client Version: 0x0303                               │
│  [32 bytes] Random (имитация TLS Random, содержит ephemeral)    │
│  [1 byte] Session ID Length: 32                                 │
│  [32 bytes] Session ID (encrypted static key)                   │
│  [2 bytes] Cipher Suites Length: varies                         │
│  [variable] Cipher Suites (TLS_AES_128_GCM, etc.)               │
│  [1 byte] Extensions Length                                     │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Extension: encrypted_timestamp (0xFE0D custom)            │  │
│  │  [2 bytes] Type: 0xFE0D                                   │  │
│  │  [2 bytes] Length                                         │  │
│  │  [variable] Encrypted timestamp + mac1 + mac2             │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Extension: padding (0xFE0E custom, optional)              │  │
│  │  [2 bytes] Type: 0xFE0E                                   │  │
│  │  [2 bytes] Length: random (0–200)                         │  │
│  │  [variable] Random padding bytes                          │  │
│  └───────────────────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────────┤
│ Random Junk Suffix (0–64 bytes, uniform random)                  │
└──────────────────────────────────────────────────────────────────┘
Final packet size: 517–1200 bytes (variable)
```

### 6.2. Data Packet (режим balanced)

```
WireGuard-OE Data Packet (QUIC short-header mimicry):
┌──────────────────────────────────────────────────────────────────┐
│ QUIC Short Header:                                              │
│  [1 byte] Header Form: 0b0xxxxxxx (short header)               │
│  [1 byte] Fixed Bit + Spin Bit + Reserved + Key Phase           │
│  [1 byte] Packet Number Length (encoded in lower bits)         │
│  [1–4 bytes] Packet Number (incremental)                       │
│  [8–20 bytes] Destination Connection ID (random per session)   │
├──────────────────────────────────────────────────────────────────┤
│ Encrypted WireGuard Payload (ChaCha20-Poly1305)                 │
│  [8 bytes] WireGuard nonce (embedded in QUIC PN)               │
│  [variable] Encrypted IP packet                                │
│  [16 bytes] Poly1305 authentication tag                        │
├──────────────────────────────────────────────────────────────────┤
│ Variable Padding to target size (0–100 bytes)                   │
└──────────────────────────────────────────────────────────────────┘
Target sizes (sampled from real QUIC distributions):
  - 80% packets: 200–800 bytes
  - 15% packets: 80–200 bytes (ACK-only имитация)
  - 5% packets: 1200–1400 bytes (full MTU)
```

---

## 7. Криптография

### 7.1. Двухслойная схема

```
Оригинальный WireGuard:
  IP packet → WireGuard encrypt (ChaCha20-Poly1305) → UDP packet

WireGuard-OE (режим balanced):
  IP packet → WireGuard encrypt (ChaCha20-Poly1305)
           → Obfuscation wrap (TLS/QUIC mimicry frame)
           → Outer encrypt (ChaCha20-Poly1305, отдельный ключ)
           → Padding + Junk
           → UDP packet

Два независимых ключа:
  K_wg   — стандартный WireGuard ключ (Noise IK handshake)
  K_obs  — дополнительный ключ для внешнего слоя (встроен в Noise handshake)
```

### 7.2. Ключевые улучшения

| Элемент | Vanilla WG | WireGuard-OE |
|---------|------------|--------------|
| Handshake protocol | Noise_IK | Noise_IK + outer layer |
| Ключей на сессию | 1 | 2 (K_wg, K_obs) |
| Perfect Forward Secrecy | ✅ | ✅ (для обоих слоёв) |
| Replay protection | ✅ (timestamp) | ✅ (timestamp + cookie) |
| Active probing resistance | ❌ | ✅ (cookie validation) |

---

## 8. Active Probing Protection

### 8.1. Метод защиты

```
DPI Probe → отправляет «похожий на WireGuard» пакет
                │
                ▼
WireGuard-OE получает пакет
                │
                ▼
        ┌─────────────────┐
        │ Cookie валиден? │
        └────┬────────┬───┘
             │ YES    │ NO
             ▼        ▼
      Обработать   Ответить случайным junk-ом (80–200 байт),
      нормально    имитируя TLS Alert или QUIC CONNECTION_CLOSE
                  (не раскрывая факт, что это WireGuard)
```

### 8.2. Cookie Mechanism

Cookie вычисляется как:
```
cookie = HMAC-SHA256(K_obs, source_ip || source_port || timestamp || salt)
```

- Сервер при probing возвращает случайный TLS 1.3 ServerHello с невалидной сессией
- Это выглядит для DPI как обычный TLS-сервер, который отклонил неизвестную сессию
- Никаких признаков WireGuard в ответе

---

## 9. Стратегия тестирования DPI

### 9.1. Локальный тест-стенд

Компоненты:
- **DPI Emulator** (`scripts/dpi-emulator/`) — Go-программа, симулирующая:
  - Сигнатурный детект (фиксированный размер, magic bytes)
  - Энтропийный анализ (скользящее окно, H > 7.8 бит/байт)
  - ML-классификатор (обученная модель на реальном трафике, включая 2025 сигнатуры)
  - Активное probing (отправка подозрительных пакетов)
- **Генератор трафика** — iperf3, curl, YouTube streaming через VPN
- **Метрики** — процент обходных пакетов, latency overhead, throughput

### 9.2. Тестирование на реальных провайдерах

| Провайдер | Тип DPI | Ожидаемый результат (balanced) |
|-----------|---------|:---:|
| Ростелеком | ТСПУ (РКН) | Обход ✅ |
| Билайн | ТСПУ + Sandvine | Обход ✅ |
| МТС | ТСПУ + RDI | Обход ✅ |
| GFW (China) | GFW + probing | Обход ✅ (UDP), может потребоваться WS fallback |
| Enterprise (Palo Alto) | App-ID | Обход ✅ (TLS mimicry) |

### 9.3. Сравнительное тестирование

В рамках тестирования WireGuard-OE должен быть проверен против:
- **Mullvad LWO** — базовый уровень обфускации (XOR + padding)
- **AmneziaWG 2.0 (vanilla)** — текущий state-of-the-art
- **Vanilla WireGuard** — контрольная группа
- **Актуальные сигнатуры 2025 года** — те TSPU/GFW правила, которые детектят AmneziaWG и Mullvad LWO сегодня

### 9.4. Процедура тестирования

1. Развернуть сервер на VPS в целевой стране
2. Подключить клиент в режиме `balanced`
3. Генерировать трафик (HTTP, DNS, streaming)
4. Мониторить блокировки (tcpdump + анализ ответов probing)
5. Повторить для каждого режима (vanilla, light, balanced, max, auto)
6. Записать результаты в `DPI_TEST_RESULTS.md`

---

## 10. Риски и минимизация

| Риск | Вероятность | Влияние | Минимизация |
|------|:---:|:---:|------------|
| Обновление DPI сигнатур (TLS mimicry детектится) | Средняя | Высокое | Динамическая смена JA3 fingerprints; модульность позволяет менять mimicry без переписывания ядра |
| Устаревание TLS/QUIC fingerprints | Средняя | Высокое | Динамическая ротация параметров mimicry и uTLS client hello randomization через обновляемый реестр fingerprint-ов |
| TCP-over-TCP meltdown (режим 3) | Высокая | Среднее | Использовать smux/kcp для мультиплексирования; предупреждать в документации |
| Деградация производительности | Низкая | Среднее | Бенчмарки в CI; overhead целевой 8–15% для режима balanced |
| Несовместимость с будущими версиями WireGuard / AmneziaWG | Средняя | Среднее | Минимальные патчи поверх amneziawg-go; абстракция через интерфейс `Obfuscator` |
| Юридические риски (обход блокировок) | Низкая | Низкое | Проект позиционируется как инструмент для легитимного обхода цензуры; лицензия GPLv2 |
| Утечки ключей через обфускацию | Низкая | Критическое | Дополнительный слой шифрования (K_obs); security audit |

---

## 11. Roadmap (14 недель)

| Неделя | Этап | Задачи |
|:---:|------|--------|
| **1** | **Изучение и форк** | Изучить репозитории AmneziaWG 2.0; форкнуть актуальные версии; настроить monorepo; базовый CI/CD |
| **2** | **Common: Obfuscator interface** | Интерфейсы, фабрика, VanillaMode, тесты |
| **3** | **Common: Padding + Light mode** | Variable padding, random junk, LightMode, тесты |
| **4** | **Common: TLS mimicry** | TLS 1.3 ClientHello/ServerHello mimicry, JA3 fingerprints |
| **5** | **Common: QUIC mimicry** | QUIC short-header mimicry для data-пакетов, BalancedMode |
| **6** | **Common: Active probing** | Cookie-based защита, случайные ответы, MaxMode |
| **7** | **Server: userspace daemon** | Go server daemon на базе amneziawg-go, интеграция с common |
| **8** | **Server: kernel patch (optional)** | Минимальный патч для wireguard-linux, тестирование |
| **9** | **Windows client** | Форк amneziawg-windows, интеграция с common, WinTUN + Go UI + NSIS installer |
| **10** | **Android client** | Форк amneziawg-android, JNI bridge, UI |
| **11** | **Common: WebSocket fallback** | Режим 3: WebSocket over TLS over TCP |
| **12** | **Тестирование** | DPI эмулятор, реальные провайдеры, performance benchmarks |
| **13** | **Интеграционное тестирование** | Кросс-платформенные тесты, fallback-тесты, нагрузочное тестирование |
| **14** | **Документация и релиз** | README, BUILD-инструкции, GitHub Actions release, v1.0.0 |

---

## 12. Критерии приёмки (Definition of Done)

- [ ] Все режимы (0–4) реализованы и проходят unit-тесты (coverage >80%)
- [ ] Режим `balanced` обходит DPI Emulator с вероятностью >95%
- [ ] Режим `balanced` обходит актуальные сигнатуры 2025 года (РКН, GFW, Sandvine)
- [ ] Производительность режима `balanced`: overhead 8–15% latency, 5–10% throughput (в зависимости от уровня padding)
- [ ] Режим `vanilla` (0) полностью совместим со стандартным WireGuard (в обе стороны)
- [ ] Windows клиент: установщик .exe, работает в system tray, переключение режимов
- [ ] Android клиент: split-tunneling, Always-on, Kill Switch, выбор режима обфускации
- [ ] CI/CD: автоматическая сборка всех платформ, тесты при каждом push
- [ ] Документация: README, BUILD_SERVER, BUILD_WINDOWS, BUILD_ANDROID, DPI_TESTING, SECURITY
- [ ] Active probing resistance работает: DPI Emulator не детектит WireGuard-OE как WireGuard
- [ ] WireGuard-OE показывает stealth выше, чем vanilla AmneziaWG 2.0 и Mullvad LWO

---

## Приложение A: Сравнение с существующими решениями

|                          | WireGuard-OE | AmneziaWG 2.0 | Mullvad LWO | sing-box wg | cloak |
|--------------------------|:---:|:---:|:---:|:---:|:---:|
| **Stealth (против РКН)** | 8.5/10 | 7.5/10 | 5/10 | 8/10 | 6/10 |
| **Stealth (против GFW)** | 7/10 | 6/10 | 4/10 | 8/10 | 7/10 |
| **Производительность**   | ★★★★★ | ★★★★☆ | ★★★★★ | ★★★☆☆ | ★★★☆☆ |
| **Fallback до vanilla WG** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Открытый код**          | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Поддержка Windows**     | ✅ (.exe) | ✅ | ❌ | ❌ (CLI) | ❌ |
| **Поддержка Android**     | ✅ (APK) | ✅ | ❌ | ✅ (APK) | ❌ |
| **Active Probing Prot.**  | ✅ | ❌ | ❌ | ⚠️ частично | ❌ |
| **Модульные режимы**      | ✅ (5 режимов) | ❌ | ❌ | ✅ | ❌ |
| **Pure userspace**        | ✅ (default) | ⚠️ kernel | ✅ | ✅ | ✅ |

---

> **План Этапа 0 (v1.2) утверждён. Переход к Этапу 1 — Подготовка репозитория (форк AmneziaWG 2.0).**
