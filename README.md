# Ghosting Server

Сервер призраков для **Ghosting Mod: Renewed** (Half-Life 2, Source SDK 2013): онлайн-призраки, чат, гонки, спреи.
Работает на Node.js, без зависимостей, по UDP.

С версии **1.4.0** сервер отвечает на запрос из окна «Найти серверы» в игре (название, онлайн, игроки),
видит SteamID и то, зашёл игрок через лаунчер HLSR или нет, и даёт права OP по SteamID.

Полная справка по протоколу и всем настройкам на английском — [README.en.md](README.en.md).

---

## Что нужно

- **Node.js 22 или новее** (рекомендуется 24 LTS): https://nodejs.org
- Открытый **UDP-порт 22228** (или свой, см. `PORT`).
- Игроки — с Ghosting **v4.3** или новее (старые версии тоже подключаются, но не видят название и онлайн в списке серверов).

## Быстрый запуск на Windows

1. Установите Node.js (LTS) с https://nodejs.org.
2. Скачайте репозиторий: **Code → Download ZIP** и распакуйте, например, в `C:\Ghosting-Server`.
3. Создайте рядом файл `start.cmd`:

   ```bat
   @echo off
   cd /d "%~dp0"
   set SERVER_NAME=Мой сервер призраков
   set PORT=22228
   set MAX_PLAYERS=16
   node index.js
   pause
   ```

4. Запустите `start.cmd`. В окне появится строка вида
   `Ghosting dedicated host listening on 0.0.0.0:22228/udp` — сервер работает.
5. Разрешите `node.exe` в брандмауэре Windows (он спросит при первом запуске) для **UDP 22228**.

Команды сервера (см. ниже) вводятся прямо в это окно.

## Хостинг на Linux (Ubuntu 24.04)

```bash
git clone https://github.com/HL-HLSR/Ghosting-Server.git
cd Ghosting-Server
sudo deploy/install-ubuntu.sh
```

Скрипт:

- ставит Node.js 24 из репозитория NodeSource (ключ проверяется);
- создаёт системного пользователя `ghserver` и группу `ghsadmin` для консоли;
- кладёт код в `/opt/ghserver`, данные (баны, OP) в `/var/lib/ghserver`, настройки в `/etc/ghserver/ghserver.env`;
- ставит службу systemd `ghserver`.

Дальше:

```bash
sudo nano /etc/ghserver/ghserver.env      # настройки (SERVER_NAME=..., PORT=..., ...)
sudo systemctl enable --now ghserver      # запустить и включить автозапуск
sudo systemctl restart ghserver           # перезапуск после изменения настроек
journalctl -u ghserver -f                 # лог
```

Команды сервера по SSH:

```bash
sudo usermod -aG ghsadmin $USER           # один раз, затем перелогиниться
ghserver-console status
ghserver-console 'ban "Griefer" 2h спам'
ghserver-console                          # без аргументов: команда вводится скрыто (для PIN)
```

Ответы команд пишутся в лог (`journalctl -u ghserver -f`).

Брандмауэр (nftables, открывает UDP-порт сервера и SSH), с автооткатом, если потеряете доступ:

```bash
sudo /opt/ghserver/deploy/firewall-apply.sh             # применить, откат через 120 с
sudo /opt/ghserver/deploy/firewall-apply.sh --confirm   # из НОВОЙ SSH-сессии: оставить
```

Обновление: `git pull` и снова `sudo deploy/install-ubuntu.sh` — скрипт можно запускать повторно, служба перезапустится.

## Дома за роутером

Пробросьте на роутере **UDP 22228** на компьютер с сервером. Игрокам давайте внешний IP
(его видно, например, на https://2ip.ru). Если игроки в одной сети с сервером — подойдёт локальный IP,
а в игре сервер найдётся на вкладке «Локальная сеть».

## Как подключиться из игры

- **Главное меню → «Найти серверы» → «Добавить сервер»** → `IP:порт` (например `1.2.3.4:22228`) → двойной клик по серверу.
  Подключение происходит при загрузке карты.
- Или через консоль:

  ```
  gh_online_ip 1.2.3.4
  gh_online_port 22228
  gh_online_connect
  ```

Пока вы подключены, под меню есть кнопки «Отключиться» и «Начать гонку».

## Основные настройки

Задаются переменными окружения (в `start.cmd` через `set`, на Linux — в `/etc/ghserver/ghserver.env`).

| Переменная | По умолчанию | Что делает |
| --- | --- | --- |
| `PORT` | `22228` | UDP-порт сервера. |
| `BIND_ADDRESS` | `0.0.0.0` | Адрес, на котором слушать. `127.0.0.1` — только этот компьютер. |
| `SERVER_NAME` | `Ghosting server` | Название в списке серверов. До 63 байт (русская буква — 2 байта). |
| `MAX_PLAYERS` | `16` | Слоты. Больше 16 не проверялось под нагрузкой. |
| `SERVER_INFO` | `1` | `0` — не отвечать на запросы списка серверов. |
| `SERVER_INFO_PLAYERS` | `1` | `0` — показывать только число игроков, без ников. |
| `ACCESS_FILE` | `access.json` | Где хранятся баны, whitelist и OP. |
| `OP_CHAT_COMMANDS` | `1` | `0` — модерация только из консоли сервера, без чат-команд. |
| `OP_ALLOW_NO_PIN` | `0` | `1` — разрешить OP без PIN (не рекомендуется). |
| `RACE_SPECTATORS` | `0` | `1` — зрителям можно запускать гонку. |
| `EMOTE_PACK` | не задан | Общий набор эмоутов 7TV для лобби: ссылка `7tv.app/emote-sets/<id>` или id. |
| `DEBUG` | `0` | `1` — подробный лог. |

Остальные (лимиты, антиспам, таймауты гонки) — в [README.en.md](README.en.md). Неизвестная или неверная
переменная — сервер не запустится и напишет, что не так.

## Админка (OP)

- `opsteam <SteamID64> <PIN>` — постоянный OP по SteamID. PIN — 6–12 цифр, хранится только хешем.
- `op "Ник" <PIN>` — выдать OP игроку, который сейчас на сервере; `deop "Ник"`, `deopsteam <SteamID64>`; `ops` — список.
- В чате OP пишет PIN первым словом: `/kick 12345678 Ник`.

> **Важно:** SteamID игра сообщает о себе сама, сервер его не проверяет через Steam.
> Подделать его так же просто, как ник, поэтому настоящая защита OP — **PIN** (ставьте 8+ цифр).

## Команды консоли сервера

| Команда | Что делает |
| --- | --- |
| `help` | Список команд |
| `status`, `list` | Состояние сервера и игроки (кто через HLSR, SteamID) |
| `kick "Ник"` | Кикнуть |
| `ban "Ник" [срок] [причина]`, `unban "Ник"` | Бан по нику |
| `banip <IP> [срок]`, `unbanip <IP>` | Бан по адресу |
| `bansteam <SteamID64> [срок]`, `unbansteam <SteamID64>` | Бан по SteamID |
| `banlist` | Все баны |
| `whitelist on\|off`, `whitelist add "Ник"`, `whitelist addip <IP>`, `whitelist addsteam <SteamID64>`, `whitelist remove…` | Вход только по списку |
| `op`, `deop`, `opsteam`, `deopsteam`, `ops` | Операторы |
| `sprays`, `sprayban "Ник"`, `unsprayban "Ник"` | Спреи |
| `broadcast <текст>` | Сообщение всем |
| `race cancel` | Отменить текущую гонку |
| `maxplayers <N>`, `limits` | Слоты и лимиты |
| `unguard "Ник"` | Снять защиту ника |
| `reload` | Перечитать `access.json` |

Сроки: `30m`, `2h`, `7d`; без срока — навсегда.

## Команды в игровом чате

- Все: `/race` — открыть лобби гонки, `/ready` — вступить, `/leave` — выйти.
- OP (PIN первым словом): `/kick`, `/ban`, `/unban`, `/sprayban`, `/unsprayban`, `/broadcast`.

## Папки

- `index.js`, `src/` — сервер; `deploy/` — установка на Linux; `test/` — тесты.
- `legacy/` — старый однофайловый сервер, хранится только для сравнения и не запускается.

## Проверка

```bash
npm test
```
