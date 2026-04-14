# Eltex MES Telnet Password Changer

[🇷🇺 Русский](#russian) | [🇺🇸 English](#english)

<a name="russian"></a>
## 🇷🇺 Описание проекта (RU)

Скрипт для массовой смены пароля пользователей на коммутаторах Eltex MES через Telnet.

Подходит для быстрого прохода по пулу IP-адресов, проверки доступности Telnet-порта и смены пароля на нескольких устройствах параллельно.

## Что умеет

- поддерживает список целей в виде:
  - одного IP
  - диапазона IP
  - CIDR-сети
  - смешанного списка через запятую
- делает TCP precheck до Telnet-порта
- опционально проверяет ICMP ping
- логинится по Telnet
- при необходимости входит в `enable`
- меняет пароль указанному пользователю
- при необходимости задаёт `enable password`
- сохраняет конфигурацию через `write memory`
- работает в несколько потоков
- сохраняет результат в CSV и LOG

## Поддерживаемые форматы ввода

Примеры:

```text
10.99.0.12
10.99.0.10-10.99.0.50
10.99.0.10-50
10.99.0.0/24
10.99.0.0/24,10.99.1.10-10.99.1.20,10.99.2.5
```
## Требования

- Python 3.9+
- доступ посредством telnet к устройствам
- известные текущие учетные данные
- права на изменение пользователя и, при необходимости, enable password


## Запуск
```
python3 eltex_mes_telnet_changer_v1.2.py
```

## После запуска скрипт последовательно спросит:
- IP или пул адресов
- Telnet порт
- timeout для Telnet
- timeout для TCP precheck
- нужно ли проверять ping
- число потоков
- текущий логин
- текущий пароль
- нужен ли enable
- какому пользователю менять пароль
- новый пароль
- нужно ли обновить enable password
- нужно ли сохранить конфиг

## Сценарий обработки:
1.	Проверяется доступность TCP-порта Telnet.
2.	При включённой опции дополнительно проверяется ICMP ping.
3.	Выполняется вход по Telnet.
4.	При необходимости выполняется вход в enable.
5.	Скрипт переходит в режим конфигурации.
6.	Выполняет команду смены пароля пользователя:

	`
	username <user> password <new_password>
	`

7.	При необходимости задаёт:

	`
	enable password <new_enable_password>
	`

9.	Выходит из конфигурации.
10.	При включённой опции выполняет:
	`
	write memory
	`
	
## Выходные файлы:

После завершения создаются два файла:


	•	eltex_mes_telnet_v1.2_YYYYMMDD-HHMMSS.csv	
	
	
	•	eltex_mes_telnet_v1.2_YYYYMMDD-HHMMSS.log


В них сохраняются:


	
	•	IP-адрес устройства
	
	•	статус выполнения
	
	•	детали результата
	
	


Статусы


	
	•	OK — пароль успешно изменён
	
	•	SKIP(TCP) — Telnet-порт недоступен
	
	•	SKIP(PING) — устройство не отвечает на ping, если проверка была включена
	
	•	ERROR — ошибка при логине, входе в enable, смене пароля или сохранении
	
	

## Важное замечание по безопасности

### Этот скрипт сохраняет новые пароли в CSV и LOG

Это сделано намеренно для проверки результата.

После проверки рекомендуется удалить CSV и LOG файлы, либо хранить их в надежном и защищенном месте.

Перед использованием убедитесь, что понимаете риск хранения паролей в открытом виде
	
---
### 💖 Поддержать проект / Support the project
Вы можете поддержать разработку этого и других моих проектов по ссылке:
👉 **[Реквизиты и карты](https://github.com/KOTKOKOCC/KOTKOKOCC)**


<a name="english"></a>

# Eltex MES Telnet Password Changer


[🇷🇺 Русский](#russian) | [🇺🇸 English](#english)

## Project Description

A script for bulk password changes for users on Eltex MES switches via Telnet.

It is suitable for quickly scanning a pool of IP addresses, checking Telnet port availability, and changing passwords on multiple devices in parallel.

## Features

- supports target input as:
  - a single IP address
  - an IP range
  - a CIDR network
  - a mixed comma-separated list
- performs a TCP precheck for the Telnet port
- can optionally check ICMP ping
- logs in via Telnet
- enters `enable` mode if required
- changes the password for the specified user
- can optionally set `enable password`
- saves the configuration with `write memory`
- works in multiple threads
- saves the result to CSV and LOG

## Supported Input Formats

Examples:

    10.99.0.12
    10.99.0.10-10.99.0.50
    10.99.0.10-50
    10.99.0.0/24
    10.99.0.0/24,10.99.1.10-10.99.1.20,10.99.2.5

## Requirements

- Python 3.9+
- Telnet access to the devices
- valid current credentials
- permission to modify the user account and, if needed, the enable password

## Run

    python3 eltex_mes_telnet_changer_v1.2.py

## After Launch, the Script Will Prompt for

- IP address or address pool
- Telnet port
- Telnet timeout
- TCP precheck timeout
- whether ping check is required
- number of threads
- current login
- current password
- whether enable mode is required
- which user password should be changed
- new password
- whether to update the enable password
- whether to save the configuration

## Processing Workflow

1. Checks whether the Telnet TCP port is available.
2. If enabled, also checks ICMP ping.
3. Logs in via Telnet.
4. Enters enable mode if required.
5. Switches to configuration mode.
6. Executes the user password change command:

`username <user> password <new_password>`

7. If required, sets:

`enable password <new_enable_password>`

8. Exits configuration mode.
9. If enabled, executes: `write memory`

## Output Files

After completion, two files are created:

- `eltex_mes_telnet_v1.2_YYYYMMDD-HHMMSS.csv`
- `eltex_mes_telnet_v1.2_YYYYMMDD-HHMMSS.log`

They contain:

- device IP address
- execution status
- result details

## Statuses

- `OK` — password changed successfully
- `SKIP(TCP)` — Telnet port is unavailable
- `SKIP(PING)` — the device does not respond to ping, if the check was enabled
- `ERROR` — error during login, entering enable mode, changing the password, or saving the configuration

## Important Security Notice

### This script stores new passwords in CSV and LOG files

This is done intentionally to verify the result.

After verification, it is recommended to delete the CSV and LOG files or store them in a secure and protected location.

Before using the script, make sure you understand the risks of storing passwords in plain text.

---

### 💖 Support the Project

You can support the development of this and my other projects using the link below:
👉 **[Details and cards](https://github.com/KOTKOKOCC/KOTKOKOCC)**
