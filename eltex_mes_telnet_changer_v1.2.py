#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Eltex MES Telnet password changer v1.2
UI + TCP-precheck + paging + save-confirm + threads + CSV/LOG (incl. creds)
"""

import ipaddress
import telnetlib
import time
import getpass
import socket
import platform
import subprocess
import re
import csv
from datetime import datetime
from typing import List, Optional, Tuple, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# ----------------- helpers: targets -----------------

def parse_targets(s: str) -> List[str]:
    """
    Поддержка:
      - CIDR: 10.99.0.0/24
      - Range full: 10.99.0.10-10.99.0.50
      - Range short: 10.99.0.10-50  (последний октет)
      - Single: 10.99.0.12
      - Список через запятую: 10.0.0.0/24,10.0.1.10-10.0.1.20,10.0.2.5
    """
    out: List[str] = []
    parts = [p.strip() for p in s.split(",") if p.strip()]

    for part in parts:
        if "/" in part:
            net = ipaddress.ip_network(part, strict=False)
            out.extend(str(ip) for ip in net.hosts())
            continue

        if "-" in part:
            a, b = part.split("-", 1)
            a = a.strip()
            b = b.strip()
            start = ipaddress.ip_address(a)

            # short form: 10.99.0.10-50
            if re.fullmatch(r"\d{1,3}", b):
                last = int(b)
                if not (0 <= last <= 255):
                    raise ValueError(f"Неверный последний октет в диапазоне: {part}")
                octets = a.split(".")
                if len(octets) != 4:
                    raise ValueError(f"Неверный IP слева в диапазоне: {part}")
                end = ipaddress.ip_address(".".join(octets[:3] + [str(last)]))
            else:
                end = ipaddress.ip_address(b)

            if int(end) < int(start):
                raise ValueError(f"Некорректный диапазон: {part}")

            # защита от случайного /8
            if int(end) - int(start) > 65535:
                raise ValueError(f"Слишком большой диапазон (>65536 адресов): {part}")

            for i in range(int(start), int(end) + 1):
                out.append(str(ipaddress.ip_address(i)))
            continue

        out.append(part)

    # remove duplicates, keep order
    seen, res = set(), []
    for h in out:
        if h not in seen:
            seen.add(h)
            res.append(h)
    return res

# ----------------- helpers: connectivity -----------------

def tcp_port_open(host: str, port: int, timeout_sec: float) -> bool:
    """Честный precheck: TCP connect к telnet порту."""
    try:
        with socket.create_connection((host, port), timeout=timeout_sec):
            return True
    except OSError:
        return False

def ping_host(host: str, timeout_sec: int = 1) -> bool:
    """
    Оставлено опционально (НЕ как основной критерий).
    Может врать (ICMP режут), поэтому по умолчанию выключено.
    """
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_sec * 1000), host]
    else:
        if system == "darwin":
            cmd = ["ping", "-c", "1", "-W", str(timeout_sec * 1000), host]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout_sec), host]
    try:
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode == 0
    except Exception:
        return False

# ----------------- helpers: telnet io (paging aware) -----------------

MORE_MARKERS = [b"--More--", b"<More>", b" more ", b"More"]
LOGIN_PATTERNS = [b"login:", b"username:", b"user name:", b"user:"]
PASS_PATTERNS = [b"password:"]
PROMPT_PATTERNS = [b"#", b">"]
SAVE_CONFIRM_PATTERNS = [b"(y/n)", b"overwrite file", b"[n] ?"]

def _drain_more(tn: telnetlib.Telnet, buf: bytes) -> bytes:
    loops = 0
    low = buf.lower()
    while loops < 50 and any(m.lower() in low for m in MORE_MARKERS):
        tn.write(b" ")              # пробел = next page
        time.sleep(0.05)
        chunk = tn.read_very_eager()
        if not chunk:
            break
        buf += chunk
        low = buf.lower()
        loops += 1
    return buf

def read_until_any(tn: telnetlib.Telnet, patterns, timeout: float):
    end = time.time() + timeout
    buf = b""
    patterns_l = [p.lower() for p in patterns]
    while time.time() < end:
        chunk = tn.read_very_eager()
        if chunk:
            buf += chunk
            buf = _drain_more(tn, buf)
            low = buf.lower()
            if any(p in low for p in patterns_l):
                return buf
        time.sleep(0.03)
    return buf

def send(tn: telnetlib.Telnet, cmd: str):
    tn.write(cmd.encode("utf-8") + b"\n")

def has_error(buf: bytes) -> bool:
    low = (buf or b"").lower()
    return any(x in low for x in [b"% invalid", b"% unknown", b"% incomplete", b"% ambiguous", b"% error"])

# ----------------- device logic -----------------

def login_telnet(host: str, port: int, user: str, pwd: str, timeout: float) -> telnetlib.Telnet:
    tn = telnetlib.Telnet(host, port, timeout)

    buf = read_until_any(tn, LOGIN_PATTERNS + PASS_PATTERNS, timeout=timeout)
    low = buf.lower()

    # если сразу попросил пароль
    if b"password:" in low and not any(p in low for p in [b"login:", b"username:", b"user:", b"user name:"]):
        send(tn, pwd)
    else:
        send(tn, user)
        read_until_any(tn, PASS_PATTERNS, timeout=timeout)
        send(tn, pwd)

    # ждём prompt
    buf2 = read_until_any(tn, PROMPT_PATTERNS, timeout=timeout)
    if not any(p in buf2 for p in PROMPT_PATTERNS):
        raise RuntimeError("Не дождался prompt после логина")
    return tn

def ensure_enable(tn: telnetlib.Telnet, enable_pwd: Optional[str], timeout: float):
    send(tn, "")
    buf = read_until_any(tn, PROMPT_PATTERNS, timeout=timeout)
    if b">" in buf and b"#" not in buf:
        send(tn, "enable")
        buf2 = read_until_any(tn, [b"password:", b"#"], timeout=timeout)
        if b"password:" in buf2.lower():
            if not enable_pwd:
                raise RuntimeError("Нужен enable password (prompt '>'), но он не задан.")
            send(tn, enable_pwd)
            read_until_any(tn, [b"#"], timeout=timeout)

def change_password_enable_save(
    tn: telnetlib.Telnet,
    target_user: str,
    new_pwd: str,
    set_enable_pwd: Optional[str],
    save: bool,
    timeout: float
):
    # config mode
    send(tn, "configure")
    buf = read_until_any(tn, [b"(config)#", b"config)#"], timeout=timeout)
    if has_error(buf):
        raise RuntimeError("Не вошёл в configure")

    # change user password
    send(tn, f"username {target_user} password {new_pwd}")
    buf = read_until_any(tn, [b"(config)#", b"config)#"], timeout=timeout)
    if has_error(buf):
        raise RuntimeError("Ошибка в команде username ... password ...")

    # set enable password (если задано)
    if set_enable_pwd:
        # твой MES: enable password <pwd>
        send(tn, f"enable password {set_enable_pwd}")
        buf = read_until_any(tn, [b"(config)#", b"config)#"], timeout=timeout)
        if has_error(buf):
            raise RuntimeError("Ошибка в команде enable password ...")

    # end
    send(tn, "end")
    read_until_any(tn, PROMPT_PATTERNS, timeout=timeout)

    if save:
        send(tn, "write memory")
        buf = read_until_any(
            tn,
            SAVE_CONFIRM_PATTERNS + PROMPT_PATTERNS + [b"copy succeeded", b"completed successfully"],
            timeout=timeout + 4
        )

        # подтвердить Y если спросило
        low = buf.lower()
        if any(m in low for m in SAVE_CONFIRM_PATTERNS):
            send(tn, "Y")
            buf2 = read_until_any(
                tn,
                PROMPT_PATTERNS + [b"copy succeeded", b"completed successfully"],
                timeout=timeout + 8
            )
            if has_error(buf2):
                raise RuntimeError("Ошибка при сохранении (после подтверждения Y)")

    send(tn, "exit")

def work_one_host(
    host: str,
    port: int,
    user: str,
    pwd: str,
    enable_pwd: Optional[str],
    target_user: str,
    new_pwd: str,
    set_enable_pwd: Optional[str],
    save: bool,
    timeout: float,
    do_ping: bool,
    ping_timeout: int,
    tcp_precheck_timeout: float,
) -> Tuple[str, str, Dict[str, Any]]:
    """
    Возвращает (host, status, info)
    status: OK | SKIP(TCP) | SKIP(PING) | ERROR
    info: dict с деталями
    """
    if not tcp_port_open(host, port, timeout_sec=tcp_precheck_timeout):
        return host, "SKIP(TCP)", {"reason": f"tcp/{port} closed or unreachable"}

    if do_ping and not ping_host(host, timeout_sec=ping_timeout):
        return host, "SKIP(PING)", {"reason": "icmp no reply"}

    try:
        tn = login_telnet(host, port, user, pwd, timeout=timeout)
        ensure_enable(tn, enable_pwd, timeout=timeout)
        change_password_enable_save(tn, target_user, new_pwd, set_enable_pwd, save, timeout=timeout)
        tn.close()
        return host, "OK", {
            "login_user": user,
            "target_user": target_user,
            "new_user_password": new_pwd,
            "enable_mode_used": bool(enable_pwd),
            "new_enable_password": set_enable_pwd if set_enable_pwd else "",
            "saved": bool(save),
        }
    except Exception as e:
        return host, "ERROR", {"error": str(e)}

# ----------------- interactive UI -----------------

def ask(prompt: str, default: Optional[str] = None) -> str:
    if default is not None:
        s = input(f"{prompt} [{default}]: ").strip()
        return s if s else default
    return input(f"{prompt}: ").strip()

def ask_int(prompt: str, default: int) -> int:
    s = input(f"{prompt} [{default}]: ").strip()
    if not s:
        return default
    try:
        return int(s)
    except ValueError:
        return default

def ask_float(prompt: str, default: float) -> float:
    s = input(f"{prompt} [{default}]: ").strip()
    if not s:
        return default
    try:
        return float(s)
    except ValueError:
        return default

def ask_yes_no(prompt: str, default_yes: bool = True) -> bool:
    d = "Y/n" if default_yes else "y/N"
    s = input(f"{prompt} ({d}): ").strip().lower()
    if not s:
        return default_yes
    return s in ("y", "yes", "да", "д")

# ----------------- main -----------------

def main():
    print("Eltex MES Telnet password changer v1.2 — UI + TCP-precheck + paging + save-confirm + logs (incl. creds)\n")

    targets_str = ask(
        "Введи IP/пул (CIDR, range, список через запятую)\n"
        "Пример: 10.99.0.0/24 или 10.99.0.10-10.99.0.50 или 10.99.0.10-50\n"
        "Можно так: 10.99.0.0/24,10.99.1.10-10.99.1.20,10.99.2.5"
    )
    try:
        hosts = parse_targets(targets_str)
    except Exception as e:
        print(f"Ошибка targets: {e}")
        return

    port = ask_int("Telnet порт", 23)
    timeout = ask_float("Telnet read timeout (сек)", 8.0)
    tcp_precheck_timeout = ask_float("TCP precheck timeout (сек)", 1.2)

    do_ping = ask_yes_no("Дополнительно пропинговать и пропускать без ICMP?", default_yes=False)
    ping_timeout = ask_int("Ping timeout (сек)", 1) if do_ping else 0

    threads = ask_int("Потоков (ускорение)", 20)
    if threads < 1:
        threads = 1
    if threads > 200:
        print("Слишком много потоков, ограничу до 200.")
        threads = 200

    username = ask("Текущий логин", "admin")
    password = getpass.getpass("Текущий пароль (ввод скрыт) [по умолчанию admin]: ").strip() or "admin"

    enable_pwd = None
    if ask_yes_no("Нужен enable для входа? (если после логина prompt '>')", default_yes=False):
        enable_pwd = getpass.getpass("Enable password (ввод скрыт): ").strip() or None

    target_user = ask("Какому пользователю меняем пароль", "admin")
    new_password = getpass.getpass("Новый пароль (ввод скрыт): ").strip()
    if not new_password:
        print("Новый пароль не задан — выходим.")
        return

    set_enable_pwd = None
    if ask_yes_no("Задать/обновить enable password? (enable password ...)", default_yes=True):
        set_enable_pwd = getpass.getpass("Новый enable password (Enter = использовать новый пароль): ").strip()
        if not set_enable_pwd:
            set_enable_pwd = new_password

    save = ask_yes_no("Сохранить конфиг? (write memory)", default_yes=True)

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    csv_path = f"eltex_mes_telnet_v1.2_{ts}.csv"
    log_path = f"eltex_mes_telnet_v1.2_{ts}.log"

    total = len(hosts)
    print(f"\nЦелей: {total}")
    if total <= 30:
        print("Список:", ", ".join(hosts))
    else:
        print("Первые 10:", ", ".join(hosts[:10]), "...")
    print(
        f"Threads={threads}, tcp_precheck=ON, ping={'ON' if do_ping else 'OFF'}, "
        f"save={'ON' if save else 'OFF'}\n"
    )

    lock = Lock()
    done = ok = fail = skip = 0
    results: List[Dict[str, Any]] = []

    t0 = time.time()

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [
            ex.submit(
                work_one_host,
                h, port, username, password, enable_pwd,
                target_user, new_password, set_enable_pwd, save,
                timeout, do_ping, ping_timeout, tcp_precheck_timeout
            )
            for h in hosts
        ]

        for fut in as_completed(futures):
            host, status, info = fut.result()

            with lock:
                done += 1
                if status == "OK":
                    ok += 1
                elif status.startswith("SKIP"):
                    skip += 1
                else:
                    fail += 1

                # Строка деталей для CSV/LOG — С ПАРОЛЯМИ (как ты попросил)
                if status == "OK":
                    details = (
                        f"login_user={info.get('login_user','')} "
                        f"target_user={info.get('target_user','')} "
                        f"new_user_password={info.get('new_user_password','')} "
                        f"enable_mode_used={info.get('enable_mode_used', False)} "
                        f"new_enable_password={info.get('new_enable_password','')} "
                        f"saved={info.get('saved', False)}"
                    )
                elif status.startswith("SKIP"):
                    details = info.get("reason", "")
                else:
                    details = info.get("error", "")

                results.append({
                    "host": host,
                    "status": status,
                    "details": (details or "")[:8000],
                })

                print(f"[{done}/{total}] {host}: {status} | OK={ok} FAIL={fail} SKIP={skip}")

    dt = time.time() - t0

    def ip_key(h: str):
        try:
            return int(ipaddress.ip_address(h))
        except Exception:
            return 2**128

    results.sort(key=lambda r: ip_key(r["host"]))

    # CSV
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["host", "status", "details"])
        w.writeheader()
        w.writerows(results)

    # LOG
    with open(log_path, "w", encoding="utf-8") as f:
        f.write("Eltex MES Telnet password changer v1.2\n")
        f.write(f"Targets: {targets_str}\n")
        f.write(f"Threads: {threads}\n")
        f.write(f"OK={ok} FAIL={fail} SKIP={skip} TOTAL={total}\n")
        f.write(f"Duration: {dt:.1f}s\n")
        f.write("=" * 70 + "\n")
        for r in results:
            f.write(f"{r['host']}\t{r['status']}\t{r['details']}\n")

    print(f"\nГотово за {dt:.1f}s: OK={ok}, FAIL={fail}, SKIP={skip}, TOTAL={total}")
    print(f"CSV: {csv_path}")
    print(f"LOG: {log_path}")

if __name__ == "__main__":
    main()