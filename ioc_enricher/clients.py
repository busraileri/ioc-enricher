import base64
import os
import time

import requests
from dotenv import load_dotenv

load_dotenv()

API_BASE = "https://www.virustotal.com/api/v3"
MIN_INTERVAL = 15.5  # Ücretsiz kota dakikada 4 istek: 60 sn / 4 + pay

ENDPOINTS = {
    "md5": "files",
    "sha1": "files",
    "sha256": "files",
    "ip": "ip_addresses",
    "domain": "domains",
}


def url_to_id(url: str) -> str:
    """VirusTotal URL kimliği: dolgusuz, URL-güvenli base64."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


class VirusTotalClient:
    def __init__(self, api_key=None, session=None, min_interval=MIN_INTERVAL, sleep=time.sleep):
        self.api_key = api_key or os.getenv("VT_API_KEY")
        if not self.api_key:
            raise RuntimeError(
                "VT_API_KEY bulunamadı. .env dosyasını kontrol et.")
        self.session = session or requests.Session()
        self.min_interval = min_interval
        self.sleep = sleep
        self._last_request = 0.0

    def _wait_turn(self):
        """İstekler arası asgari süreyi korur (hız sınırı)."""
        elapsed = time.monotonic() - self._last_request
        if elapsed < self.min_interval and self._last_request:
            self.sleep(self.min_interval - elapsed)
        self._last_request = time.monotonic()

    def _build_path(self, kind: str, value: str) -> str:
        if kind == "url":
            return f"urls/{url_to_id(value)}"
        return f"{ENDPOINTS[kind]}/{value}"

    def lookup(self, kind: str, value: str, retries: int = 2) -> dict:
        """Göstergeyi sorgular. Hiçbir zaman dosya ya da URL göndermez, yalnızca sorar."""
        if kind not in ENDPOINTS and kind != "url":
            return {"status": "error", "detail": f"desteklenmeyen tür: {kind}"}

        url = f"{API_BASE}/{self._build_path(kind, value)}"
        headers = {"x-apikey": self.api_key, "accept": "application/json"}

        for attempt in range(retries + 1):
            self._wait_turn()
            try:
                r = self.session.get(url, headers=headers, timeout=15)
            except requests.RequestException as exc:
                return {"status": "error", "detail": f"ağ hatası: {type(exc).__name__}"}

            if r.status_code == 200:
                return self._parse(r.json())
            if r.status_code == 404:
                return {"status": "not_found", "detail": "VirusTotal'de kayıt yok (temiz demek değildir)"}
            if r.status_code == 401:
                return {"status": "error", "detail": "API anahtarı geçersiz"}
            if r.status_code == 429:
                if attempt < retries:
                    self.sleep(60)
                    continue
                return {"status": "rate_limited", "detail": "kota aşıldı, sonra tekrar dene"}
            return {"status": "error", "detail": f"beklenmeyen yanıt: HTTP {r.status_code}"}

        return {"status": "error", "detail": "bilinmeyen hata"}

    @staticmethod
    def _parse(payload: dict) -> dict:
        attrs = payload.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "status": "ok",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "detail": "",
        }
