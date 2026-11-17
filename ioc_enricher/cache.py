import json
import os
import time

DEFAULT_TTL = 24 * 3600  # 24 saat
CACHEABLE = {"ok", "not_found"}  # hata ve kota durumları saklanmaz


class Cache:
    def __init__(self, path="cache.json", ttl=DEFAULT_TTL, now=time.time):
        self.path = path
        self.ttl = ttl
        self.now = now
        self._data = self._load()

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (FileNotFoundError, json.JSONDecodeError):
            return {}  # dosya yok ya da bozuksa boş başla

    @staticmethod
    def _key(kind, value):
        return f"{kind}:{value}"

    def get(self, kind, value):
        entry = self._data.get(self._key(kind, value))
        if not entry:
            return None
        if self.now() - entry["ts"] > self.ttl:
            return None  # süresi dolmuş
        return entry["result"]

    def set(self, kind, value, result):
        if result.get("status") not in CACHEABLE:
            return
        self._data[self._key(kind, value)] = {
            "ts": self.now(), "result": result}

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)
