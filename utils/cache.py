"""
ResultCache provides a persistent store to avoid redundant checks, 
improving scan speed by orders of magnitude for large ranges.
"""
import json
import os

class ResultCache:
    def __init__(self, cache_file="scan_cache.json"):
        self.cache_file = cache_file
        self.cache = self._load()

    def _load(self):
        if os.path.exists(self.cache_file):
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        return {}

    def get(self, target, port):
        return self.cache.get(f"{target}:{port}")

    def set(self, target, port, result):
        self.cache[f"{target}:{port}"] = result
        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f)
