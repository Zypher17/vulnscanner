import csv
import os
from typing import List, Dict

class SearchSploit:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.exploits = self._load_db()

    def _load_db(self) -> List[Dict]:
        exploits = []
        if not os.path.exists(self.db_path):
            return exploits
        
        with open(self.db_path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                exploits.append(row)
        return exploits

    def search(self, query: str) -> List[Dict]:
        query = query.lower()
        results = []
        for exp in self.exploits:
            if query in exp['description'].lower() or query in exp['id']:
                results.append(exp)
        return results

    def match_service(self, service: str, version: str = None) -> List[Dict]:
        query = service.lower()
        if version:
            query = f"{service} {version}".lower()
        
        return self.search(query)
