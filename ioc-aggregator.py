#!/usr/bin/env python3
"""
Minimal Threat Intelligence Aggregator
Collecte des IOCs depuis des APIs publiques
"""

import requests
import json
import csv
import argparse
from datetime import datetime
from typing import List, Dict, Set
from dataclasses import dataclass, asdict

# ============================================
# CONFIGURATION
# ============================================

@dataclass
class IOC:
    """Structure standard pour un IOC"""
    value: str
    type: str  # ip, domain, url, hash
    source: str
    first_seen: str
    last_seen: str
    confidence: int  # 0-100
    tags: List[str]

# ============================================
# SOURCES (APIs)
# ============================================

class ThreatSources:
    """Collecte depuis différentes APIs"""
    
    @staticmethod
    def abuseipdb(api_key: str = None) -> List[IOC]:
        """AbuseIPDB - IPs malveillantes récentes"""
        iocs = []
        url = "https://api.abuseipdb.com/api/v2/blacklist"
        headers = {"Key": api_key, "Accept": "application/json"} if api_key else {}
        
        try:
            # Version sans clé (limité)
            params = {"confidenceMinimum": 90}
            resp = requests.get(url, headers=headers, params=params, timeout=10)
            
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get('data', []):
                    iocs.append(IOC(
                        value=item.get('ipAddress'),
                        type='ip',
                        source='AbuseIPDB',
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                        confidence=item.get('abuseConfidenceScore', 50),
                        tags=['malicious', 'blacklist']
                    ))
        except Exception as e:
            print(f"[!] AbuseIPDB error: {e}")
        
        return iocs
    
    @staticmethod
    def urlhaus() -> List[IOC]:
        """URLhaus - URLs et domaines malveillants"""
        iocs = []
        url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
        
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get('urls', [])[:50]:  # Limite 50
                    iocs.append(IOC(
                        value=item.get('url'),
                        type='url',
                        source='URLhaus',
                        first_seen=item.get('firstseen', datetime.now().isoformat()),
                        last_seen=item.get('lastseen', datetime.now().isoformat()),
                        confidence=80,
                        tags=['malicious', 'url']
                    ))
        except Exception as e:
            print(f"[!] URLhaus error: {e}")
        
        return iocs
    
    @staticmethod
    def circl_lu() -> List[IOC]:
        """CIRCL.LU - Hashs malveillants"""
        iocs = []
        url = "https://hashlookup.circl.lu/lookup/feed"
        
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get('hashes', [])[:30]:
                    iocs.append(IOC(
                        value=item.get('hash'),
                        type='hash',
                        source='CIRCL',
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                        confidence=70,
                        tags=['malware', 'hash']
                    ))
        except Exception as e:
            print(f"[!] CIRCL error: {e}")
        
        return iocs
    
    @staticmethod
    def mock() -> List[IOC]:
        """Données de test (pour démo sans API)"""
        return [
            IOC("8.8.8.8", "ip", "Mock", datetime.now().isoformat(), datetime.now().isoformat(), 50, ["test"]),
            IOC("google.com", "domain", "Mock", datetime.now().isoformat(), datetime.now().isoformat(), 30, ["test"]),
        ]

# ============================================
# AGREGATEUR
# ============================================

class Aggregator:
    """Agrège, déduplique et exporte les IOCs"""
    
    def __init__(self):
        self.iocs: List[IOC] = []
        self.sources = [
            ThreatSources.urlhaus,
            ThreatSources.circl_lu,
            # ThreatSources.abuseipdb,  # Décommenter avec une clé API
        ]
    
    def collect(self, use_mock: bool = False) -> int:
        """Collecte depuis toutes les sources"""
        sources = [ThreatSources.mock] if use_mock else self.sources
        
        for source in sources:
            print(f"[*] Collecting from {source.__name__}...")
            try:
                data = source()
                self.iocs.extend(data)
                print(f"    [+] {len(data)} IOCs")
            except Exception as e:
                print(f"    [!] Error: {e}")
        
        return len(self.iocs)
    
    def deduplicate(self) -> int:
        """Supprime les doublons (basé sur value + type)"""
        seen: Set[tuple] = set()
        unique = []
        
        for ioc in self.iocs:
            key = (ioc.value, ioc.type)
            if key not in seen:
                seen.add(key)
                unique.append(ioc)
        
        removed = len(self.iocs) - len(unique)
        self.iocs = unique
        return removed
    
    def filter_by_confidence(self, threshold: int = 50) -> int:
        """Garde seulement les IOCs avec confiance >= threshold"""
        self.iocs = [ioc for ioc in self.iocs if ioc.confidence >= threshold]
        return len(self.iocs)
    
    # ============================================
    # EXPORT
    # ============================================
    
    def to_json(self, filename: str = "iocs.json") -> None:
        """Export en JSON"""
        data = [asdict(ioc) for ioc in self.iocs]
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"[*] Exported {len(data)} IOCs to {filename}")
    
    def to_csv(self, filename: str = "iocs.csv") -> None:
        """Export en CSV"""
        if not self.iocs:
            print("[!] No IOCs to export")
            return
        
        fields = ['value', 'type', 'source', 'confidence', 'tags']
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for ioc in self.iocs:
                writer.writerow({
                    'value': ioc.value,
                    'type': ioc.type,
                    'source': ioc.source,
                    'confidence': ioc.confidence,
                    'tags': ','.join(ioc.tags)
                })
        print(f"[*] Exported {len(self.iocs)} IOCs to {filename}")
    
    def to_blocklist(self, filename: str = "blocklist.txt") -> None:
        """Export en blocklist (une valeur par ligne)"""
        with open(filename, 'w') as f:
            for ioc in self.iocs:
                f.write(ioc.value + '\n')
        print(f"[*] Exported {len(self.iocs)} IOCs to {filename}")
    
    def summary(self) -> Dict:
        """Résumé statistique"""
        types = {}
        sources = {}
        
        for ioc in self.iocs:
            types[ioc.type] = types.get(ioc.type, 0) + 1
            sources[ioc.source] = sources.get(ioc.source, 0) + 1
        
        return {
            "total": len(self.iocs),
            "by_type": types,
            "by_source": sources,
            "avg_confidence": sum(ioc.confidence for ioc in self.iocs) // len(self.iocs) if self.iocs else 0
        }

# ============================================
# CLI
# ============================================

def main():
    parser = argparse.ArgumentParser(description="Minimal Threat Intelligence Aggregator")
    parser.add_argument('-m', '--mock', action='store_true', help='Use mock data (no API)')
    parser.add_argument('--confidence', type=int, default=50, help='Confidence threshold (0-100)')
    parser.add_argument('--format', choices=['json', 'csv', 'blocklist', 'all'], default='all')
    args = parser.parse_args()
    
    print("=" * 50)
    print("🛡️  Threat Intelligence Aggregator (Minimal)")
    print("=" * 50)
    
    # Collect
    aggregator = Aggregator()
    count = aggregator.collect(use_mock=args.mock)
    print(f"\n[*] Collected {count} raw IOCs")
    
    # Process
    removed = aggregator.deduplicate()
    print(f"[*] Removed {removed} duplicates")
    
    kept = aggregator.filter_by_confidence(args.confidence)
    print(f"[*] Kept {kept} IOCs (confidence >= {args.confidence})")
    
    # Summary
    summary = aggregator.summary()
    print("\n📊 Summary:")
    print(f"  Total: {summary['total']}")
    print(f"  By type: {summary['by_type']}")
    print(f"  By source: {summary['by_source']}")
    print(f"  Avg confidence: {summary['avg_confidence']}%")
    
    # Export
    print("\n📁 Exports:")
    if args.format in ['json', 'all']:
        aggregator.to_json(f"iocs_{datetime.now().strftime('%Y%m%d')}.json")
    
    if args.format in ['csv', 'all']:
        aggregator.to_csv(f"iocs_{datetime.now().strftime('%Y%m%d')}.csv")
    
    if args.format in ['blocklist', 'all']:
        aggregator.to_blocklist(f"blocklist_{datetime.now().strftime('%Y%m%d')}.txt")
    
    print("\n✅ Done!")

if __name__ == "__main__":
    main()
