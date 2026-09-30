"""Hash identification."""

from . import module

CANDIDATES = {
    32: ["MD5", "NTLM", "MD4", "LM"],
    40: ["SHA-1", "RIPEMD-160", "MySQL5 (without *)"],
    56: ["SHA-224", "SHA3-224"],
    64: ["SHA-256", "SHA3-256", "BLAKE2s-256"],
    96: ["SHA-384", "SHA3-384"],
    128: ["SHA-512", "SHA3-512", "BLAKE2b-512", "Whirlpool"],
}


@module("hash", "Hash Identifier", ["hash"],
        "Likely algorithms, plus malware and crack-database lookups.", order=5)
def identify(value):
    algos = CANDIDATES.get(len(value), [])
    file_hash = len(value) in (32, 40, 64)
    return {
        "length": len(value),
        "bits": len(value) * 4,
        "likely": algos[0] if algos else None,
        "candidates": algos,
        "file_hash": file_hash,
        "lookups": [
            {"name": "VirusTotal", "url": f"https://www.virustotal.com/gui/search/{value}"},
            {"name": "MalwareBazaar", "url": f"https://bazaar.abuse.ch/browse.php?search=sha256%3A{value}"
             if len(value) == 64 else f"https://bazaar.abuse.ch/browse.php?search={value}"},
            {"name": "Hybrid Analysis", "url": f"https://www.hybrid-analysis.com/search?query={value}"},
            {"name": "CrackStation", "url": "https://crackstation.net/"},
            {"name": "Hashes.com", "url": f"https://hashes.com/en/decrypt/hash?hashes={value}"},
            {"name": "Google", "url": f"https://www.google.com/search?q=%22{value}%22"},
        ],
    }
