import hashlib, json

def chain_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()

def verify_chain(path: str) -> bool:
    previous = "0" * 64
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                entry = json.loads(line)
                if entry.get("prev_hash") != previous:
                    return False
                actual = chain_hash(entry)
                if actual != entry.get("hash"):
                    return False
                previous = actual
    except (OSError, json.JSONDecodeError, TypeError):
        return False
    return True
