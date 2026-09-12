import os
import sys
import time

# Add parent directory to path to allow running directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ephemguard.security.schema_verifier import SchemaVerifier

def main():
    schema={"tools":[{"name":"filesystem_read","inputSchema":{"type":"object"}}]}
    v = SchemaVerifier()
    v.pin_schema("bench", schema)
    
    start = time.perf_counter()
    for _ in range(1000): 
        v.verify_schema("bench", schema)
    elapsed = (time.perf_counter()-start)*1000
    
    print(f"1000 schema-verification operations: {elapsed:.3f} ms; average {elapsed/1000:.6f} ms")

if __name__ == "__main__":
    main()
