import sys
import json
from core.client import BridgeClient

def main():
    print("=== Antigravity IDA Bridge Verification ===")
    client = BridgeClient()
    print(f"Server URL: {client.base_url}")
    
    # Check online status
    print("Checking connection to IDA Bridge...")
    ping_res = client.ping()
    if "error" in ping_res:
        print(f"FAILED: Could not connect to bridge. Reason: {ping_res['error']}")
        print("\nPlease ensure:")
        print("1. IDA Pro is running.")
        print("2. The Antigravity Bridge plugin is loaded (Ctrl+Shift+A pressed inside IDA).")
        print("3. Check that the port matches (default 13370).")
        sys.exit(1)
        
    print("SUCCESS: Connected to IDA Bridge!")
    print(f"Ping Response: {json.dumps(ping_res, indent=2)}")
    
    # Get binary info
    info_res = client.info()
    print("\nRetrieving Loaded Binary Metadata...")
    print(json.dumps(info_res, indent=2))
    
    print("\n==========================================")
    print("VERIFICATION COMPLETED SUCCESSFULLY!")
    print("==========================================")

if __name__ == "__main__":
    main()
