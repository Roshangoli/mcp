import asyncio
from server import call_tool
from database import Database
import os

async def test_log_sanitization():
    print("\n--- Testing Log Sanitization for rotate_api_key ---")

    # 1. Rotate a key as admin
    args = {
        "api_key": "tz_admin_secret_123",
        "customer_email": "alice@gmail.com"
    }
    result = await call_tool("rotate_api_key", args)
    new_key_text = result[0].text

    if "NEW API KEY:" in new_key_text:
        # Extract the new key roughly
        import re
        match = re.search(r"NEW API KEY: (\S+)", new_key_text)
        if match:
            new_key = match.group(1)
            print(f"Generated new key: {new_key[:5]}...")

            # 2. Check the database audit logs
            db = Database("ecommerce.db")
            conn = db.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT result FROM audit_logs WHERE tool_name = 'rotate_api_key' ORDER BY log_id DESC LIMIT 1")
            row = cursor.fetchone()
            log_result = row['result']
            conn.close()

            print(f"Log content: {log_result}")

            if new_key in log_result:
                print("SECURITY VULNERABILITY: Plain-text API key found in logs!")
            else:
                print("SECURE: API key was redacted from logs.")

if __name__ == "__main__":
    asyncio.run(test_log_sanitization())
