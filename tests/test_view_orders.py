#!/usr/bin/env python3

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import Database
from security import SecurityManager

# Use absolute path
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ecommerce.db")

def test_view_orders(api_key: str):
    """Simulate the view_orders MCP tool"""

    print("=" * 80)
    print("TESTING VIEW_ORDERS TOOL")
    print("=" * 80)
    print(f"API Key: {api_key}")
    print()

    # Initialize
    db = Database(DB_PATH)
    security = SecurityManager()

    # Step 1: Authenticate
    print("Step 1: Authentication")
    print("-" * 80)
    success, user, msg = security.authenticate(db, api_key)

    if not success:
        print(f"❌ Authentication FAILED: {msg}")
        return

    print(f"✅ Authentication SUCCESS")
    print(f"   User: {user.get('name')}")
    print(f"   Email: {user.get('email')}")
    print(f"   Role: {user.get('role')}")
    print(f"   Customer ID: {user.get('customer_id')}")
    print(f"   User ID (for queries): {user.get('id')}")  # This should match customer_id
    print()

    # Step 2: Check authorization
    print("Step 2: Authorization")
    print("-" * 80)
    authorized, auth_msg = security.authorize("view_orders", user['role'])

    if not authorized:
        print(f"❌ Authorization FAILED: {auth_msg}")
        return

    print(f"✅ Authorization SUCCESS: {user['role']} can view_orders")
    print()

    # Step 3: Get orders
    print("Step 3: Query Orders")
    print("-" * 80)

    customer_id = user.get('id')
    if customer_id is None:
        print("❌ ERROR: user['id'] is None - BUG NOT FIXED!")
        print("   The authentication didn't set user['id'] properly")
        return

    print(f"Querying orders for customer_id = {customer_id}")

    import sqlite3
    conn = db.get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT o.order_id, o.product_id, o.quantity, o.total_price, o.status, o.created_at,
               p.name as product_name, c.name as company_name
        FROM orders o
        JOIN products p ON o.product_id = p.product_id
        JOIN companies c ON p.company_id = c.company_id
        WHERE o.customer_id = ?
        ORDER BY o.created_at DESC
        LIMIT 50
    ''', (customer_id,))

    rows = cursor.fetchall()
    conn.close()

    print(f"Found: {len(rows)} orders")
    print()

    if len(rows) == 0:
        print("❌ NO ORDERS FOUND")
        print()
        print("Possible reasons:")
        print("  1. This customer hasn't placed any orders")
        print("  2. The customer_id mapping is wrong")
        print("  3. Database not seeded properly")
        return

    # Step 4: Display orders
    print("=" * 80)
    print(f"ORDER HISTORY FOR {user.get('email')}")
    print("=" * 80)
    print()

    total_spent = 0

    for row in rows:
        order_id, prod_id, qty, total, status, created, prod_name, company = row

        print(f"📦 Order #{order_id}")
        print(f"   Date: {created}")
        print(f"   Product: {prod_name}")
        print(f"   Company: {company}")
        print(f"   Quantity: {qty}")
        print(f"   Total: ${total:.2f}")
        print(f"   Status: {status.upper()}")
        print()

        total_spent += total

    print("=" * 80)
    print(f"SUMMARY:")
    print(f"  Total Orders: {len(rows)}")
    print(f"  Total Spent: ${total_spent:.2f}")
    print("=" * 80)
    print()

    print("✅ ✅ ✅ SUCCESS! This is what Claude Desktop SHOULD show you!")


if __name__ == "__main__":
    print()
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 20 + "DIRECT TOOL TEST - VIEW ORDERS" + " " * 28 + "║")
    print("╚" + "=" * 78 + "╝")
    print()

    # Test different API keys
    test_cases = [
        ("global_shopper_key_2024", "Global Customer"),
        ("techzone_sarah_key_2024", "Sarah (TechZone Customer)"),
    ]

    for api_key, description in test_cases:
        print()
        print(f"TESTING: {description}")
        print()
        test_view_orders(api_key)
        print()
        print()
