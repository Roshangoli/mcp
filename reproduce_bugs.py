import asyncio
import os
import sqlite3
from server import call_tool
from mcp.types import TextContent

async def test_idor_track_order():
    print("\n--- Testing IDOR in track_order ---")
    # Alice (tz_cust1_key) has orders 1 and 2. Charlie (sp_cust1_key) has order 3.
    # Let's see if Charlie can track Alice's order (ID 1).
    args = {
        "api_key": "sp_cust1_key",
        "order_id": 1
    }
    result = await call_tool("track_order", args)
    print(f"Charlie tracking Alice's order (ID 1): {result[0].text}")
    if "Order ID: 1" in result[0].text and "alice@gmail.com" in result[0].text:
        print("VULNERABLE: Charlie successfully tracked Alice's order!")
    else:
        print("SECURE: Charlie could not track Alice's order.")

async def test_idor_order_history():
    print("\n--- Testing IDOR in get_order_history ---")
    # Bob (tz_cust2_key) tries to see Alice's history.
    args = {
        "api_key": "tz_cust2_key",
        "customer_email": "alice@gmail.com"
    }
    result = await call_tool("get_order_history", args)
    print(f"Bob viewing Alice's order history: {result[0].text}")
    if "Order History for alice@gmail.com" in result[0].text:
        print("VULNERABLE: Bob successfully viewed Alice's history!")
    else:
        print("SECURE: Bob could not view Alice's history.")

async def test_race_condition():
    print("\n--- Testing Race Condition in place_order (Conceptual) ---")
    # We will simulate concurrent requests.
    # TechZone Laptop (p1_id=1) has 10 in stock.
    # If 11 people try to buy it at the same time, it should fail for one.

    tasks = []
    for _ in range(11):
        args = {
            "api_key": "tz_cust1_key",
            "product_id": 1,
            "quantity": 1
        }
        tasks.append(call_tool("place_order", args))

    results = await asyncio.gather(*tasks)

    success_count = 0
    for r in results:
        if "Order Placed Successfully" in r[0].text:
            success_count += 1

    print(f"Total successful orders: {success_count} out of 11 requests (Initial stock: 10)")
    if success_count > 10:
        print("VULNERABLE: Overselling detected!")
    else:
        print("SECURE: Stock handled correctly (but might still be vulnerable to actual high-concurrency race).")

async def test_search_filtering():
    print("\n--- Testing Search Filtering in search_products ---")
    # Try searching for "Laptop" in company "SportsPro"
    # Laptops are only in "TechZone".
    args = {
        "api_key": "tz_cust2_key",
        "query": "Laptop",
        "company": "SportsPro"
    }
    result = await call_tool("search_products", args)
    print(f"Search for Laptop in SportsPro: {result[0].text}")
    if "Laptop" in result[0].text and "TechZone" in result[0].text:
        print("LOGIC BUG: Found TechZone laptop when searching in SportsPro!")
    else:
        print("OK: Filtering worked as expected (in-memory).")

async def test_global_customer_history():
    print("\n--- Testing global_customer cross-company history ---")
    # Place orders in different companies for global user
    # Use products that have stock (p2_id=2 and p3_id=3)
    await call_tool("place_order", {"api_key": "global_cust_key", "product_id": 2, "quantity": 1}) # TechZone
    await call_tool("place_order", {"api_key": "global_cust_key", "product_id": 3, "quantity": 1}) # SportsPro

    args = {
        "api_key": "global_cust_key",
        "customer_email": "global@world.com"
    }
    result = await call_tool("get_order_history", args)
    print(f"Global user history: {result[0].text}")
    # Currently it will probably only show orders for one or no company because user_data['company_id'] is None
    # and db.get_customer_orders(None, email) is called.
    # Actually if user_data['company_id'] is None, it calls db.get_customer_orders(None, email)
    # which uses "WHERE o.company_id = ? AND c.email = ?" - this will fail to find anything.

async def run_tests():
    await test_idor_track_order()
    await test_idor_order_history()
    await test_race_condition()
    await test_search_filtering()
    await test_global_customer_history()

if __name__ == "__main__":
    asyncio.run(run_tests())
