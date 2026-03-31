import asyncio
from server import call_tool

async def test_partial_company_search():
    print("\n--- Testing Partial Company Name Search ---")
    args = {
        "api_key": "tz_cust1_key",
        "query": "Laptop",
        "company": "Tech"
    }
    result = await call_tool("search_products", args)
    print(f"Search for Laptop in 'Tech': {result[0].text}")

if __name__ == "__main__":
    asyncio.run(test_partial_company_search())
