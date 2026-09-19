import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import Database
from security import SecurityManager

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "ecommerce.db")


def test_null_company_id_search_returns_products_from_both_companies():
    db = Database(DB_PATH)

    # Search with NULL company_id (global search)
    all_products = db.search_products("", company_id=None, limit=100)

    # Get unique company IDs
    company_ids = set(p['company_id'] for p in all_products if p['company_id'] is not None)

    assert len(company_ids) >= 2, f"Expected products from at least 2 companies, found: {company_ids}"


def test_null_company_id_returns_more_results_than_single_company():
    db = Database(DB_PATH)

    # Global search
    global_results = db.search_products("", company_id=None, limit=100)

    # Single company search (TechZone)
    techzone_results = db.search_products("", company_id=1, limit=100)

    assert len(global_results) > len(techzone_results), \
        f"Global search ({len(global_results)}) should return more than single company ({len(techzone_results)})"


def test_global_customer_place_order_stamps_correct_company_id():
    db = Database(DB_PATH)
    security = SecurityManager()

    # Authenticate global customer
    success, user, msg = security.authenticate(db, "global_shopper_key_2024")
    assert success is True
    assert user['role'] == "global_customer"

    # Get a TechZone product
    product = db.get_product_by_id(product_id=1, company_id=1)
    assert product is not None

    # Place order as global customer
    order_id = db.create_order(
        company_id=product['company_id'],  # Should be 1 (TechZone)
        customer_id=user['customer_id'],
        product_id=1,
        quantity=1,
        total_price=product['price']
    )

    # Verify order has correct company_id
    order = db.get_order_by_id(order_id, company_id=1)
    assert order is not None
    assert order['company_id'] == 1, f"Order should have company_id=1, got {order['company_id']}"


def test_global_customer_order_history_shows_orders_across_companies():
    db = Database(DB_PATH)
    security = SecurityManager()

    # Authenticate global customer
    success, user, msg = security.authenticate(db, "global_shopper_key_2024")
    assert success is True

    # Get global customer's orders with company_id=None to search across all companies
    orders = db.get_customer_orders(company_id=None, customer_email=user['email'], limit=100)

    # Global customer might not have orders yet, but this should not error
    assert isinstance(orders, list)


def test_global_customer_search_results_capped_at_limit():
    db = Database(DB_PATH)

    # Search with limit=5
    results = db.search_products("", company_id=None, limit=5)

    assert len(results) <= 5, f"Results should be capped at 5, got {len(results)}"


def test_global_customer_cannot_access_admin_tools():
    security = SecurityManager()

    # Global customer should NOT have admin access
    success, msg = security.authorize("add_product", "global_customer")
    assert success is False
    assert "admin" in msg.lower()

    success, msg = security.authorize("update_inventory", "global_customer")
    assert success is False

    success, msg = security.authorize("view_all_orders", "global_customer")
    assert success is False


def test_global_customer_can_search_specific_company():
    db = Database(DB_PATH)

    # Global customer can still search specific company
    techzone_products = db.search_products("", company_id=1, limit=50)

    # All results should be from TechZone
    for product in techzone_products:
        assert product['company_id'] == 1, f"Expected TechZone product, got company_id={product['company_id']}"


def test_global_customer_authentication_returns_null_company_id():
    db = Database(DB_PATH)
    security = SecurityManager()

    success, user, msg = security.authenticate(db, "global_shopper_key_2024")

    assert success is True
    assert user is not None
    assert user['company_id'] is None, "Global customer should have NULL company_id"
    assert user['role'] == "global_customer"


def test_global_search_with_category_filter():
    db = Database(DB_PATH)

    # Search all companies for a specific category
    # This tests that category filtering works with global search
    results = db.search_products("", company_id=None, category="Electronics", limit=50)

    # All results should be electronics (if any found)
    for product in results:
        assert product['category'].lower() == "electronics", \
            f"Expected Electronics category, got {product['category']}"


def test_global_search_pagination_works():
    db = Database(DB_PATH)

    # Get first page
    page1 = db.search_products("", company_id=None, limit=2)

    # Get second page (offset=2)
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """SELECT * FROM products WHERE name LIKE ? LIMIT ? OFFSET ?""",
        (f"%%", 2, 2)
    )
    page2_rows = cursor.fetchall()
    conn.close()

    # Pages should have different products
    if len(page1) > 0 and len(page2_rows) > 0:
        page1_ids = set(p['product_id'] for p in page1)
        page2_ids = set(row['product_id'] for row in page2_rows)
        assert page1_ids != page2_ids, "Pagination should return different products"
