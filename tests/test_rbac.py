import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import Database
from security import SecurityManager

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "ecommerce.db")


def test_customer_can_access_customer_tools():
    security = SecurityManager()

    success, msg = security.authorize("search_products", "customer")
    assert success is True

    success, msg = security.authorize("get_product_details", "customer")
    assert success is True

    success, msg = security.authorize("place_order", "customer")
    assert success is True

    success, msg = security.authorize("track_order", "customer")
    assert success is True

    success, msg = security.authorize("get_order_history", "customer")
    assert success is True


def test_customer_blocked_from_add_product():
    security = SecurityManager()

    success, msg = security.authorize("add_product", "customer")

    assert success is False
    assert "admin role required" in msg


def test_customer_blocked_from_update_inventory():
    security = SecurityManager()

    success, msg = security.authorize("update_inventory", "customer")

    assert success is False
    assert "admin role required" in msg


def test_customer_blocked_from_view_all_orders():
    security = SecurityManager()

    success, msg = security.authorize("view_all_orders", "customer")

    assert success is False
    assert "admin role required" in msg


def test_customer_blocked_from_update_order_status():
    security = SecurityManager()

    success, msg = security.authorize("update_order_status", "customer")

    assert success is False
    assert "admin role required" in msg


def test_customer_blocked_from_sales_summary():
    security = SecurityManager()

    success, msg = security.authorize("sales_summary", "customer")

    assert success is False
    assert "admin role required" in msg


def test_customer_blocked_from_rotate_api_key():
    security = SecurityManager()

    success, msg = security.authorize("rotate_api_key", "customer")

    assert success is False
    assert "admin role required" in msg


def test_customer_blocked_from_view_security_alerts():
    security = SecurityManager()

    success, msg = security.authorize("view_security_alerts", "customer")

    assert success is False
    assert "admin role required" in msg


def test_admin_can_access_all_customer_tools():
    security = SecurityManager()

    success, msg = security.authorize("search_products", "admin")
    assert success is True

    success, msg = security.authorize("get_product_details", "admin")
    assert success is True

    success, msg = security.authorize("place_order", "admin")
    assert success is True


def test_admin_can_access_all_admin_tools():
    security = SecurityManager()

    success, msg = security.authorize("add_product", "admin")
    assert success is True

    success, msg = security.authorize("update_inventory", "admin")
    assert success is True

    success, msg = security.authorize("view_all_orders", "admin")
    assert success is True

    success, msg = security.authorize("update_order_status", "admin")
    assert success is True

    success, msg = security.authorize("sales_summary", "admin")
    assert success is True

    success, msg = security.authorize("rotate_api_key", "admin")
    assert success is True

    success, msg = security.authorize("view_security_alerts", "admin")
    assert success is True


def test_global_customer_can_access_customer_tools():
    security = SecurityManager()

    success, msg = security.authorize("search_products", "global_customer")
    assert success is True

    success, msg = security.authorize("place_order", "global_customer")
    assert success is True

    success, msg = security.authorize("get_order_history", "global_customer")
    assert success is True


def test_global_customer_blocked_from_admin_tools():
    security = SecurityManager()

    success, msg = security.authorize("add_product", "global_customer")
    assert success is False

    success, msg = security.authorize("update_inventory", "global_customer")
    assert success is False

    success, msg = security.authorize("sales_summary", "global_customer")
    assert success is False


def test_global_customer_can_search_all_companies():
    db = Database(DB_PATH)

    # Search for generic term that should match products in both companies
    # TechZone has "Laptop" and "Mouse", SportsPro has "Football" and "Jersey"
    all_products = db.search_products("", company_id=None, limit=50)

    company_ids = set(p['company_id'] for p in all_products if p['company_id'] is not None)
    assert len(company_ids) >= 2, f"Global customer should find products from multiple companies, found: {company_ids}"


def test_invalid_role_is_rejected():
    security = SecurityManager()

    success, msg = security.authorize("search_products", "invalid_role")

    assert success is False
    assert "Unknown role" in msg
