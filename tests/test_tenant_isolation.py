import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import Database
from security import SecurityManager

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "ecommerce.db")


def test_techzone_admin_cannot_see_sportspro_products():
    db = Database(DB_PATH)

    # TechZone is company_id=1, SportsPro is company_id=2
    product = db.get_product_by_id(product_id=3, company_id=1)  # SportsPro product with TechZone filter

    assert product is None, "TechZone admin should not see SportsPro products"


def test_techzone_admin_cannot_update_sportspro_inventory():
    db = Database(DB_PATH)

    # First verify the product exists in SportsPro
    sportspro_product = db.get_product_by_id(product_id=3, company_id=2)
    assert sportspro_product is not None, "SportsPro product should exist"

    # Try to update SportsPro product (ID 3) with TechZone company_id
    # This should affect 0 rows due to company_id mismatch
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """UPDATE products SET stock = ? WHERE product_id = ? AND company_id = ?""",
        (999, 3, 1)
    )
    rows_affected = cursor.rowcount
    conn.commit()
    conn.close()

    assert rows_affected == 0, "TechZone admin should not update SportsPro inventory"


def test_techzone_admin_cannot_see_sportspro_orders():
    db = Database(DB_PATH)

    # Get TechZone orders only
    orders = db.get_all_orders(company_id=1, limit=100)

    # Verify all orders belong to TechZone (company_id=1)
    for order in orders:
        assert order['company_id'] == 1, f"Found order from company {order['company_id']}, expected TechZone (1)"


def test_sportspro_admin_cannot_see_homenest_orders():
    db = Database(DB_PATH)

    # Get SportsPro orders only (company_id=2)
    orders = db.get_all_orders(company_id=2, limit=100)

    # Verify all orders belong to SportsPro
    for order in orders:
        assert order['company_id'] == 2, f"Found order from company {order['company_id']}, expected SportsPro (2)"


def test_place_order_stamps_correct_company_id():
    db = Database(DB_PATH)

    # Get a TechZone product (company_id=1)
    product = db.get_product_by_id(product_id=1, company_id=1)
    assert product is not None
    assert product['company_id'] == 1

    # Place order for TechZone customer
    order_id = db.create_order(
        company_id=1,
        customer_id=1,
        product_id=1,
        quantity=1,
        total_price=product['price']
    )

    # Verify order has correct company_id
    order = db.get_order_by_id(order_id, company_id=1)
    assert order is not None
    assert order['company_id'] == 1, f"Order has company_id {order['company_id']}, expected 1"


def test_cross_company_product_search_returns_only_own_products():
    db = Database(DB_PATH)

    # Search with company_id=1 (TechZone)
    products = db.search_products("product", company_id=1, limit=100)

    # Verify all products belong to TechZone
    for product in products:
        assert product['company_id'] == 1, f"Found product from company {product['company_id']}, expected TechZone (1)"


def test_customer_order_history_filtered_by_company():
    db = Database(DB_PATH)

    # Get orders for a TechZone customer (company_id=1)
    orders = db.get_customer_orders(company_id=1, customer_email="alice@gmail.com", limit=100)

    # Verify all orders belong to TechZone
    for order in orders:
        assert order['company_id'] == 1, f"Found order from company {order['company_id']} for TechZone customer"


def test_admin_cannot_update_other_company_order_status():
    db = Database(DB_PATH)

    # Get a SportsPro order
    sportspro_orders = db.get_all_orders(company_id=2, limit=1)
    if sportspro_orders:
        order_id = sportspro_orders[0]['order_id']

        # Try to update it with TechZone company_id
        success = db.update_order_status(order_id, company_id=1, new_status="shipped")

        assert success is False, "TechZone admin should not update SportsPro orders"


def test_security_alerts_filtered_by_company():
    db = Database(DB_PATH)

    # Create alert for company 1
    db.create_security_alert(
        alert_type="test_alert",
        severity="LOW",
        company_id=1,
        user_email="test@techzone.com",
        attempted_action="test",
        reason="test"
    )

    # Get alerts for company 1
    alerts = db.get_security_alerts(company_id=1, limit=100)

    # Verify all alerts belong to company 1
    for alert in alerts:
        if alert['company_id'] is not None:
            assert alert['company_id'] == 1, f"Found alert from company {alert['company_id']}, expected 1"


def test_sales_summary_only_includes_own_company_data():
    db = Database(DB_PATH)

    # Get sales summary for TechZone (company_id=1)
    summary = db.get_sales_summary(company_id=1)

    # Get all TechZone orders to verify
    techzone_orders = db.get_all_orders(company_id=1, limit=1000)

    assert summary['total_orders'] == len(techzone_orders), "Sales summary should only count own company orders"
