import os
import sqlite3
from database import Database
from security import security_manager
from datetime import datetime, timedelta

def seed():
    db_path = "ecommerce.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    db = Database(db_path)

    # 1. Create Companies
    techzone_id = db.create_company("TechZone", security_manager.hash_api_key("techzone_key"))
    sportspro_id = db.create_company("SportsPro", security_manager.hash_api_key("sportspro_key"))

    # 2. Create Admins
    # TechZone Admin
    tz_admin_key = "tz_admin_secret_123"
    tz_admin_salt = security_manager.generate_salt()
    tz_admin_hash = security_manager.hash_api_key(tz_admin_key, tz_admin_salt)
    tz_admin_lookup = security_manager.hash_api_key(tz_admin_key, "lookup_salt_constant")
    db.create_customer(techzone_id, "TZ Admin", "admin@techzone.com", "admin", tz_admin_hash, tz_admin_salt, tz_admin_lookup)

    # SportsPro Admin
    sp_admin_key = "sp_admin_secret_456"
    sp_admin_salt = security_manager.generate_salt()
    sp_admin_hash = security_manager.hash_api_key(sp_admin_key, sp_admin_salt)
    sp_admin_lookup = security_manager.hash_api_key(sp_admin_key, "lookup_salt_constant")
    db.create_customer(sportspro_id, "SP Admin", "admin@sportspro.com", "admin", sp_admin_hash, sp_admin_salt, sp_admin_lookup)

    # 3. Create Customers
    # TechZone Customer 1
    tz_c1_key = "tz_cust1_key"
    tz_c1_salt = security_manager.generate_salt()
    tz_c1_hash = security_manager.hash_api_key(tz_c1_key, tz_c1_salt)
    tz_c1_lookup = security_manager.hash_api_key(tz_c1_key, "lookup_salt_constant")
    tz_c1_id = db.create_customer(techzone_id, "TZ Customer 1", "alice@gmail.com", "customer", tz_c1_hash, tz_c1_salt, tz_c1_lookup)

    # TechZone Customer 2
    tz_c2_key = "tz_cust2_key"
    tz_c2_salt = security_manager.generate_salt()
    tz_c2_hash = security_manager.hash_api_key(tz_c2_key, tz_c2_salt)
    tz_c2_lookup = security_manager.hash_api_key(tz_c2_key, "lookup_salt_constant")
    tz_c2_id = db.create_customer(techzone_id, "TZ Customer 2", "bob@gmail.com", "customer", tz_c2_hash, tz_c2_salt, tz_c2_lookup)

    # SportsPro Customer 1
    sp_c1_key = "sp_cust1_key"
    sp_c1_salt = security_manager.generate_salt()
    sp_c1_hash = security_manager.hash_api_key(sp_c1_key, sp_c1_salt)
    sp_c1_lookup = security_manager.hash_api_key(sp_c1_key, "lookup_salt_constant")
    sp_c1_id = db.create_customer(sportspro_id, "SP Customer 1", "charlie@gmail.com", "customer", sp_c1_hash, sp_c1_salt, sp_c1_lookup)

    # Global Customer
    global_key = "global_cust_key"
    global_salt = security_manager.generate_salt()
    global_hash = security_manager.hash_api_key(global_key, global_salt)
    global_lookup = security_manager.hash_api_key(global_key, "lookup_salt_constant")
    global_id = db.create_customer(None, "Global User", "global@world.com", "global_customer", global_hash, global_salt, global_lookup)

    # 4. Create Products
    # TechZone Products
    p1_id = db.create_product(techzone_id, "Laptop", "Electronics", 1200.00, 10, "High-end gaming laptop")
    p2_id = db.create_product(techzone_id, "Mouse", "Electronics", 25.00, 50, "Wireless mouse")

    # SportsPro Products
    p3_id = db.create_product(sportspro_id, "Football", "Sports", 30.00, 100, "Official match ball")
    p4_id = db.create_product(sportspro_id, "Jersey", "Apparel", 60.00, 5, "Home team jersey")

    # 5. Create some initial orders
    # Alice (TZ) buys a laptop
    db.create_order(techzone_id, tz_c1_id, p1_id, 1, 1200.00)
    # Alice (TZ) buys a mouse
    db.create_order(techzone_id, tz_c1_id, p2_id, 1, 25.00)
    # Charlie (SP) buys a football
    db.create_order(sportspro_id, sp_c1_id, p3_id, 2, 60.00)

    print("Database seeded successfully!")
    print(f"TZ Customer 1 Key: {tz_c1_key} (alice@gmail.com)")
    print(f"TZ Customer 2 Key: {tz_c2_key} (bob@gmail.com)")
    print(f"SP Customer 1 Key: {sp_c1_key} (charlie@gmail.com)")
    print(f"Global Customer Key: {global_key} (global@world.com)")
    print(f"TZ Admin Key: {tz_admin_key}")

if __name__ == "__main__":
    seed()
