import sqlite3
import os
from datetime import datetime
from typing import Optional, List, Dict, Any


class Database:
    def __init__(self, db_path: str = "ecommerce.db"):
        # Convert to absolute path to ensure database is always found
        if not os.path.isabs(db_path):
            # If relative path, make it relative to this file's directory
            script_dir = os.path.dirname(os.path.abspath(__file__))
            self.db_path = os.path.join(script_dir, db_path)
        else:
            self.db_path = db_path
        self.init_database()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_database(self):
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS companies (
                company_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                api_key_hash TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Products table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS products (
                product_id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                price REAL NOT NULL,
                stock INTEGER NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (company_id) REFERENCES companies(company_id)
            )
        """)

        # Customers table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS customers (
                customer_id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_id INTEGER,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('customer', 'admin', 'global_customer')),
                api_key_hash TEXT NOT NULL UNIQUE,
                api_key_salt TEXT NOT NULL,
                api_key_lookup_hash TEXT NOT NULL UNIQUE,
                expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (company_id) REFERENCES companies(company_id)
            )
        """)

        # Create index for faster lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_customers_email
            ON customers(email, company_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_customers_lookup_hash
            ON customers(api_key_lookup_hash)
        """)

        # Orders table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                order_id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_id INTEGER NOT NULL,
                customer_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                total_price REAL NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (company_id) REFERENCES companies(company_id),
                FOREIGN KEY (customer_id) REFERENCES customers(customer_id),
                FOREIGN KEY (product_id) REFERENCES products(product_id)
            )
        """)

        # Audit logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tool_name TEXT NOT NULL,
                company_id INTEGER,
                user_email TEXT,
                role TEXT,
                input_params TEXT,
                result TEXT,
                success BOOLEAN NOT NULL,
                execution_time_ms REAL,
                result_count INTEGER,
                session_id TEXT
            )
        """)

        # Rate limit log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rate_limit_log (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key_hash TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tool_name TEXT NOT NULL
            )
        """)

        # Create index for rate limit queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_rate_limit_timestamp
            ON rate_limit_log(api_key_hash, timestamp)
        """)

        # Security alerts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_alerts (
                alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                alert_type TEXT NOT NULL,
                api_key_hash TEXT,
                user_email TEXT,
                company_id INTEGER,
                attempted_action TEXT,
                reason TEXT,
                severity TEXT NOT NULL CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
            )
        """)

        # Create index for security alerts
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_alerts_company
            ON security_alerts(company_id, timestamp DESC)
        """)

        conn.commit()
        conn.close()

    # ==================== COMPANY OPERATIONS ====================

    def create_company(self, name: str, api_key_hash: str) -> int:
        """Create a new company"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO companies (name, api_key_hash) VALUES (?, ?)",
            (name, api_key_hash)
        )
        company_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return company_id

    def get_company_by_api_key(self, api_key_hash: str) -> Optional[Dict[str, Any]]:
        """Get company by API key hash"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM companies WHERE api_key_hash = ?",
            (api_key_hash,)
        )
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    # ==================== CUSTOMER OPERATIONS ====================

    def create_customer(self, company_id: Optional[int], name: str, email: str,
                       role: str, api_key_hash: str, api_key_salt: str,
                       api_key_lookup_hash: str, expires_at: Optional[str] = None) -> int:
        """Create a new customer (supports global customers with company_id=NULL)"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO customers (company_id, name, email, role, api_key_hash, api_key_salt, api_key_lookup_hash, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (company_id, name, email, role, api_key_hash, api_key_salt, api_key_lookup_hash, expires_at)
        )
        customer_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return customer_id

    def get_customer_by_lookup_hash(self, lookup_hash: str) -> Optional[Dict[str, Any]]:
        """Get customer by API key lookup hash (fast O(1) lookup)"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM customers WHERE api_key_lookup_hash = ?",
            (lookup_hash,)
        )
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_customer_by_api_key(self, api_key_hash: str) -> Optional[Dict[str, Any]]:
        """Get customer by API key hash"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM customers WHERE api_key_hash = ?",
            (api_key_hash,)
        )
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_customer_by_email(self, company_id: Optional[int], email: str) -> Optional[Dict[str, Any]]:
        """Get customer by email within a company (or global if company_id is None)"""
        conn = self.get_connection()
        cursor = conn.cursor()
        if company_id is None:
            cursor.execute(
                "SELECT * FROM customers WHERE company_id IS NULL AND email = ?",
                (email,)
            )
        else:
            cursor.execute(
                "SELECT * FROM customers WHERE company_id = ? AND email = ?",
                (company_id, email)
            )
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    # ==================== PRODUCT OPERATIONS ====================

    def create_product(self, company_id: int, name: str, category: str,
                      price: float, stock: int, description: str) -> int:
        """Create a new product with company isolation"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO products (company_id, name, category, price, stock, description)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (company_id, name, category, price, stock, description)
        )
        product_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return product_id

    def search_products(self, query: str, company_id: Optional[int] = None,
                       max_price: Optional[float] = None,
                       category: Optional[str] = None,
                       limit: int = 50) -> List[Dict[str, Any]]:
        """Search products with company isolation"""
        conn = self.get_connection()
        cursor = conn.cursor()

        sql = """
            SELECT p.*, c.name as company_name
            FROM products p
            JOIN companies c ON p.company_id = c.company_id
            WHERE (p.name LIKE ? OR p.description LIKE ? OR p.category LIKE ?)
        """
        params = [f"%{query}%", f"%{query}%", f"%{query}%"]

        if company_id:
            sql += " AND p.company_id = ?"
            params.append(company_id)

        if max_price:
            sql += " AND p.price <= ?"
            params.append(max_price)

        if category:
            sql += " AND p.category LIKE ?"
            params.append(f"%{category}%")

        sql += " ORDER BY p.created_at DESC LIMIT ?"
        params.append(limit)

        cursor.execute(sql, params)
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_product_by_id(self, product_id: int, company_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Get product by ID with optional company isolation"""
        conn = self.get_connection()
        cursor = conn.cursor()

        if company_id:
            cursor.execute(
                """SELECT p.*, c.name as company_name
                   FROM products p
                   JOIN companies c ON p.company_id = c.company_id
                   WHERE p.product_id = ? AND p.company_id = ?""",
                (product_id, company_id)
            )
        else:
            cursor.execute(
                """SELECT p.*, c.name as company_name
                   FROM products p
                   JOIN companies c ON p.company_id = c.company_id
                   WHERE p.product_id = ?""",
                (product_id,)
            )

        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def update_product_stock(self, product_id: int, company_id: int,
                            new_stock: int) -> bool:
        """Update product stock with company isolation"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE products
               SET stock = ?
               WHERE product_id = ? AND company_id = ?""",
            (new_stock, product_id, company_id)
        )
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        return affected > 0

    def decrement_product_stock_atomic(self, product_id: int, company_id: int,
                                      quantity: int) -> bool:
        """Atomic stock decrement to prevent race conditions"""
        conn = self.get_connection()
        cursor = conn.cursor()
        # Atomic update: only decrement if enough stock exists
        cursor.execute(
            """UPDATE products
               SET stock = stock - ?
               WHERE product_id = ? AND company_id = ? AND stock >= ?""",
            (quantity, product_id, company_id, quantity)
        )
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        return affected > 0

    def get_low_stock_products(self, company_id: int, threshold: int = 10) -> List[Dict[str, Any]]:
        """Get products with low stock for a company"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT * FROM products
               WHERE company_id = ? AND stock <= ?
               ORDER BY stock ASC""",
            (company_id, threshold)
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    # ==================== ORDER OPERATIONS ====================

    def create_order(self, company_id: int, customer_id: int, product_id: int,
                    quantity: int, total_price: float) -> int:
        """Create a new order with company isolation"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO orders (company_id, customer_id, product_id, quantity, total_price, status)
               VALUES (?, ?, ?, ?, ?, 'pending')""",
            (company_id, customer_id, product_id, quantity, total_price)
        )
        order_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return order_id

    def get_order_by_id(self, order_id: int, company_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Get order by ID with optional company isolation"""
        conn = self.get_connection()
        cursor = conn.cursor()

        if company_id:
            cursor.execute(
                """SELECT o.*, c.name as customer_name, c.email as customer_email,
                          p.name as product_name, p.price as unit_price,
                          comp.name as company_name
                   FROM orders o
                   JOIN customers c ON o.customer_id = c.customer_id
                   JOIN products p ON o.product_id = p.product_id
                   JOIN companies comp ON o.company_id = comp.company_id
                   WHERE o.order_id = ? AND o.company_id = ?""",
                (order_id, company_id)
            )
        else:
            cursor.execute(
                """SELECT o.*, c.name as customer_name, c.email as customer_email,
                          p.name as product_name, p.price as unit_price,
                          comp.name as company_name
                   FROM orders o
                   JOIN customers c ON o.customer_id = c.customer_id
                   JOIN products p ON o.product_id = p.product_id
                   JOIN companies comp ON o.company_id = comp.company_id
                   WHERE o.order_id = ?""",
                (order_id,)
            )

        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_customer_orders(self, company_id: Optional[int], customer_email: str,
                           limit: int = 50) -> List[Dict[str, Any]]:
        """Get all orders for a customer with company isolation"""
        conn = self.get_connection()
        cursor = conn.cursor()
        if company_id is not None:
            cursor.execute(
                """SELECT o.*, p.name as product_name, p.price as unit_price
                   FROM orders o
                   JOIN customers c ON o.customer_id = c.customer_id
                   JOIN products p ON o.product_id = p.product_id
                   WHERE o.company_id = ? AND c.email = ?
                   ORDER BY o.created_at DESC
                   LIMIT ?""",
                (company_id, customer_email, limit)
            )
        else:
            # Global customer case: Search across all companies
            cursor.execute(
                """SELECT o.*, p.name as product_name, p.price as unit_price
                   FROM orders o
                   JOIN customers c ON o.customer_id = c.customer_id
                   JOIN products p ON o.product_id = p.product_id
                   WHERE c.email = ?
                   ORDER BY o.created_at DESC
                   LIMIT ?""",
                (customer_email, limit)
            )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_all_orders(self, company_id: int, status: Optional[str] = None,
                      limit: int = 50) -> List[Dict[str, Any]]:
        """Get all orders for a company with optional status filter"""
        conn = self.get_connection()
        cursor = conn.cursor()

        if status:
            cursor.execute(
                """SELECT o.*, c.name as customer_name, c.email as customer_email,
                          p.name as product_name, p.price as unit_price
                   FROM orders o
                   JOIN customers c ON o.customer_id = c.customer_id
                   JOIN products p ON o.product_id = p.product_id
                   WHERE o.company_id = ? AND o.status = ?
                   ORDER BY o.created_at DESC
                   LIMIT ?""",
                (company_id, status, limit)
            )
        else:
            cursor.execute(
                """SELECT o.*, c.name as customer_name, c.email as customer_email,
                          p.name as product_name, p.price as unit_price
                   FROM orders o
                   JOIN customers c ON o.customer_id = c.customer_id
                   JOIN products p ON o.product_id = p.product_id
                   WHERE o.company_id = ?
                   ORDER BY o.created_at DESC
                   LIMIT ?""",
                (company_id, limit)
            )

        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def update_order_status(self, order_id: int, company_id: int,
                           new_status: str) -> bool:
        """Update order status with company isolation"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE orders
               SET status = ?
               WHERE order_id = ? AND company_id = ?""",
            (new_status, order_id, company_id)
        )
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        return affected > 0

    # ==================== ANALYTICS OPERATIONS ====================

    def get_sales_summary(self, company_id: int) -> Dict[str, Any]:
        """Get sales summary for a company"""
        conn = self.get_connection()
        cursor = conn.cursor()

        # Total revenue and order count
        cursor.execute(
            """SELECT
                   COUNT(*) as total_orders,
                   COALESCE(SUM(total_price), 0) as total_revenue,
                   COALESCE(AVG(total_price), 0) as average_order_value
               FROM orders
               WHERE company_id = ?""",
            (company_id,)
        )
        summary = dict(cursor.fetchone())

        # Top products
        cursor.execute(
            """SELECT p.name, COUNT(*) as order_count,
                      SUM(o.quantity) as total_quantity,
                      SUM(o.total_price) as revenue
               FROM orders o
               JOIN products p ON o.product_id = p.product_id
               WHERE o.company_id = ?
               GROUP BY p.product_id
               ORDER BY order_count DESC
               LIMIT 5""",
            (company_id,)
        )
        summary['top_products'] = [dict(row) for row in cursor.fetchall()]

        # Order status breakdown
        cursor.execute(
            """SELECT status, COUNT(*) as count
               FROM orders
               WHERE company_id = ?
               GROUP BY status""",
            (company_id,)
        )
        summary['status_breakdown'] = [dict(row) for row in cursor.fetchall()]

        conn.close()
        return summary

    # ==================== AUDIT LOG OPERATIONS ====================

    def create_audit_log(self, tool_name: str, company_id: Optional[int],
                        user_email: Optional[str], role: Optional[str],
                        input_params: str, result: str, success: bool,
                        execution_time_ms: Optional[float] = None,
                        result_count: Optional[int] = None,
                        session_id: Optional[str] = None) -> int:
        """Create an audit log entry with enhanced tracking"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO audit_logs (tool_name, company_id, user_email, role,
                                       input_params, result, success, execution_time_ms,
                                       result_count, session_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (tool_name, company_id, user_email, role, input_params, result, success,
             execution_time_ms, result_count, session_id)
        )
        log_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return log_id

    def get_audit_logs(self, company_id: Optional[int] = None,
                      limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit logs with optional company filter"""
        conn = self.get_connection()
        cursor = conn.cursor()

        if company_id:
            cursor.execute(
                """SELECT * FROM audit_logs
                   WHERE company_id = ?
                   ORDER BY timestamp DESC
                   LIMIT ?""",
                (company_id, limit)
            )
        else:
            cursor.execute(
                """SELECT * FROM audit_logs
                   ORDER BY timestamp DESC
                   LIMIT ?""",
                (limit,)
            )

        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    # ==================== RATE LIMITING OPERATIONS ====================

    def log_rate_limit_call(self, api_key_hash: str, tool_name: str) -> int:
        """Log a tool call for rate limiting"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO rate_limit_log (api_key_hash, tool_name)
               VALUES (?, ?)""",
            (api_key_hash, tool_name)
        )
        log_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return log_id

    def get_rate_limit_count(self, api_key_hash: str, window_seconds: int = 60) -> int:
        """Get count of calls in the last N seconds"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT COUNT(*) as count
               FROM rate_limit_log
               WHERE api_key_hash = ?
               AND datetime(timestamp) > datetime('now', '-' || ? || ' seconds')""",
            (api_key_hash, window_seconds)
        )
        row = cursor.fetchone()
        conn.close()
        return row['count'] if row else 0

    def cleanup_old_rate_limits(self, hours_old: int = 24) -> int:
        """Clean up rate limit logs older than N hours"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """DELETE FROM rate_limit_log
               WHERE datetime(timestamp) < datetime('now', '-' || ? || ' hours')""",
            (hours_old,)
        )
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        return deleted

    # ==================== SECURITY ALERTS OPERATIONS ====================

    def create_security_alert(self, alert_type: str, severity: str,
                             api_key_hash: Optional[str] = None,
                             user_email: Optional[str] = None,
                             company_id: Optional[int] = None,
                             attempted_action: Optional[str] = None,
                             reason: Optional[str] = None) -> int:
        """Create a security alert"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO security_alerts (alert_type, severity, api_key_hash,
                                           user_email, company_id, attempted_action, reason)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (alert_type, severity, api_key_hash, user_email, company_id, attempted_action, reason)
        )
        alert_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return alert_id

    def get_security_alerts(self, company_id: Optional[int] = None,
                           limit: int = 20) -> List[Dict[str, Any]]:
        """Get security alerts with optional company filter"""
        conn = self.get_connection()
        cursor = conn.cursor()

        if company_id:
            cursor.execute(
                """SELECT * FROM security_alerts
                   WHERE company_id = ?
                   ORDER BY timestamp DESC
                   LIMIT ?""",
                (company_id, limit)
            )
        else:
            cursor.execute(
                """SELECT * FROM security_alerts
                   ORDER BY timestamp DESC
                   LIMIT ?""",
                (limit,)
            )

        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def count_failed_auth_attempts(self, api_key_hash: str, minutes: int = 1) -> int:
        """Count failed authentication attempts in last N minutes"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT COUNT(*) as count
               FROM security_alerts
               WHERE api_key_hash = ?
               AND alert_type = 'authentication_failure'
               AND datetime(timestamp) > datetime('now', '-' || ? || ' minutes')""",
            (api_key_hash, minutes)
        )
        row = cursor.fetchone()
        conn.close()
        return row['count'] if row else 0

    # ==================== CUSTOMER UPDATE OPERATIONS ====================

    def update_customer_api_key(self, customer_id: int, new_api_key_hash: str,
                               new_api_key_salt: str, new_api_key_lookup_hash: str,
                               new_expires_at: Optional[str] = None) -> bool:
        """Update customer API key (for key rotation)"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE customers
               SET api_key_hash = ?, api_key_salt = ?, api_key_lookup_hash = ?, expires_at = ?
               WHERE customer_id = ?""",
            (new_api_key_hash, new_api_key_salt, new_api_key_lookup_hash, new_expires_at, customer_id)
        )
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        return affected > 0

    def get_customer_by_id(self, customer_id: int) -> Optional[Dict[str, Any]]:
        """Get customer by ID"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM customers WHERE customer_id = ?",
            (customer_id,)
        )
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None
