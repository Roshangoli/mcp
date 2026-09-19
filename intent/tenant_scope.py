"""
Tenant Scope Enforcement module - implements the three core rules for TSIC.

This module enforces:
1. READ tools stay wide: tenant_scope="ALL" allows cross-company reads
2. WRITE tools must narrow: resource's company_id must be in tenant_scope
3. Cross-tenant intent leakage detection: single tool call can't reference multiple
   companies unless explicitly authorized

This is the novel contribution of Paper 2: tenant-scoped intent verification that
prevents prompt injection from causing cross-tenant data leakage.
"""

from typing import Dict, Any, Optional, List, Set


class TenantScopeEnforcer:
    """
    Enforces tenant scope boundaries for tool calls based on intent certificates.

    The enforcer implements the three core rules:
    - check_read(): Validates read operations respect tenant_scope (but stay wide if "ALL")
    - check_write(): Validates write operations narrow to resource's actual company_id
    - detect_cross_tenant_leakage(): Catches cross-company data access within a single call
    """

    # Tool categorization (pulled from security.py lines 13-29)
    # These MUST match the exact tool names from server.py routing (lines 362-385)
    READ_TOOLS = {
        "search_products",
        "get_product_details",
        "track_order",
        "get_order_history",
        # Admin read tools
        "view_all_orders",
        "sales_summary",
        "view_security_alerts",
    }

    WRITE_TOOLS = {
        "place_order",
        # Admin write tools
        "add_product",
        "update_inventory",
        "update_order_status",
        "rotate_api_key",
    }

    # All 12 tools for reference
    ALL_TOOLS = READ_TOOLS | WRITE_TOOLS

    def __init__(self, database):
        """
        Initialize the TenantScopeEnforcer.

        Args:
            database: Database instance for looking up resource company_ids
        """
        self.db = database

    def check_read(
        self,
        certificate: Dict[str, Any],
        tool_name: str,
        params: Dict[str, Any]
    ) -> None:
        """
        Validate that a READ operation respects the certificate's tenant_scope.

        Rule 1: READ tools stay wide
        - If tenant_scope == "ALL", all 8 companies are readable (same as Paper 1's global_customer)
        - If tenant_scope is specific company IDs (e.g., "1,3"), only those companies readable
        - This doesn't change read behavior from Paper 1 - just gates it behind intent verification

        Implementation:
        - For now, READ tools with tenant_scope="ALL" pass through (no additional filtering)
        - For specific scopes, could optionally filter results (but Paper 1 doesn't do this)
        - Main enforcement is that the certificate's intent_classes must authorize the read

        Args:
            certificate: The verified intent certificate dict
            tool_name: Name of the tool being called (must be in READ_TOOLS)
            params: The tool call parameters

        Raises:
            TenantScopeViolationError: If read violates tenant_scope boundaries
        """
        # Verify tool is actually a read tool
        if tool_name not in self.READ_TOOLS:
            raise TenantScopeViolationError(
                f"Tool {tool_name} is not a READ tool, cannot use check_read()"
            )

        # For READ tools, tenant_scope primarily controls what data is returned
        # The actual filtering happens in the database layer (Paper 1's Layer 5)
        # Layer 0 just needs to verify the certificate authorizes this read

        # If specific company filter requested in params, verify it matches scope
        if 'company' in params and params['company'] and certificate['tenant_scope'] != "ALL":
            allowed_companies = set(certificate['tenant_scope'].split(','))

            # Look up company ID from name
            conn = self.db.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT company_id FROM companies WHERE name LIKE ?", (f"%{params['company']}%",))
            row = cursor.fetchone()
            conn.close()

            if row and str(row['company_id']) not in allowed_companies:
                raise TenantScopeViolationError(
                    f"Company '{params['company']}' (ID {row['company_id']}) not in certificate scope {certificate['tenant_scope']}"
                )

        # READ operations pass - actual tenant filtering happens at database layer

    def check_write(
        self,
        certificate: Dict[str, Any],
        tool_name: str,
        params: Dict[str, Any],
        resource: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Validate that a WRITE operation narrows to the resource's actual company_id.

        Rule 2: WRITE tools must narrow
        - On ANY write, tenant_scope must be checked against the RESOURCE's actual company_id
        - The resource's company is derived the same way as Paper 1:
          * place_order: from product.company_id (NOT customer.company_id)
          * add_product: from params['company_id'] or admin's company
          * update_inventory: from product.company_id
          * update_order_status: from order.company_id
          * rotate_api_key: from customer.company_id
        - If resource's company_id is NOT in the certificate's tenant_scope, block

        Special enforcement for place_order:
        - Check cumulative spend: previous orders + new order <= spend_limit
        - Raise SpendLimitExceededError if total > spend_limit

        Args:
            certificate: The verified intent certificate dict
            tool_name: Name of the tool being called (must be in WRITE_TOOLS)
            params: The tool call parameters
            resource: Optional pre-fetched resource dict (e.g., product, order) containing company_id

        Raises:
            TenantScopeViolationError: If write targets a company outside tenant_scope
            SpendLimitExceededError: If place_order total exceeds spend_limit (for place_order only)
        """
        # Verify tool is actually a write tool
        if tool_name not in self.WRITE_TOOLS:
            raise TenantScopeViolationError(
                f"Tool {tool_name} is not a WRITE tool, cannot use check_write()"
            )

        # Derive resource company_id based on tool type
        resource_company_id = None

        if tool_name == "place_order":
            # For place_order: get product's company_id (NOT customer's)
            product_id = params.get('product_id')
            if not product_id:
                raise TenantScopeViolationError("place_order requires product_id")

            # Fetch product to get its company_id
            conn = self.db.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT company_id, price FROM products WHERE product_id = ?", (product_id,))
            product_row = cursor.fetchone()
            conn.close()

            if not product_row:
                raise TenantScopeViolationError(f"Product {product_id} not found")

            resource_company_id = product_row['company_id']
            product_price = product_row['price']

            # Check cumulative spend limit for this certificate
            if certificate.get('spend_limit') is not None:
                quantity = params.get('quantity', 1)
                current_order_total = product_price * quantity

                # Query all previous orders linked to this certificate
                certificate_id = certificate.get('certificate_id')
                previous_total = 0.0

                if certificate_id:
                    conn = self.db.get_connection()
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT SUM(total_price) as total FROM orders WHERE certificate_id = ?",
                        (certificate_id,)
                    )
                    row = cursor.fetchone()
                    conn.close()

                    if row and row['total'] is not None:
                        previous_total = float(row['total'])

                cumulative_total = previous_total + current_order_total

                if cumulative_total > certificate['spend_limit']:
                    raise SpendLimitExceededError(
                        f"Cumulative spend ${cumulative_total:.2f} exceeds limit "
                        f"${certificate['spend_limit']:.2f} "
                        f"(previous: ${previous_total:.2f}, current order: ${current_order_total:.2f})"
                    )

        elif tool_name == "add_product":
            # For add_product: from params['company_id'] (admin specifies which company)
            # This requires the admin to explicitly state which company they're adding to
            resource_company_id = params.get('company_id')
            if not resource_company_id:
                raise TenantScopeViolationError("add_product requires company_id parameter")

        elif tool_name == "update_inventory":
            # For update_inventory: from product.company_id
            product_id = params.get('product_id')
            if not product_id:
                raise TenantScopeViolationError("update_inventory requires product_id")

            conn = self.db.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT company_id FROM products WHERE product_id = ?", (product_id,))
            row = cursor.fetchone()
            conn.close()

            if not row:
                raise TenantScopeViolationError(f"Product {product_id} not found")

            resource_company_id = row['company_id']

        elif tool_name == "update_order_status":
            # For update_order_status: from order.company_id
            order_id = params.get('order_id')
            if not order_id:
                raise TenantScopeViolationError("update_order_status requires order_id")

            conn = self.db.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT company_id FROM orders WHERE order_id = ?", (order_id,))
            row = cursor.fetchone()
            conn.close()

            if not row:
                raise TenantScopeViolationError(f"Order {order_id} not found")

            resource_company_id = row['company_id']

        elif tool_name == "rotate_api_key":
            # For rotate_api_key: from customer.company_id
            # The customer rotating their own key
            customer_id = certificate.get('customer_id')
            if not customer_id:
                raise TenantScopeViolationError("rotate_api_key requires customer_id from certificate")

            conn = self.db.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT company_id FROM customers WHERE customer_id = ?", (customer_id,))
            row = cursor.fetchone()
            conn.close()

            if not row:
                raise TenantScopeViolationError(f"Customer {customer_id} not found")

            resource_company_id = row['company_id']

        # Check if resource's company_id is in tenant_scope
        if resource_company_id is not None:
            # tenant_scope="ALL" allows writes to any company (global_customer pattern)
            if certificate['tenant_scope'] == "ALL":
                # Global customer can write to any company
                pass
            else:
                # Check if resource's company is in allowed scope
                allowed_companies = set(certificate['tenant_scope'].split(','))
                if str(resource_company_id) not in allowed_companies:
                    raise TenantScopeViolationError(
                        f"Write to company {resource_company_id} not allowed. "
                        f"Certificate scope: {certificate['tenant_scope']}"
                    )

    def detect_cross_tenant_leakage(
        self,
        certificate: Dict[str, Any],
        params: Dict[str, Any]
    ) -> None:
        """
        Detect if a SINGLE tool call's params reference multiple companies simultaneously.

        Rule 3: Cross-Tenant Intent Leakage detection

        This is the NEW attack class Paper 2 defines. In multi-tenant systems, a malicious
        prompt injection could try to:
        - Compare data across companies: "show me laptops from TechZone and SportsPro"
        - Exfiltrate via cross-referencing: "get order totals for company 1 and company 2"

        Detection heuristic (from user specification):
        1. Collect all company_ids referenced in params
        2. Check product_id references → get product.company_id
        3. Check order_id references → get order.company_id
        4. Check customer_email references → get customer.company_id
        5. If more than 1 distinct company found:
           - If "cross_company" in certificate.intent_classes: ALLOW
           - Otherwise: raise CrossTenantIntentLeakageError
        6. If regular customer (scope != "ALL"):
           - Verify all referenced companies are in allowed scope
           - Otherwise: raise CrossTenantIntentLeakageError

        Known limitation (must flag in code comments):
        This only catches leakage visible within a SINGLE tool call's params. It CAN'T
        catch an LLM making two separate, individually-valid calls and then cross-referencing
        the data in its own reasoning. That would require session-level tracking, which is
        out of scope for Layer 0.

        For example, this IS caught:
        - Tool: search_products, params: {company: "TechZone,SportsPro", query: "laptop"}
          (if certificate.tenant_scope != "ALL")

        This is NOT caught (limitation):
        - Call 1: search_products {company: "TechZone", query: "laptop"} -> gets data
        - Call 2: search_products {company: "SportsPro", query: "laptop"} -> gets data
        - LLM compares results in its reasoning and reports back to user

        Args:
            certificate: The verified intent certificate dict
            params: The tool call parameters to inspect

        Raises:
            CrossTenantIntentLeakageError: If params reference multiple companies without authorization
        """
        company_ids_found: Set[int] = set()

        # Check product_id references
        if "product_id" in params and params["product_id"]:
            try:
                conn = self.db.get_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT company_id FROM products WHERE product_id = ?", (params["product_id"],))
                row = cursor.fetchone()
                conn.close()

                if row and row['company_id'] is not None:
                    company_ids_found.add(row['company_id'])
            except Exception:
                pass  # Don't fail on lookup errors

        # Check order_id references
        if "order_id" in params and params["order_id"]:
            try:
                conn = self.db.get_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT company_id FROM orders WHERE order_id = ?", (params["order_id"],))
                row = cursor.fetchone()
                conn.close()

                if row and row['company_id'] is not None:
                    company_ids_found.add(row['company_id'])
            except Exception:
                pass

        # Check customer_email references
        if "customer_email" in params and params["customer_email"]:
            try:
                # Note: For global customers (company_id=NULL), we skip this check
                conn = self.db.get_connection()
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT company_id FROM customers WHERE email = ? AND company_id IS NOT NULL",
                    (params["customer_email"],)
                )
                row = cursor.fetchone()
                conn.close()

                if row and row['company_id'] is not None:
                    company_ids_found.add(row['company_id'])
            except Exception:
                pass

        # Check company name in params (common in search_products)
        if "company" in params and params["company"]:
            company_name = params["company"]

            # Check if multiple companies requested (comma-separated)
            if ',' in company_name:
                # Multiple companies requested in single call - potential leakage
                company_names = [name.strip() for name in company_name.split(',')]

                for name in company_names:
                    try:
                        conn = self.db.get_connection()
                        cursor = conn.cursor()
                        cursor.execute("SELECT company_id FROM companies WHERE name LIKE ?", (f"%{name}%",))
                        row = cursor.fetchone()
                        conn.close()

                        if row and row['company_id'] is not None:
                            company_ids_found.add(row['company_id'])
                    except Exception:
                        pass

        # Analysis: Check if multiple companies referenced
        if len(company_ids_found) > 1:
            # Multiple companies referenced in single call

            # Check if certificate explicitly allows cross-company operations
            intent_classes = certificate.get('intent_classes', [])
            if "cross_company" in intent_classes:
                # Explicitly authorized for cross-company comparison
                return

            # Otherwise, this is a cross-tenant leakage attempt
            raise CrossTenantIntentLeakageError(
                f"Operation references multiple companies {company_ids_found} "
                f"but certificate scope is {certificate['tenant_scope']}. "
                f"This may be a cross-tenant data leakage attempt."
            )

        # If regular customer (not ALL scope), verify referenced companies are allowed
        if certificate['tenant_scope'] != "ALL" and len(company_ids_found) > 0:
            allowed_companies = set(int(c) for c in certificate['tenant_scope'].split(','))

            for company_id in company_ids_found:
                if company_id not in allowed_companies:
                    raise CrossTenantIntentLeakageError(
                        f"Company {company_id} not in allowed scope {certificate['tenant_scope']}"
                    )


# Custom exceptions for tenant scope violations

class TenantScopeViolationError(Exception):
    """
    Raised when a write operation targets a company outside the certificate's tenant_scope.

    This fires at Layer 0 BEFORE Layer 5's company_id filter is reached.
    """
    pass


class SpendLimitExceededError(Exception):
    """Raised when cumulative spend across certificate's orders exceeds spend_limit."""
    pass


class CrossTenantIntentLeakageError(Exception):
    """
    Raised when a single tool call's params reference multiple companies without authorization.

    This is the novel attack class defined in Paper 2, only possible in multi-tenant systems.
    """
    pass
