import os
from typing import Optional
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from database import Database
from security import security_manager
from logger import create_audit_logger

import os as _os
DB_PATH = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "ecommerce.db")
db = Database(DB_PATH)
audit_logger = create_audit_logger(db)
app = Server("multi-company-ecommerce-gateway")

def authenticate_and_authorize(api_key: str, tool_name: str) -> tuple:
    auth_success, user_data, auth_msg = security_manager.authenticate(db, api_key)
    if not auth_success:
        audit_logger.log_authentication_failure(tool_name, auth_msg)
        return False, None, auth_msg

    allowed, rate_msg = security_manager.check_rate_limit(
        db, user_data['api_key_hash'], user_data['role'], tool_name
    )
    if not allowed:
        audit_logger.log_rate_limit_exceeded(tool_name, user_data['email'])
        # Create security alert for rate limit
        db.create_security_alert(
            alert_type="rate_limit_exceeded",
            severity=security_manager.SEVERITY_MEDIUM,
            api_key_hash=user_data['api_key_hash'],
            user_email=user_data['email'],
            company_id=user_data.get('company_id'),
            attempted_action=tool_name,
            reason=rate_msg
        )
        return False, None, rate_msg

    # Authorize
    authz_success, authz_msg = security_manager.authorize(tool_name, user_data['role'])
    if not authz_success:
        audit_logger.log_authorization_failure(
            tool_name,
            user_data['email'],
            user_data['role'],
            authz_msg
        )
        # Create security alert for unauthorized access attempt
        db.create_security_alert(
            alert_type="unauthorized_access_attempt",
            severity=security_manager.SEVERITY_HIGH,
            api_key_hash=user_data['api_key_hash'],
            user_email=user_data['email'],
            company_id=user_data.get('company_id'),
            attempted_action=tool_name,
            reason=f"Customer tried to access admin tool: {tool_name}"
        )
        return False, None, authz_msg

    return True, user_data, ""


# ==================== CUSTOMER TOOLS ====================

@app.list_tools()
async def list_tools() -> list[Tool]:
    """List all available tools"""
    return [
        Tool(
            name="search_products",
            description="""Search for products across all companies or filter by specific company.
            Use this when users want to find products by name, description, or category.
            Supports filtering by company name, maximum price, and category.
            Returns matching products with details like name, price, stock, and company.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key": {
                        "type": "string",
                        "description": "User's API key for authentication"
                    },
                    "query": {
                        "type": "string",
                        "description": "Search query (searches in product name, description, category)"
                    },
                    "company": {
                        "type": "string",
                        "description": "Optional: Filter by company name (e.g., 'TechZone', 'SportsPro', 'HomeNest')"
                    },
                    "max_price": {
                        "type": "number",
                        "description": "Optional: Maximum price filter"
                    },
                    "category": {
                        "type": "string",
                        "description": "Optional: Filter by category"
                    }
                },
                "required": ["api_key", "query"]
            }
        ),
        Tool(
            name="get_product_details",
            description="""Get detailed information about a specific product by its ID.
            Use this when users want to see full details of a particular product.
            Returns product name, description, price, stock availability, category, and company.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key": {
                        "type": "string",
                        "description": "User's API key for authentication"
                    },
                    "product_id": {
                        "type": "integer",
                        "description": "Product ID to retrieve details for"
                    }
                },
                "required": ["api_key", "product_id"]
            }
        ),
        Tool(
            name="place_order",
            description="""Place an order for a product. Automatically reduces stock and creates order record.
            Use this when users want to purchase/order a product.
            Uses the authenticated user from the API key to place the order.
            Validates stock availability before placing order.
            Returns order confirmation with order ID, total price, and status.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key": {
                        "type": "string",
                        "description": "User's API key for authentication"
                    },
                    "product_id": {
                        "type": "integer",
                        "description": "Product ID to order"
                    },
                    "quantity": {
                        "type": "integer",
                        "description": "Quantity to order (must be positive integer)"
                    }
                },
                "required": ["api_key", "product_id", "quantity"]
            }
        ),
        Tool(
            name="track_order",
            description="""Track the status of an order by order ID.
            Use this when users want to check their order status or get order details.
            Returns order details including status, product info, quantity, total price, and timestamps.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key": {
                        "type": "string",
                        "description": "User's API key for authentication"
                    },
                    "order_id": {
                        "type": "integer",
                        "description": "Order ID to track"
                    }
                },
                "required": ["api_key", "order_id"]
            }
        ),
        Tool(
            name="get_order_history",
            description="""Get complete order history for a customer.
            Use this when users want to see all their past orders.
            Returns list of orders with product names, quantities, prices, and statuses.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key": {
                        "type": "string",
                        "description": "User's API key for authentication"
                    },
                    "customer_email": {
                        "type": "string",
                        "description": "Email of the customer to get order history for"
                    }
                },
                "required": ["api_key", "customer_email"]
            }
        ),
        Tool(
            name="add_product",
            description="""Add a new product to the company's inventory (ADMIN ONLY).
            Use this when admin wants to add a new product to their catalog.
            Requires admin role. Creates product in the admin's company only.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key": {
                        "type": "string",
                        "description": "Admin's API key for authentication"
                    },
                    "name": {
                        "type": "string",
                        "description": "Product name"
                    },
                    "category": {
                        "type": "string",
                        "description": "Product category"
                    },
                    "price": {
                        "type": "number",
                        "description": "Product price (must be positive)"
                    },
                    "stock": {
                        "type": "integer",
                        "description": "Initial stock quantity (must be non-negative)"
                    },
                    "description": {
                        "type": "string",
                        "description": "Product description"
                    }
                },
                "required": ["api_key", "name", "category", "price", "stock", "description"]
            }
        ),
        Tool(
            name="update_inventory",
            description="""Update product stock level (ADMIN ONLY).
            Use this when admin wants to adjust inventory/stock for a product.
            Requires admin role. Can only update products from admin's own company.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key": {
                        "type": "string",
                        "description": "Admin's API key for authentication"
                    },
                    "product_id": {
                        "type": "integer",
                        "description": "Product ID to update"
                    },
                    "new_stock": {
                        "type": "integer",
                        "description": "New stock level (must be non-negative)"
                    }
                },
                "required": ["api_key", "product_id", "new_stock"]
            }
        ),
        Tool(
            name="view_all_orders",
            description="""View all orders for the admin's company (ADMIN ONLY).
            Use this when admin wants to see all orders, optionally filtered by status.
            Requires admin role. Only shows orders from admin's own company.
            Supports filtering by status: pending, processing, shipped, delivered, cancelled.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key": {
                        "type": "string",
                        "description": "Admin's API key for authentication"
                    },
                    "status": {
                        "type": "string",
                        "description": "Optional: Filter by order status (pending/processing/shipped/delivered/cancelled)"
                    }
                },
                "required": ["api_key"]
            }
        ),
        Tool(
            name="update_order_status",
            description="""Update the status of an order (ADMIN ONLY).
            Use this when admin wants to change order status (e.g., mark as shipped).
            Requires admin role. Can only update orders from admin's own company.
            Valid statuses: pending, processing, shipped, delivered, cancelled.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key": {
                        "type": "string",
                        "description": "Admin's API key for authentication"
                    },
                    "order_id": {
                        "type": "integer",
                        "description": "Order ID to update"
                    },
                    "new_status": {
                        "type": "string",
                        "description": "New status (pending/processing/shipped/delivered/cancelled)"
                    }
                },
                "required": ["api_key", "order_id", "new_status"]
            }
        ),
        Tool(
            name="sales_summary",
            description="""Get comprehensive sales analytics for the admin's company (ADMIN ONLY).
            Use this when admin wants to see business metrics and performance.
            Requires admin role. Shows total revenue, order count, top products, and low stock alerts.
            Only includes data from admin's own company.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key": {
                        "type": "string",
                        "description": "Admin's API key for authentication"
                    }
                },
                "required": ["api_key"]
            }
        ),
        Tool(
            name="rotate_api_key",
            description="""Rotate (regenerate) API key for a customer (ADMIN ONLY).
            Use this when a key needs to be refreshed or has expired.
            Requires admin role. Generates new key with new expiry date.
            Returns the new plain-text API key (only time it's shown).""",
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key": {
                        "type": "string",
                        "description": "Admin's API key for authentication"
                    },
                    "customer_email": {
                        "type": "string",
                        "description": "Email of customer whose key should be rotated"
                    }
                },
                "required": ["api_key", "customer_email"]
            }
        ),
        Tool(
            name="view_security_alerts",
            description="""View security alerts for the admin's company (ADMIN ONLY).
            Use this when admin wants to see suspicious activity or security events.
            Requires admin role. Shows failed logins, rate limit violations, unauthorized access attempts.
            Only shows alerts for admin's own company.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "api_key": {
                        "type": "string",
                        "description": "Admin's API key for authentication"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Number of alerts to retrieve (default: 20, max: 100)"
                    }
                },
                "required": ["api_key"]
            }
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Handle tool calls with authentication, authorization, and audit logging"""

    try:
        if name == "search_products":
            return await search_products(arguments)
        elif name == "get_product_details":
            return await get_product_details(arguments)
        elif name == "place_order":
            return await place_order(arguments)
        elif name == "track_order":
            return await track_order(arguments)
        elif name == "get_order_history":
            return await get_order_history(arguments)
        elif name == "add_product":
            return await add_product(arguments)
        elif name == "update_inventory":
            return await update_inventory(arguments)
        elif name == "view_all_orders":
            return await view_all_orders(arguments)
        elif name == "update_order_status":
            return await update_order_status(arguments)
        elif name == "sales_summary":
            return await sales_summary(arguments)
        elif name == "rotate_api_key":
            return await rotate_api_key(arguments)
        elif name == "view_security_alerts":
            return await view_security_alerts(arguments)
        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except Exception as e:
        error_msg = f"Internal error: {str(e)}"
        return [TextContent(type="text", text=error_msg)]


# ==================== TOOL IMPLEMENTATIONS ====================

async def search_products(args: dict) -> list[TextContent]:
    """Search for products across companies"""
    api_key = args.get("api_key", "")
    query = args.get("query", "")
    company_name = args.get("company")
    max_price = args.get("max_price")
    category = args.get("category")

    # Authenticate and authorize
    success, user_data, error_msg = authenticate_and_authorize(api_key, "search_products")
    if not success:
        return [TextContent(type="text", text=error_msg)]

    # Validate search parameters
    valid, msg = security_manager.validate_search_params(query, max_price, category)
    if not valid:
        audit_logger.log_validation_error(
            "search_products", user_data['company_id'],
            user_data['email'], user_data['role'], args, msg
        )
        return [TextContent(type="text", text=msg)]

    # Sanitize inputs
    query = security_manager.sanitize_string(query)
    category = security_manager.sanitize_string(category) if category else None

    # Determine company_id filter
    company_id = None
    if company_name:
        company_name = security_manager.sanitize_string(company_name)
        # Search for company by name to get its ID for better DB filtering
        # (Though we still filter in-memory for cases where name is slightly different,
        # providing it to DB improves performance and isolation)
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT company_id FROM companies WHERE name LIKE ?", (f"%{company_name}%",))
        row = cursor.fetchone()
        if row:
            company_id = row['company_id']
        conn.close()

    try:
        # Search products
        products = db.search_products(
            query=query,
            company_id=company_id,
            max_price=max_price,
            category=category
        )

        # Filter by company name if specified
        if company_name:
            products = [p for p in products if p['company_name'].lower() == company_name.lower()]

        if not products:
            result = f"No products found matching '{query}'"
            audit_logger.log_tool_call(
                "search_products", user_data['company_id'],
                user_data['email'], user_data['role'],
                args, True, result
            )
            return [TextContent(type="text", text=result)]

        # Format results
        result_lines = [f"Found {len(products)} product(s):\n"]
        for p in products:
            result_lines.append(f"ID: {p['product_id']} | {p['name']}")
            result_lines.append(f"  Company: {p['company_name']}")
            result_lines.append(f"  Category: {p['category']}")
            result_lines.append(f"  Price: ${p['price']:.2f}")
            result_lines.append(f"  Stock: {p['stock']} available")
            result_lines.append(f"  Description: {p['description'][:100]}...")
            result_lines.append("")

        result = "\n".join(result_lines)

        # Audit log
        audit_logger.log_tool_call(
            "search_products", user_data['company_id'],
            user_data['email'], user_data['role'],
            args, True, f"Found {len(products)} products"
        )

        return [TextContent(type="text", text=result)]

    except Exception as e:
        error_msg = f"Error searching products: {str(e)}"
        audit_logger.log_tool_call(
            "search_products", user_data['company_id'],
            user_data['email'], user_data['role'],
            args, False, None, error_msg
        )
        return [TextContent(type="text", text=error_msg)]


async def get_product_details(args: dict) -> list[TextContent]:
    """Get detailed information about a product"""
    api_key = args.get("api_key", "")
    product_id = args.get("product_id")

    # Authenticate and authorize
    success, user_data, error_msg = authenticate_and_authorize(api_key, "get_product_details")
    if not success:
        return [TextContent(type="text", text=error_msg)]

    # Validate product_id
    try:
        product_id = int(product_id)
    except (ValueError, TypeError):
        error_msg = "Invalid product_id"
        audit_logger.log_validation_error(
            "get_product_details", user_data['company_id'],
            user_data['email'], user_data['role'], args, error_msg
        )
        return [TextContent(type="text", text=error_msg)]

    try:
        # Get product (no company filter - users can view products from any company)
        product = db.get_product_by_id(product_id)

        if not product:
            result = f"Product ID {product_id} not found"
            audit_logger.log_tool_call(
                "get_product_details", user_data['company_id'],
                user_data['email'], user_data['role'],
                args, False, None, result
            )
            return [TextContent(type="text", text=result)]

        # Format result
        result = f"""
Product Details:
================
ID: {product['product_id']}
Name: {product['name']}
Company: {product['company_name']}
Category: {product['category']}
Price: ${product['price']:.2f}
Stock: {product['stock']} available
Description: {product['description']}
"""

        # Audit log
        audit_logger.log_tool_call(
            "get_product_details", user_data['company_id'],
            user_data['email'], user_data['role'],
            args, True, f"Retrieved product {product_id}"
        )

        return [TextContent(type="text", text=result)]

    except Exception as e:
        error_msg = f"Error getting product details: {str(e)}"
        audit_logger.log_tool_call(
            "get_product_details", user_data['company_id'],
            user_data['email'], user_data['role'],
            args, False, None, error_msg
        )
        return [TextContent(type="text", text=error_msg)]


async def place_order(args: dict) -> list[TextContent]:
    """Place an order for a product"""
    api_key = args.get("api_key", "")
    product_id = args.get("product_id")
    quantity = args.get("quantity")

    # Authenticate and authorize
    success, user_data, error_msg = authenticate_and_authorize(api_key, "place_order")
    if not success:
        return [TextContent(type="text", text=error_msg)]

    # Use authenticated user's customer_id directly
    customer_id = user_data.get('id')
    if not customer_id:
        return [TextContent(type="text", text="Error: Invalid user authentication")]

    # Validate quantity
    valid, quantity, msg = security_manager.validate_positive_integer(quantity, "quantity")
    if not valid:
        audit_logger.log_validation_error(
            "place_order", user_data['company_id'],
            user_data['email'], user_data['role'], args, msg
        )
        return [TextContent(type="text", text=msg)]

    # Validate product_id
    try:
        product_id = int(product_id)
    except (ValueError, TypeError):
        error_msg = "Invalid product_id"
        audit_logger.log_validation_error(
            "place_order", user_data['company_id'],
            user_data['email'], user_data['role'], args, error_msg
        )
        return [TextContent(type="text", text=error_msg)]

    try:
        # Get product details
        product = db.get_product_by_id(product_id)
        if not product:
            result = f"Product ID {product_id} not found"
            audit_logger.log_tool_call(
                "place_order", user_data['company_id'],
                user_data['email'], user_data['role'],
                args, False, None, result
            )
            return [TextContent(type="text", text=result)]

        # Check stock availability
        if product['stock'] < quantity:
            result = f"Insufficient stock. Available: {product['stock']}, Requested: {quantity}"
            audit_logger.log_tool_call(
                "place_order", user_data['company_id'],
                user_data['email'], user_data['role'],
                args, False, None, result
            )
            return [TextContent(type="text", text=result)]

        # Calculate total price
        total_price = product['price'] * quantity

        # Atomic stock decrement
        success_stock = db.decrement_product_stock_atomic(product_id, product['company_id'], quantity)
        if not success_stock:
            result = "Error: Stock level changed. Please try again."
            audit_logger.log_tool_call(
                "place_order", user_data['company_id'],
                user_data['email'], user_data['role'],
                args, False, None, result
            )
            return [TextContent(type="text", text=result)]

        # Create order using authenticated user's customer_id
        order_id = db.create_order(
            company_id=product['company_id'],
            customer_id=customer_id,
            product_id=product_id,
            quantity=quantity,
            total_price=total_price
        )

        # Get updated product info for stock display
        updated_product = db.get_product_by_id(product_id)

        # Format result
        result = f"""
Order Placed Successfully!
==========================
Order ID: {order_id}
Product: {product['name']}
Company: {product['company_name']}
Quantity: {quantity}
Unit Price: ${product['price']:.2f}
Total Price: ${total_price:.2f}
Status: pending

Your order has been placed and is being processed.
Remaining stock: {updated_product['stock']}
"""

        # Audit log
        audit_logger.log_tool_call(
            "place_order", product['company_id'],
            user_data['email'], user_data['role'],
            args, True, f"Created order {order_id}"
        )

        return [TextContent(type="text", text=result)]

    except Exception as e:
        error_msg = f"Error placing order: {str(e)}"
        audit_logger.log_tool_call(
            "place_order", user_data.get('company_id'),
            user_data['email'], user_data['role'],
            args, False, None, error_msg
        )
        return [TextContent(type="text", text=error_msg)]


async def track_order(args: dict) -> list[TextContent]:
    """Track an order by ID"""
    api_key = args.get("api_key", "")
    order_id = args.get("order_id")

    # Authenticate and authorize
    success, user_data, error_msg = authenticate_and_authorize(api_key, "track_order")
    if not success:
        return [TextContent(type="text", text=error_msg)]

    # Validate order_id
    try:
        order_id = int(order_id)
    except (ValueError, TypeError):
        error_msg = "Invalid order_id"
        audit_logger.log_validation_error(
            "track_order", user_data['company_id'],
            user_data['email'], user_data['role'], args, error_msg
        )
        return [TextContent(type="text", text=error_msg)]

    try:
        # Get order
        order = db.get_order_by_id(order_id)

        if not order:
            result = f"Order ID {order_id} not found"
            audit_logger.log_tool_call(
                "track_order", user_data['company_id'],
                user_data['email'], user_data['role'],
                args, False, None, result
            )
            return [TextContent(type="text", text=result)]

        # SECURITY FIX: Ensure customers can only track their own orders
        # Admins can track any order in their company
        if user_data['role'] != security_manager.ROLE_ADMIN:
            if order['customer_id'] != user_data['id']:
                result = "Access denied: You can only track your own orders."
                audit_logger.log_authorization_failure(
                    "track_order", user_data['email'], user_data['role'], result
                )
                db.create_security_alert(
                    alert_type="unauthorized_order_access",
                    severity=security_manager.SEVERITY_HIGH,
                    api_key_hash=user_data['api_key_hash'],
                    user_email=user_data['email'],
                    company_id=user_data.get('company_id'),
                    attempted_action="track_order",
                    reason=f"User tried to track order {order_id} belonging to another customer"
                )
                return [TextContent(type="text", text=result)]
        else:
            # Admin role: ensure order belongs to their company
            if order['company_id'] != user_data['company_id']:
                result = "Access denied: You can only track orders from your own company."
                return [TextContent(type="text", text=result)]

        # Format result
        result = f"""
Order Tracking Information:
===========================
Order ID: {order['order_id']}
Status: {order['status'].upper()}
Company: {order['company_name']}

Customer: {order['customer_name']} ({order['customer_email']})
Product: {order['product_name']}
Quantity: {order['quantity']}
Total Price: ${order['total_price']:.2f}
Order Date: {order['created_at']}
"""

        # Audit log
        audit_logger.log_tool_call(
            "track_order", user_data['company_id'],
            user_data['email'], user_data['role'],
            args, True, f"Tracked order {order_id}"
        )

        return [TextContent(type="text", text=result)]

    except Exception as e:
        error_msg = f"Error tracking order: {str(e)}"
        audit_logger.log_tool_call(
            "track_order", user_data['company_id'],
            user_data['email'], user_data['role'],
            args, False, None, error_msg
        )
        return [TextContent(type="text", text=error_msg)]


async def get_order_history(args: dict) -> list[TextContent]:
    """Get order history for a customer"""
    api_key = args.get("api_key", "")
    customer_email = args.get("customer_email", "")

    # Authenticate and authorize
    success, user_data, error_msg = authenticate_and_authorize(api_key, "get_order_history")
    if not success:
        return [TextContent(type="text", text=error_msg)]

    # Validate email
    valid, customer_email, msg = security_manager.validate_email(customer_email)
    if not valid:
        audit_logger.log_validation_error(
            "get_order_history", user_data['company_id'],
            user_data['email'], user_data['role'], args, msg
        )
        return [TextContent(type="text", text=msg)]

    # SECURITY FIX: Ensure customers can only view their own history
    if user_data['role'] != security_manager.ROLE_ADMIN:
        if customer_email.lower() != user_data['email'].lower():
            result = "Access denied: You can only view your own order history."
            audit_logger.log_authorization_failure(
                "get_order_history", user_data['email'], user_data['role'], result
            )
            return [TextContent(type="text", text=result)]

    try:
        # Get customer orders for the user's company
        # (Global customers will be handled by a change in db.get_customer_orders later or by checking all companies)
        orders = db.get_customer_orders(user_data['company_id'], customer_email)

        if not orders:
            result = f"No orders found for {customer_email}"
            audit_logger.log_tool_call(
                "get_order_history", user_data['company_id'],
                user_data['email'], user_data['role'],
                args, True, result
            )
            return [TextContent(type="text", text=result)]

        # Format results
        result_lines = [f"Order History for {customer_email}"]
        result_lines.append("=" * 50)
        result_lines.append(f"Total Orders: {len(orders)}\n")

        for order in orders:
            result_lines.append(f"Order ID: {order['order_id']}")
            result_lines.append(f"  Product: {order['product_name']}")
            result_lines.append(f"  Quantity: {order['quantity']}")
            result_lines.append(f"  Total: ${order['total_price']:.2f}")
            result_lines.append(f"  Status: {order['status'].upper()}")
            result_lines.append(f"  Date: {order['created_at']}")
            result_lines.append("")

        result = "\n".join(result_lines)

        # Audit log
        audit_logger.log_tool_call(
            "get_order_history", user_data['company_id'],
            user_data['email'], user_data['role'],
            args, True, f"Retrieved {len(orders)} orders"
        )

        return [TextContent(type="text", text=result)]

    except Exception as e:
        error_msg = f"Error getting order history: {str(e)}"
        audit_logger.log_tool_call(
            "get_order_history", user_data['company_id'],
            user_data['email'], user_data['role'],
            args, False, None, error_msg
        )
        return [TextContent(type="text", text=error_msg)]


# ==================== ADMIN TOOLS ====================

async def add_product(args: dict) -> list[TextContent]:
    """Add a new product (admin only)"""
    api_key = args.get("api_key", "")
    name = args.get("name", "")
    category = args.get("category", "")
    price = args.get("price")
    stock = args.get("stock")
    description = args.get("description", "")

    # Authenticate and authorize
    success, user_data, error_msg = authenticate_and_authorize(api_key, "add_product")
    if not success:
        return [TextContent(type="text", text=error_msg)]

    # Validate product data
    valid, msg = security_manager.validate_product_data(name, category, price, stock, description)
    if not valid:
        audit_logger.log_validation_error(
            "add_product", user_data['company_id'],
            user_data['email'], user_data['role'], args, msg
        )
        return [TextContent(type="text", text=msg)]

    # Sanitize strings
    name = security_manager.sanitize_string(name)
    category = security_manager.sanitize_string(category)
    description = security_manager.sanitize_string(description, max_length=1000)

    try:
        # Create product in admin's company
        product_id = db.create_product(
            company_id=user_data['company_id'],
            name=name,
            category=category,
            price=float(price),
            stock=int(stock),
            description=description
        )

        result = f"""
Product Added Successfully!
===========================
Product ID: {product_id}
Name: {name}
Category: {category}
Price: ${float(price):.2f}
Stock: {int(stock)}
Description: {description}

The product is now available in your catalog.
"""

        # Audit log
        audit_logger.log_tool_call(
            "add_product", user_data['company_id'],
            user_data['email'], user_data['role'],
            args, True, f"Created product {product_id}"
        )

        return [TextContent(type="text", text=result)]

    except Exception as e:
        error_msg = f"Error adding product: {str(e)}"
        audit_logger.log_tool_call(
            "add_product", user_data['company_id'],
            user_data['email'], user_data['role'],
            args, False, None, error_msg
        )
        return [TextContent(type="text", text=error_msg)]


async def update_inventory(args: dict) -> list[TextContent]:
    """Update product inventory (admin only)"""
    api_key = args.get("api_key", "")
    product_id = args.get("product_id")
    new_stock = args.get("new_stock")

    # Authenticate and authorize
    success, user_data, error_msg = authenticate_and_authorize(api_key, "update_inventory")
    if not success:
        return [TextContent(type="text", text=error_msg)]

    # Validate product_id
    try:
        product_id = int(product_id)
    except (ValueError, TypeError):
        error_msg = "Invalid product_id"
        audit_logger.log_validation_error(
            "update_inventory", user_data['company_id'],
            user_data['email'], user_data['role'], args, error_msg
        )
        return [TextContent(type="text", text=error_msg)]

    # Validate new_stock
    valid, new_stock, msg = security_manager.validate_non_negative_integer(new_stock, "new_stock")
    if not valid:
        audit_logger.log_validation_error(
            "update_inventory", user_data['company_id'],
            user_data['email'], user_data['role'], args, msg
        )
        return [TextContent(type="text", text=msg)]

    try:
        # Verify product belongs to admin's company
        product = db.get_product_by_id(product_id, user_data['company_id'])
        if not product:
            result = f"Product ID {product_id} not found in your company"
            audit_logger.log_tool_call(
                "update_inventory", user_data['company_id'],
                user_data['email'], user_data['role'],
                args, False, None, result
            )
            return [TextContent(type="text", text=result)]

        # Update stock
        success = db.update_product_stock(product_id, user_data['company_id'], new_stock)

        if not success:
            result = "Failed to update inventory"
            audit_logger.log_tool_call(
                "update_inventory", user_data['company_id'],
                user_data['email'], user_data['role'],
                args, False, None, result
            )
            return [TextContent(type="text", text=result)]

        result = f"""
Inventory Updated Successfully!
================================
Product: {product['name']}
Previous Stock: {product['stock']}
New Stock: {new_stock}
Change: {new_stock - product['stock']:+d}
"""

        # Audit log
        audit_logger.log_tool_call(
            "update_inventory", user_data['company_id'],
            user_data['email'], user_data['role'],
            args, True, f"Updated product {product_id} stock to {new_stock}"
        )

        return [TextContent(type="text", text=result)]

    except Exception as e:
        error_msg = f"Error updating inventory: {str(e)}"
        audit_logger.log_tool_call(
            "update_inventory", user_data['company_id'],
            user_data['email'], user_data['role'],
            args, False, None, error_msg
        )
        return [TextContent(type="text", text=error_msg)]


async def view_all_orders(args: dict) -> list[TextContent]:
    """View all orders for company (admin only)"""
    api_key = args.get("api_key", "")
    status = args.get("status")

    # Authenticate and authorize
    success, user_data, error_msg = authenticate_and_authorize(api_key, "view_all_orders")
    if not success:
        return [TextContent(type="text", text=error_msg)]

    # Validate status if provided
    if status:
        valid, status, msg = security_manager.validate_order_status(status)
        if not valid:
            audit_logger.log_validation_error(
                "view_all_orders", user_data['company_id'],
                user_data['email'], user_data['role'], args, msg
            )
            return [TextContent(type="text", text=msg)]

    try:
        # Get all orders for admin's company
        orders = db.get_all_orders(user_data['company_id'], status)

        if not orders:
            result = "No orders found"
            if status:
                result = f"No orders found with status: {status}"
            audit_logger.log_tool_call(
                "view_all_orders", user_data['company_id'],
                user_data['email'], user_data['role'],
                args, True, result
            )
            return [TextContent(type="text", text=result)]

        # Format results
        result_lines = ["Company Orders"]
        result_lines.append("=" * 50)
        if status:
            result_lines.append(f"Filtered by status: {status.upper()}")
        result_lines.append(f"Total Orders: {len(orders)}\n")

        for order in orders:
            result_lines.append(f"Order ID: {order['order_id']}")
            result_lines.append(f"  Customer: {order['customer_name']} ({order['customer_email']})")
            result_lines.append(f"  Product: {order['product_name']}")
            result_lines.append(f"  Quantity: {order['quantity']}")
            result_lines.append(f"  Total: ${order['total_price']:.2f}")
            result_lines.append(f"  Status: {order['status'].upper()}")
            result_lines.append(f"  Date: {order['created_at']}")
            result_lines.append("")

        result = "\n".join(result_lines)

        # Audit log
        audit_logger.log_tool_call(
            "view_all_orders", user_data['company_id'],
            user_data['email'], user_data['role'],
            args, True, f"Viewed {len(orders)} orders"
        )

        return [TextContent(type="text", text=result)]

    except Exception as e:
        error_msg = f"Error viewing orders: {str(e)}"
        audit_logger.log_tool_call(
            "view_all_orders", user_data['company_id'],
            user_data['email'], user_data['role'],
            args, False, None, error_msg
        )
        return [TextContent(type="text", text=error_msg)]


async def update_order_status(args: dict) -> list[TextContent]:
    """Update order status (admin only)"""
    api_key = args.get("api_key", "")
    order_id = args.get("order_id")
    new_status = args.get("new_status", "")

    # Authenticate and authorize
    success, user_data, error_msg = authenticate_and_authorize(api_key, "update_order_status")
    if not success:
        return [TextContent(type="text", text=error_msg)]

    # Validate order_id
    try:
        order_id = int(order_id)
    except (ValueError, TypeError):
        error_msg = "Invalid order_id"
        audit_logger.log_validation_error(
            "update_order_status", user_data['company_id'],
            user_data['email'], user_data['role'], args, error_msg
        )
        return [TextContent(type="text", text=error_msg)]

    # Validate new_status
    valid, new_status, msg = security_manager.validate_order_status(new_status)
    if not valid:
        audit_logger.log_validation_error(
            "update_order_status", user_data['company_id'],
            user_data['email'], user_data['role'], args, msg
        )
        return [TextContent(type="text", text=msg)]

    try:
        # Verify order belongs to admin's company
        order = db.get_order_by_id(order_id, user_data['company_id'])
        if not order:
            result = f"Order ID {order_id} not found in your company"
            audit_logger.log_tool_call(
                "update_order_status", user_data['company_id'],
                user_data['email'], user_data['role'],
                args, False, None, result
            )
            return [TextContent(type="text", text=result)]

        # Update status
        success = db.update_order_status(order_id, user_data['company_id'], new_status)

        if not success:
            result = "Failed to update order status"
            audit_logger.log_tool_call(
                "update_order_status", user_data['company_id'],
                user_data['email'], user_data['role'],
                args, False, None, result
            )
            return [TextContent(type="text", text=result)]

        result = f"""
Order Status Updated Successfully!
===================================
Order ID: {order_id}
Customer: {order['customer_name']} ({order['customer_email']})
Product: {order['product_name']}
Previous Status: {order['status'].upper()}
New Status: {new_status.upper()}
"""

        # Audit log
        audit_logger.log_tool_call(
            "update_order_status", user_data['company_id'],
            user_data['email'], user_data['role'],
            args, True, f"Updated order {order_id} to {new_status}"
        )

        return [TextContent(type="text", text=result)]

    except Exception as e:
        error_msg = f"Error updating order status: {str(e)}"
        audit_logger.log_tool_call(
            "update_order_status", user_data['company_id'],
            user_data['email'], user_data['role'],
            args, False, None, error_msg
        )
        return [TextContent(type="text", text=error_msg)]


async def sales_summary(args: dict) -> list[TextContent]:
    """Get sales summary (admin only)"""
    api_key = args.get("api_key", "")

    # Authenticate and authorize
    success, user_data, error_msg = authenticate_and_authorize(api_key, "sales_summary")
    if not success:
        return [TextContent(type="text", text=error_msg)]

    try:
        # Get sales summary for admin's company
        summary = db.get_sales_summary(user_data['company_id'])

        # Get low stock products
        low_stock = db.get_low_stock_products(user_data['company_id'], threshold=10)

        # Format results
        result_lines = ["SALES SUMMARY"]
        result_lines.append("=" * 50)
        result_lines.append(f"Total Orders: {summary['total_orders']}")
        result_lines.append(f"Total Revenue: ${summary['total_revenue']:.2f}")
        result_lines.append(f"Average Order Value: ${summary['average_order_value']:.2f}")
        result_lines.append("")

        result_lines.append("Top Products:")
        result_lines.append("-" * 50)
        if summary['top_products']:
            for prod in summary['top_products']:
                result_lines.append(f"  {prod['name']}")
                result_lines.append(f"    Orders: {prod['order_count']}, Total Qty: {prod['total_quantity']}, Revenue: ${prod['revenue']:.2f}")
        else:
            result_lines.append("  No sales data available")
        result_lines.append("")

        result_lines.append("Order Status Breakdown:")
        result_lines.append("-" * 50)
        if summary['status_breakdown']:
            for status in summary['status_breakdown']:
                result_lines.append(f"  {status['status'].upper()}: {status['count']} orders")
        else:
            result_lines.append("  No orders")
        result_lines.append("")

        result_lines.append("Low Stock Alerts (10 or fewer):")
        result_lines.append("-" * 50)
        if low_stock:
            for prod in low_stock:
                result_lines.append(f"  {prod['name']}: {prod['stock']} remaining")
        else:
            result_lines.append("  All products have sufficient stock")

        result = "\n".join(result_lines)

        # Audit log
        audit_logger.log_tool_call(
            "sales_summary", user_data['company_id'],
            user_data['email'], user_data['role'],
            args, True, "Retrieved sales summary"
        )

        return [TextContent(type="text", text=result)]

    except Exception as e:
        error_msg = f"Error getting sales summary: {str(e)}"
        audit_logger.log_tool_call(
            "sales_summary", user_data['company_id'],
            user_data['email'], user_data['role'],
            args, False, None, error_msg
        )
        return [TextContent(type="text", text=error_msg)]


async def rotate_api_key(args: dict) -> list[TextContent]:
    """Rotate API key for a customer (admin only)"""
    api_key = args.get("api_key", "")
    customer_email = args.get("customer_email", "")

    # Authenticate and authorize
    success, user_data, error_msg = authenticate_and_authorize(api_key, "rotate_api_key")
    if not success:
        return [TextContent(type="text", text=error_msg)]

    try:
        # Validate email
        valid, email, msg = security_manager.validate_email(customer_email)
        if not valid:
            audit_logger.log_validation_error(
                "rotate_api_key", user_data['company_id'],
                user_data['email'], user_data['role'], args, msg
            )
            return [TextContent(type="text", text=msg)]

        # Get customer in admin's company
        customer = db.get_customer_by_email(user_data['company_id'], email)
        if not customer:
            error_msg = f"Customer not found: {email}"
            audit_logger.log_tool_call(
                "rotate_api_key", user_data['company_id'],
                user_data['email'], user_data['role'],
                args, False, None, error_msg
            )
            return [TextContent(type="text", text=error_msg)]

        # Generate new API key
        import secrets as sec
        new_api_key = f"{email.split('@')[0]}_rotated_key_{sec.token_hex(8)}"

        # Hash with new salt
        new_salt = security_manager.generate_salt()
        new_hash = security_manager.hash_api_key(new_api_key, new_salt)
        new_lookup_hash = security_manager.hash_api_key(new_api_key, "lookup_salt_constant")

        # Set new expiry based on role
        from datetime import datetime, timedelta
        if customer['role'] == 'admin':
            new_expiry = (datetime.now() + timedelta(days=30)).isoformat()
        else:
            new_expiry = (datetime.now() + timedelta(days=90)).isoformat()

        # Update in database
        success_update = db.update_customer_api_key(
            customer['customer_id'],
            new_hash,
            new_salt,
            new_lookup_hash,
            new_expiry
        )

        if not success_update:
            error_msg = "Failed to rotate API key"
            audit_logger.log_tool_call(
                "rotate_api_key", user_data['company_id'],
                user_data['email'], user_data['role'],
                args, False, None, error_msg
            )
            return [TextContent(type="text", text=error_msg)]

        # Create security alert
        db.create_security_alert(
            alert_type="api_key_rotated",
            severity=security_manager.SEVERITY_LOW,
            api_key_hash=new_hash,
            user_email=customer['email'],
            company_id=user_data['company_id'],
            attempted_action="rotate_api_key",
            reason=f"Admin {user_data['email']} rotated key for {customer['email']}"
        )

        # Format results
        result_lines = ["API KEY ROTATED SUCCESSFULLY"]
        result_lines.append("=" * 50)
        result_lines.append(f"Customer: {customer['name']} ({customer['email']})")
        result_lines.append(f"Role: {customer['role']}")
        result_lines.append(f"\nNEW API KEY: {new_api_key}")
        result_lines.append(f"Expires: {new_expiry}")
        result_lines.append("\n⚠️  IMPORTANT: Save this key now! It won't be shown again.")
        result_lines.append(f"Old key has been invalidated.")

        result_text = "\n".join(result_lines)

        audit_logger.log_tool_call(
            "rotate_api_key", user_data['company_id'],
            user_data['email'], user_data['role'],
            args, True, result_text, None
        )
        return [TextContent(type="text", text=result_text)]

    except Exception as e:
        error_msg = f"Error rotating API key: {str(e)}"
        audit_logger.log_tool_call(
            "rotate_api_key", user_data['company_id'],
            user_data['email'], user_data['role'],
            args, False, None, error_msg
        )
        return [TextContent(type="text", text=error_msg)]


async def view_security_alerts(args: dict) -> list[TextContent]:
    """View security alerts for admin's company (admin only)"""
    api_key = args.get("api_key", "")
    limit = args.get("limit", 20)

    # Authenticate and authorize
    success, user_data, error_msg = authenticate_and_authorize(api_key, "view_security_alerts")
    if not success:
        return [TextContent(type="text", text=error_msg)]

    try:
        # Validate limit
        if not isinstance(limit, int) or limit < 1 or limit > 100:
            limit = 20

        # Get security alerts for company
        alerts = db.get_security_alerts(user_data['company_id'], limit)

        # Format results
        result_lines = [f"SECURITY ALERTS (Last {len(alerts)} alerts)"]
        result_lines.append("=" * 80)

        if not alerts:
            result_lines.append("No security alerts found.")
        else:
            for alert in alerts:
                severity_icon = {
                    "LOW": "ℹ️",
                    "MEDIUM": "⚠️",
                    "HIGH": "🔴",
                    "CRITICAL": "🚨"
                }.get(alert['severity'], "•")

                result_lines.append(f"\n{severity_icon} [{alert['severity']}] {alert['alert_type']}")
                result_lines.append(f"   Time: {alert['timestamp']}")
                if alert['user_email']:
                    result_lines.append(f"   User: {alert['user_email']}")
                if alert['attempted_action']:
                    result_lines.append(f"   Action: {alert['attempted_action']}")
                if alert['reason']:
                    result_lines.append(f"   Reason: {alert['reason']}")
                result_lines.append("-" * 80)

        result_text = "\n".join(result_lines)

        audit_logger.log_tool_call(
            "view_security_alerts", user_data['company_id'],
            user_data['email'], user_data['role'],
            args, True, f"Retrieved {len(alerts)} alerts", None,
            result_count=len(alerts)
        )
        return [TextContent(type="text", text=result_text)]

    except Exception as e:
        error_msg = f"Error retrieving security alerts: {str(e)}"
        audit_logger.log_tool_call(
            "view_security_alerts", user_data['company_id'],
            user_data['email'], user_data['role'],
            args, False, None, error_msg
        )
        return [TextContent(type="text", text=error_msg)]


# ==================== MAIN ====================

async def main():
    """Run the MCP server"""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
