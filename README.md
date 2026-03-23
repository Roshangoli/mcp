# MCPCommerce: Secure Multi-Tenant MCP Gateway for Natural Language E-Commerce Operations

## 📄 Published Paper

**[Read the Paper (DOI: 10.5281/zenodo.19081144)](https://zenodo.org/records/19081144)**

Goli, V. S. R. "MCPCommerce: Designing a Secure Multi-Tenant MCP Gateway for Natural Language E-Commerce Operations." Preprint, March 2026.

---

## What Is This?

MCPCommerce is a prototype-scale, multi-tenant e-commerce gateway built on [Anthropic's Model Context Protocol (MCP)](https://www.anthropic.com/news/model-context-protocol). It connects **one natural language interface** to **eight independent e-commerce companies** through **twelve MCP tools**, with a **ten-layer defense-in-depth security architecture** enforced on every single tool call.

Users interact in plain English via Claude Desktop. The server handles tool selection, routing, authentication, authorization, rate limiting, tenant isolation, and audit logging — automatically.

## Why Does This Matter?

MCP defines the protocol. It doesn't define how to build the server securely behind multiple companies. In 2025 alone:
- A single path traversal bug [exposed 3,000+ MCP servers](https://blog.gitguardian.com/breaking-mcp-server-hosting/)
- A CVSS 9.6 command injection [hit 437,000 developers](https://jfrog.com/blog/cve-2025-6514-mcp-remote/)
- 30+ CVEs were filed against MCP implementations in just two months
- 82% of MCP servers surveyed were vulnerable to basic attacks

MCPCommerce addresses exactly these gaps.

## Key Results

| Metric | Value |
|---|---|
| Average latency | 0.47 ms |
| Peak throughput | 2,973 requests/sec |
| SQL injection vectors blocked | 32/32 (100%) |
| End-to-end task success (Claude Desktop) | 88% (15/17 positive cases) |
| Companies served | 8 |
| MCP tools | 12 |
| Security layers | 10 |
| Codebase | ~2,500 lines across 4 modules |

## Architecture

```
Layer 1 — Claude Desktop (natural language input)
    ↓ MCP Protocol (stdio)
Layer 2 — MCP Server (server.py) — 12 tools, routing
    ↓ authenticate_and_authorize()
Layer 3 — Security Layer (security.py) — SHA-256, RBAC, rate limiting, validation
    ↓
Layer 4 — Database Layer (database.py) — SQLite, parameterized SQL, company_id filter
```

## Ten-Layer Security Stack

| Layer | Mechanism |
|---|---|
| 1 | Salted SHA-256 authentication |
| 2 | API key expiration (90-day customer / 30-day admin) |
| 3 | Role-based access control (3 roles, tool whitelists) |
| 4 | Database-persistent sliding window rate limiting |
| 5 | Query-level tenant isolation (company_id filter) |
| 6 | Security alerts (4-severity database log) |
| 7 | Full audit logging (timestamp, role, execution time) |
| 8 | Input validation (price, length, SQL keyword blocking) |
| 9 | Parameterized SQL (all 44 queries use cursor.execute with params) |
| 10 | Result limiting (50 search / 100 admin cap) |

## The Global Customer Pattern

One API key accesses all eight companies by setting `company_id = NULL`. Orders are stamped with the correct company ID derived from the product, not the customer. Admin tools remain blocked. Tenant isolation is enforced at the query level on every call.

## MCP Tools

| # | Tool | Role | Description |
|---|---|---|---|
| 1 | search_products | customer / global | Search by keyword, price, category |
| 2 | get_product_details | customer / global | Full product info by ID |
| 3 | place_order | customer / global | Place a new order |
| 4 | track_order | customer / global | Real-time order status |
| 5 | get_order_history | customer / global | Past orders by email |
| 6 | add_product | admin | Add product to catalog |
| 7 | update_inventory | admin | Update stock level |
| 8 | view_all_orders | admin | View orders with status filter |
| 9 | update_order_status | admin | Change order status |
| 10 | sales_summary | admin | Revenue and order statistics |
| 11 | rotate_api_key | admin | Generate and replace API key |
| 12 | view_security_alerts | admin | Security alert log |

## Tech Stack

- **Python 3.11** with official MCP SDK from Anthropic
- **SQLite3** for persistence (ACID-compliant, zero-config)
- **Claude Desktop** as the natural language interface
- **stdio transport** (no network exposure)

## Project Structure

```
├── server.py          # MCP server — 12 tools, routing (1,393 lines)
├── database.py        # SQLite operations, parameterized SQL (697 lines)
├── security.py        # Authentication, RBAC, rate limiting (429 lines)
├── logger.py          # Audit logging across all layers (181 lines)
├── requirements.txt   # Python dependencies
└── claude_desktop_config.json  # Claude Desktop MCP configuration
```

## Getting Started

```bash
# Clone the repo
git clone https://github.com/Roshangoli/mcp.git
cd mcp

# Install dependencies
pip install -r requirements.txt

# The server runs via Claude Desktop's MCP configuration
# Add the config from claude_desktop_config.json to your Claude Desktop settings
```

## Citation

If you use MCPCommerce in your research, please cite:

```bibtex
@misc{goli2026mcpcommerce,
  title={MCPCommerce: Designing a Secure Multi-Tenant MCP Gateway for Natural Language E-Commerce Operations},
  author={Goli, Venkata Sai Roshan},
  year={2026},
  month={March},
  doi={10.5281/zenodo.19081144},
  url={https://zenodo.org/records/19081144},
  note={Preprint}
}
```

## Author

**Venkata Sai Roshan Goli**
- MS Computer Science, Illinois Institute of Technology (December 2025)
- Email: vgoli2@hawk.illinoistech.edu
- [LinkedIn](https://www.linkedin.com/in/venkata-sai-roshan-goli/)

## License

This project is available for academic and research purposes. See the paper for full details on the system design and evaluation.
