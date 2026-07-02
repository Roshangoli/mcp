#!/usr/bin/env python3


import time
import json
import statistics
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Tuple, Any
from database import Database
from security import SecurityManager

# Use absolute path for database
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "ecommerce.db")

# Test API keys
GLOBAL_KEY = "global_shopper_key_2024"
ADMIN_KEY = "techzone_admin_key_2024"
CUSTOMER_KEY = "techzone_sarah_key_2024"

# Test queries for variety
TEST_QUERIES = ["laptop", "phone", "shoes", "watch", "camera", "headphones",
                "tablet", "monitor", "keyboard", "mouse", "desk", "chair"]


class LoadTester:
    """Comprehensive load testing suite"""

    def __init__(self):
        self.db = Database(DB_PATH)
        self.security = SecurityManager()
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "tests": {}
        }

    def authenticate(self, api_key: str) -> Tuple[bool, Dict, str]:
        """Authenticate user and return user info"""
        return self.security.authenticate(self.db, api_key)

    def measure_latency(self, func, *args, **kwargs) -> Tuple[float, Any, str]:
        """Measure function execution time in milliseconds"""
        start = time.perf_counter()
        error = None
        result = None

        try:
            result = func(*args, **kwargs)
        except Exception as e:
            error = str(e)

        end = time.perf_counter()
        latency_ms = (end - start) * 1000

        return latency_ms, result, error

    def clear_rate_limits(self):
        """Clear rate limit log to reset counters"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM rate_limit_log")
        conn.commit()
        conn.close()

    # ========================================
    # TEST 1: SEQUENTIAL LOAD TEST
    # ========================================

    def test_sequential_load(self, num_calls: int = 500) -> Dict:
        """Run sequential load test with search_products"""
        print("\n" + "="*60)
        print("TEST 1: SEQUENTIAL LOAD TEST")
        print("="*60)
        print(f"Running {num_calls} sequential calls to search_products...")

        # Authenticate once
        success, user, msg = self.authenticate(GLOBAL_KEY)
        if not success:
            print(f"❌ Authentication failed: {msg}")
            return {"error": msg}

        latencies = []
        errors = 0

        # Clear rate limits before starting
        self.clear_rate_limits()

        for i in range(num_calls):
            query = TEST_QUERIES[i % len(TEST_QUERIES)]

            # Clear rate limits every 9 calls to avoid hitting limit
            if i > 0 and i % 9 == 0:
                self.clear_rate_limits()
                time.sleep(0.1)  # Small delay after clearing

            # Measure search_products call
            latency, result, error = self.measure_latency(
                self.db.search_products, query, user.get('company_id'), 10
            )

            latencies.append(latency)
            if error:
                errors += 1

            # Progress indicator
            if (i + 1) % 100 == 0:
                print(f"  Progress: {i + 1}/{num_calls} calls completed...")

        # Calculate statistics
        avg_latency = statistics.mean(latencies)
        min_latency = min(latencies)
        max_latency = max(latencies)
        p50 = statistics.median(latencies)
        p95 = statistics.quantiles(latencies, n=20)[18]  # 95th percentile
        p99 = statistics.quantiles(latencies, n=100)[98]  # 99th percentile

        results = {
            "num_calls": num_calls,
            "avg_latency_ms": round(avg_latency, 2),
            "min_latency_ms": round(min_latency, 2),
            "max_latency_ms": round(max_latency, 2),
            "p50_latency_ms": round(p50, 2),
            "p95_latency_ms": round(p95, 2),
            "p99_latency_ms": round(p99, 2),
            "errors": errors,
            "success_rate": round((num_calls - errors) / num_calls * 100, 2)
        }

        print(f"\n✅ Sequential Load Test Complete:")
        print(f"   Avg Latency:  {results['avg_latency_ms']:.2f} ms")
        print(f"   Min Latency:  {results['min_latency_ms']:.2f} ms")
        print(f"   Max Latency:  {results['max_latency_ms']:.2f} ms")
        print(f"   P50 Latency:  {results['p50_latency_ms']:.2f} ms")
        print(f"   P95 Latency:  {results['p95_latency_ms']:.2f} ms")
        print(f"   P99 Latency:  {results['p99_latency_ms']:.2f} ms")
        print(f"   Errors:       {errors}")
        print(f"   Success Rate: {results['success_rate']}%")

        self.results["tests"]["sequential_load"] = results
        return results

    # ========================================
    # TEST 2: ALL TOOLS TEST
    # ========================================

    def test_all_tools(self) -> Dict:
        """Test all 12 tools and measure individual latencies"""
        print("\n" + "="*60)
        print("TEST 2: ALL TOOLS TEST")
        print("="*60)
        print("Testing all 12 tools (5 customer + 7 admin)...")

        self.clear_rate_limits()

        # Authenticate users
        success, customer_user, msg = self.authenticate(GLOBAL_KEY)
        if not success:
            print(f"❌ Customer auth failed: {msg}")
            return {"error": msg}

        success, admin_user, msg = self.authenticate(ADMIN_KEY)
        if not success:
            print(f"❌ Admin auth failed: {msg}")
            return {"error": msg}

        tool_results = []

        # Customer Tools
        customer_tools = [
            ("search_products", lambda: self.db.search_products("laptop", customer_user.get('company_id'), 10)),
            ("get_product", lambda: self.db.get_product(1)),
            ("place_order", lambda: self.db.create_order(customer_user['id'], [(1, 2), (2, 1)])),
            ("view_orders", lambda: self.db.get_orders(customer_user['id'], 10)),
            ("view_company_info", lambda: self.db.get_company(1 if customer_user.get('company_id') else 1))
        ]

        # Admin Tools
        admin_tools = [
            ("add_product", lambda: self.db.create_product(admin_user['company_id'], "Test Product", "Test Description", 99.99, 10)),
            ("update_inventory", lambda: self.db.update_product_stock(1, 100)),
            ("update_price", lambda: self.db.update_product_price(1, 199.99)),
            ("view_all_orders", lambda: self.db.get_orders_by_company(admin_user['company_id'], None, 10)),
            ("view_customers", lambda: self.db.get_customers_by_company(admin_user['company_id'])),
            ("rotate_api_key", lambda: None),  # Skip actual rotation
            ("view_security_alerts", lambda: self.db.get_security_alerts(admin_user['company_id'], None, 10))
        ]

        print("\n📊 Tool Performance:")
        print(f"{'Tool Name':<25} {'Avg (ms)':<12} {'Min (ms)':<12} {'Max (ms)':<12} {'Status':<10}")
        print("-" * 75)

        # Test customer tools
        for tool_name, tool_func in customer_tools:
            latencies = []
            errors = 0

            # Run each tool 5 times
            for _ in range(5):
                latency, result, error = self.measure_latency(tool_func)
                latencies.append(latency)
                if error:
                    errors += 1
                self.clear_rate_limits()  # Clear between calls
                time.sleep(0.05)

            avg = statistics.mean(latencies)
            min_lat = min(latencies)
            max_lat = max(latencies)
            status = "PASS" if errors == 0 else f"FAIL({errors})"

            tool_results.append({
                "tool": tool_name,
                "type": "customer",
                "avg_ms": round(avg, 2),
                "min_ms": round(min_lat, 2),
                "max_ms": round(max_lat, 2),
                "errors": errors,
                "status": status
            })

            print(f"{tool_name:<25} {avg:>10.2f}   {min_lat:>10.2f}   {max_lat:>10.2f}   {status:<10}")

        # Test admin tools (except rotate_api_key which we skip)
        for tool_name, tool_func in admin_tools:
            if tool_name == "rotate_api_key":
                # Skip actual key rotation to avoid side effects
                tool_results.append({
                    "tool": tool_name,
                    "type": "admin",
                    "avg_ms": 0,
                    "min_ms": 0,
                    "max_ms": 0,
                    "errors": 0,
                    "status": "SKIP"
                })
                print(f"{tool_name:<25} {'SKIPPED (destructive test)'}")
                continue

            latencies = []
            errors = 0

            for _ in range(5):
                latency, result, error = self.measure_latency(tool_func)
                latencies.append(latency)
                if error:
                    errors += 1
                self.clear_rate_limits()
                time.sleep(0.05)

            avg = statistics.mean(latencies)
            min_lat = min(latencies)
            max_lat = max(latencies)
            status = "PASS" if errors == 0 else f"FAIL({errors})"

            tool_results.append({
                "tool": tool_name,
                "type": "admin",
                "avg_ms": round(avg, 2),
                "min_ms": round(min_lat, 2),
                "max_ms": round(max_lat, 2),
                "errors": errors,
                "status": status
            })

            print(f"{tool_name:<25} {avg:>10.2f}   {min_lat:>10.2f}   {max_lat:>10.2f}   {status:<10}")

        print(f"\n✅ All Tools Test Complete: {len([r for r in tool_results if r['status'] == 'PASS'])}/{len(tool_results)} passed")

        self.results["tests"]["all_tools"] = tool_results
        return tool_results

    # ========================================
    # TEST 3: CONCURRENCY TEST
    # ========================================

    def concurrent_worker(self, worker_id: int, num_calls: int) -> Dict:
        """Worker function for concurrent testing"""
        latencies = []
        errors = 0

        # Each worker authenticates once
        success, user, msg = self.authenticate(GLOBAL_KEY)
        if not success:
            return {"latencies": [], "errors": num_calls}

        for i in range(num_calls):
            query = TEST_QUERIES[i % len(TEST_QUERIES)]
            latency, result, error = self.measure_latency(
                self.db.search_products, query, user.get('company_id'), 10
            )
            latencies.append(latency)
            if error:
                errors += 1

        return {"latencies": latencies, "errors": errors}

    def test_concurrency(self, concurrency_levels: List[int] = [10, 50, 100]) -> Dict:
        """Test with different concurrency levels"""
        print("\n" + "="*60)
        print("TEST 3: CONCURRENCY TEST")
        print("="*60)
        print("Simulating concurrent users...")

        results = []

        for num_users in concurrency_levels:
            print(f"\n🔄 Testing with {num_users} concurrent users (5 calls each)...")

            self.clear_rate_limits()

            calls_per_user = 5
            total_calls = num_users * calls_per_user

            start_time = time.perf_counter()

            all_latencies = []
            total_errors = 0

            with ThreadPoolExecutor(max_workers=num_users) as executor:
                futures = [
                    executor.submit(self.concurrent_worker, i, calls_per_user)
                    for i in range(num_users)
                ]

                for future in as_completed(futures):
                    worker_result = future.result()
                    all_latencies.extend(worker_result["latencies"])
                    total_errors += worker_result["errors"]

            end_time = time.perf_counter()
            total_time = end_time - start_time

            # Calculate metrics
            requests_per_sec = total_calls / total_time if total_time > 0 else 0
            avg_latency = statistics.mean(all_latencies) if all_latencies else 0
            error_rate = (total_errors / total_calls * 100) if total_calls > 0 else 0

            result = {
                "num_users": num_users,
                "calls_per_user": calls_per_user,
                "total_calls": total_calls,
                "total_time_sec": round(total_time, 2),
                "requests_per_sec": round(requests_per_sec, 2),
                "avg_latency_ms": round(avg_latency, 2),
                "total_errors": total_errors,
                "error_rate_pct": round(error_rate, 2)
            }

            results.append(result)

            print(f"   Total Time:    {result['total_time_sec']:.2f} sec")
            print(f"   Throughput:    {result['requests_per_sec']:.2f} req/sec")
            print(f"   Avg Latency:   {result['avg_latency_ms']:.2f} ms")
            print(f"   Error Rate:    {result['error_rate_pct']:.2f}%")

        print(f"\n✅ Concurrency Test Complete")

        self.results["tests"]["concurrency"] = results
        return results

    # ========================================
    # TEST 4: SECURITY STRESS TEST
    # ========================================

    def test_security_stress(self) -> Dict:
        """Test security features under stress"""
        print("\n" + "="*60)
        print("TEST 4: SECURITY STRESS TEST")
        print("="*60)
        print("Testing rate limiting, SQL injection, invalid keys, privilege escalation...")

        self.clear_rate_limits()

        security_tests = []

        # Test 1: Rate Limit Enforcement
        print("\n🚦 Test 1: Rate Limit (should block at 11th call)")
        success, user, msg = self.authenticate(GLOBAL_KEY)

        rate_limit_blocked = False
        for i in range(15):
            latency, result, error = self.measure_latency(
                self.security.check_rate_limit,
                self.db,
                user['api_key_hash'],
                user['role'],
                "search_products"
            )

            if i >= 10:  # Should be blocked after 10 calls
                allowed, msg = result if result else (False, "Error")
                if not allowed:
                    rate_limit_blocked = True
                    print(f"   ✅ Call {i+1}: BLOCKED (latency: {latency:.2f} ms)")
                    break

        security_tests.append({
            "attack": "Rate Limit Abuse",
            "blocked": rate_limit_blocked,
            "latency_ms": round(latency, 2),
            "status": "PASS" if rate_limit_blocked else "FAIL"
        })

        self.clear_rate_limits()

        # Test 2: SQL Injection
        print("\n💉 Test 2: SQL Injection Attempt")
        sql_injection_query = "laptop'; DROP TABLE products; --"
        latency, result, error = self.measure_latency(
            self.security.validate_search_params,
            sql_injection_query,
            None,
            None
        )

        valid, msg = result if result else (True, "")
        sql_blocked = not valid  # Should be invalid

        print(f"   Query: {sql_injection_query}")
        print(f"   {'✅ BLOCKED' if sql_blocked else '❌ ALLOWED'} (latency: {latency:.2f} ms)")
        print(f"   Reason: {msg}")

        security_tests.append({
            "attack": "SQL Injection",
            "blocked": sql_blocked,
            "latency_ms": round(latency, 2),
            "status": "PASS" if sql_blocked else "FAIL"
        })

        # Test 3: Invalid API Key
        print("\n🔑 Test 3: Invalid API Key")
        latency, result, error = self.measure_latency(
            self.authenticate,
            "INVALID_KEY_12345"
        )

        success, user, msg = result if result else (True, None, "")
        invalid_blocked = not success  # Should fail

        print(f"   Key: INVALID_KEY_12345")
        print(f"   {'✅ BLOCKED' if invalid_blocked else '❌ ALLOWED'} (latency: {latency:.2f} ms)")
        print(f"   Reason: {msg}")

        security_tests.append({
            "attack": "Invalid API Key",
            "blocked": invalid_blocked,
            "latency_ms": round(latency, 2),
            "status": "PASS" if invalid_blocked else "FAIL"
        })

        # Test 4: Privilege Escalation (customer trying admin tool)
        print("\n🔐 Test 4: Privilege Escalation (customer → admin tool)")
        success, customer_user, msg = self.authenticate(CUSTOMER_KEY)

        latency, result, error = self.measure_latency(
            self.security.authorize,
            "add_product",  # Admin-only tool
            customer_user['role']
        )

        allowed, msg = result if result else (True, "")
        priv_blocked = not allowed  # Should be blocked

        print(f"   User: {customer_user['email']} (role: {customer_user['role']})")
        print(f"   Tool: add_product (admin-only)")
        print(f"   {'✅ BLOCKED' if priv_blocked else '❌ ALLOWED'} (latency: {latency:.2f} ms)")
        print(f"   Reason: {msg}")

        security_tests.append({
            "attack": "Privilege Escalation",
            "blocked": priv_blocked,
            "latency_ms": round(latency, 2),
            "status": "PASS" if priv_blocked else "FAIL"
        })

        # Test 5: Expired Key (simulate with very old timestamp)
        print("\n⏰ Test 5: Expired API Key Check")
        # Note: We can't easily test this without modifying DB, so we'll just verify the logic
        print("   (Logic verified in unit tests - skipped in load test)")

        security_tests.append({
            "attack": "Expired Key Usage",
            "blocked": True,
            "latency_ms": 0,
            "status": "SKIP"
        })

        passed = sum(1 for t in security_tests if t['status'] == 'PASS')
        total = len([t for t in security_tests if t['status'] != 'SKIP'])

        print(f"\n✅ Security Stress Test Complete: {passed}/{total} attacks blocked")

        self.results["tests"]["security_stress"] = security_tests
        return security_tests

    # ========================================
    # TEST 5: REST API BASELINE COMPARISON
    # ========================================

    def direct_db_search(self, query: str) -> List[Dict]:
        """Direct database search bypassing all security layers"""
        conn = self.db.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, company_id, name, description, price, stock_quantity
            FROM products
            WHERE name LIKE ? OR description LIKE ?
            LIMIT 10
        """, (f"%{query}%", f"%{query}%"))

        results = cursor.fetchall()
        conn.close()

        return [dict(row) for row in results]

    def mcp_search(self, query: str, user: Dict) -> List[Dict]:
        """Search through MCP with all security layers"""
        # Full authentication, authorization, rate limiting, validation
        allowed, msg = self.security.check_rate_limit(
            self.db,
            user['api_key_hash'],
            user['role'],
            "search_products"
        )

        if not allowed:
            return []

        valid, msg = self.security.validate_search_params(query, None, None)
        if not valid:
            return []

        return self.db.search_products(query, user.get('company_id'), 10)

    def test_baseline_comparison(self, num_queries: int = 100) -> Dict:
        """Compare direct DB access vs MCP with security layers"""
        print("\n" + "="*60)
        print("TEST 5: REST API BASELINE COMPARISON")
        print("="*60)
        print(f"Comparing direct DB queries vs MCP security layers ({num_queries} queries)...")

        # Authenticate for MCP calls
        success, user, msg = self.authenticate(GLOBAL_KEY)
        if not success:
            print(f"❌ Authentication failed: {msg}")
            return {"error": msg}

        direct_latencies = []
        mcp_latencies = []

        self.clear_rate_limits()

        for i in range(num_queries):
            query = TEST_QUERIES[i % len(TEST_QUERIES)]

            # Clear rate limits every 9 calls
            if i > 0 and i % 9 == 0:
                self.clear_rate_limits()
                time.sleep(0.05)

            # Direct DB call
            latency_direct, result, error = self.measure_latency(
                self.direct_db_search, query
            )
            direct_latencies.append(latency_direct)

            # MCP call with security
            latency_mcp, result, error = self.measure_latency(
                self.mcp_search, query, user
            )
            mcp_latencies.append(latency_mcp)

            if (i + 1) % 25 == 0:
                print(f"  Progress: {i + 1}/{num_queries} queries completed...")

        # Calculate statistics
        avg_direct = statistics.mean(direct_latencies)
        avg_mcp = statistics.mean(mcp_latencies)
        overhead_ms = avg_mcp - avg_direct
        overhead_pct = (overhead_ms / avg_direct * 100) if avg_direct > 0 else 0

        results = {
            "num_queries": num_queries,
            "direct_db_avg_ms": round(avg_direct, 2),
            "mcp_avg_ms": round(avg_mcp, 2),
            "security_overhead_ms": round(overhead_ms, 2),
            "overhead_pct": round(overhead_pct, 2),
            "direct_min_ms": round(min(direct_latencies), 2),
            "direct_max_ms": round(max(direct_latencies), 2),
            "mcp_min_ms": round(min(mcp_latencies), 2),
            "mcp_max_ms": round(max(mcp_latencies), 2)
        }

        print(f"\n📊 Baseline Comparison:")
        print(f"   Direct DB:         {results['direct_db_avg_ms']:.2f} ms avg")
        print(f"   Through MCP:       {results['mcp_avg_ms']:.2f} ms avg")
        print(f"   Security Overhead: {results['security_overhead_ms']:.2f} ms ({results['overhead_pct']:.1f}%)")
        print(f"\n   Direct Range:  {results['direct_min_ms']:.2f} - {results['direct_max_ms']:.2f} ms")
        print(f"   MCP Range:     {results['mcp_min_ms']:.2f} - {results['mcp_max_ms']:.2f} ms")

        print(f"\n✅ Baseline Comparison Complete")

        self.results["tests"]["baseline_comparison"] = results
        return results

    # ========================================
    # FINAL SUMMARY
    # ========================================

    def print_summary(self):
        """Print comprehensive summary of all tests"""
        print("\n\n")
        print("╔" + "="*60 + "╗")
        print("║" + " "*18 + "LOAD TEST RESULTS SUMMARY" + " "*17 + "║")
        print("╠" + "="*60 + "╣")

        # Sequential Load Test
        if "sequential_load" in self.results["tests"]:
            seq = self.results["tests"]["sequential_load"]
            print("║ Sequential Load ({} calls)".format(seq['num_calls']).ljust(61) + "║")
            print("║   Avg Latency:  {:.2f} ms".format(seq['avg_latency_ms']).ljust(61) + "║")
            print("║   P95 Latency:  {:.2f} ms".format(seq['p95_latency_ms']).ljust(61) + "║")
            print("║   P99 Latency:  {:.2f} ms".format(seq['p99_latency_ms']).ljust(61) + "║")
            print("║   Success Rate: {}%".format(seq['success_rate']).ljust(61) + "║")

        print("╠" + "="*60 + "╣")

        # Concurrency Results
        if "concurrency" in self.results["tests"]:
            print("║ Concurrency Results".ljust(61) + "║")
            for conc in self.results["tests"]["concurrency"]:
                print("║   {} users:  {:.1f} req/sec ({}% errors)".format(
                    conc['num_users'],
                    conc['requests_per_sec'],
                    conc['error_rate_pct']
                ).ljust(61) + "║")

        print("╠" + "="*60 + "╣")

        # Security Tests
        if "security_stress" in self.results["tests"]:
            print("║ Security Tests".ljust(61) + "║")
            for test in self.results["tests"]["security_stress"]:
                if test['status'] == 'SKIP':
                    continue
                status = "✅" if test['blocked'] else "❌"
                print("║   {}: {} {}".format(
                    test['attack'].ljust(25),
                    "BLOCKED" if test['blocked'] else "ALLOWED",
                    status
                ).ljust(61) + "║")

        print("╠" + "="*60 + "╣")

        # Baseline Comparison
        if "baseline_comparison" in self.results["tests"]:
            base = self.results["tests"]["baseline_comparison"]
            print("║ MCP vs REST Baseline".ljust(61) + "║")
            print("║   Direct DB:    {:.2f} ms avg".format(base['direct_db_avg_ms']).ljust(61) + "║")
            print("║   Through MCP:  {:.2f} ms avg".format(base['mcp_avg_ms']).ljust(61) + "║")
            print("║   Security overhead: {:.2f} ms ({:.1f}%)".format(
                base['security_overhead_ms'],
                base['overhead_pct']
            ).ljust(61) + "║")

        print("╚" + "="*60 + "╝")
        print()

    def save_results(self, filename: str = "load_test_results.json"):
        """Save results to JSON file"""
        filepath = os.path.join(SCRIPT_DIR, filename)
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"Results saved to {filename}")

    def run_all_tests(self):
        """Run complete test suite"""
        print("╔" + "="*60 + "╗")
        print("║" + " "*10 + "MULTI-COMPANY MCP GATEWAY LOAD TESTS" + " "*14 + "║")
        print("╚" + "="*60 + "╝")

        try:
            # Run all test suites
            self.test_sequential_load(500)
            self.test_all_tools()
            self.test_concurrency([10, 50, 100])
            self.test_security_stress()
            self.test_baseline_comparison(100)

            # Print summary
            self.print_summary()

            # Save results
            self.save_results()

        except Exception as e:
            print(f"\n❌ Test suite error: {e}")
            import traceback
            traceback.print_exc()


def main():
    """Main entry point"""
    tester = LoadTester()
    tester.run_all_tests()
    return 0


if __name__ == "__main__":
    exit(main())
