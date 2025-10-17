"""
Database Honeypot Implementation

Creates a realistic MySQL/PostgreSQL proxy with synthetic data,
realistic schemas, and SQL query simulation to deceive attackers.
"""

import asyncio
import logging
import secrets
import hashlib
import uuid
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
import socket
import struct

logger = logging.getLogger(__name__)

@dataclass
class SyntheticTable:
    """Synthetic database table"""
    name: str
    schema: str
    columns: List[Dict[str, Any]]
    rows: List[Dict[str, Any]]
    synthetic: bool = True
    fingerprint: str = ""
    
    def __post_init__(self):
        if not self.fingerprint:
            data = f"{self.schema}.{self.name}{len(self.columns)}{len(self.rows)}"
            self.fingerprint = hashlib.sha256(data.encode()).hexdigest()[:16]

@dataclass
class QueryExecution:
    """SQL query execution record"""
    query: str
    timestamp: datetime
    session_id: str
    user: str
    database: str
    execution_time_ms: float
    rows_affected: int
    result_rows: int
    error: Optional[str] = None
    synthetic: bool = True

@dataclass
class DatabaseSession:
    """Database session tracking"""
    session_id: str
    username: str
    ip_address: str
    database: str
    start_time: datetime
    last_activity: datetime
    queries: List[QueryExecution]
    connection_info: Dict[str, Any]
    synthetic: bool = True

class SyntheticDataGenerator:
    """Generates realistic synthetic database data"""
    
    FIRST_NAMES = [
        "John", "Jane", "Michael", "Sarah", "David", "Lisa", "Robert", "Emily",
        "James", "Jessica", "William", "Ashley", "Richard", "Amanda", "Thomas", "Jennifer",
        "Christopher", "Elizabeth", "Daniel", "Stephanie", "Matthew", "Rebecca", "Anthony", "Laura"
    ]
    
    LAST_NAMES = [
        "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
        "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas",
        "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson", "White"
    ]
    
    COMPANIES = [
        "TechCorp", "DataSystems", "CloudWorks", "InfoTech", "DigitalSolutions",
        "CyberSoft", "NetServices", "SystemsPlus", "TechAdvantage", "DataFlow",
        "CloudFirst", "InfoSystems", "DigitalEdge", "CyberTech", "NetWorks"
    ]
    
    DEPARTMENTS = [
        "Engineering", "Marketing", "Sales", "HR", "Finance", "Operations",
        "Legal", "IT", "Customer Support", "Product", "Research", "Quality Assurance"
    ]
    
    CITIES = [
        "New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "Philadelphia",
        "San Antonio", "San Diego", "Dallas", "San Jose", "Austin", "Jacksonville",
        "Fort Worth", "Columbus", "Charlotte", "San Francisco", "Indianapolis", "Seattle"
    ]
    
    STATES = [
        "NY", "CA", "IL", "TX", "AZ", "PA", "FL", "WA", "OH", "NC", "IN", "GA"
    ]
    
    @classmethod
    def generate_customer_data(cls, count: int = 1000) -> List[Dict[str, Any]]:
        """Generate synthetic customer data"""
        customers = []
        
        for i in range(count):
            first_name = secrets.choice(cls.FIRST_NAMES)
            last_name = secrets.choice(cls.LAST_NAMES)
            
            customer = {
                "customer_id": i + 1,
                "first_name": first_name,
                "last_name": last_name,
                "email": f"{first_name.lower()}.{last_name.lower()}@{secrets.choice(['gmail.com', 'yahoo.com', 'hotmail.com', 'company.com'])}",
                "phone": f"({secrets.randbelow(900) + 100}) {secrets.randbelow(900) + 100}-{secrets.randbelow(9000) + 1000}",
                "address": f"{secrets.randbelow(9999) + 1} {secrets.choice(['Main', 'Oak', 'Pine', 'Elm', 'Cedar'])} {secrets.choice(['St', 'Ave', 'Blvd', 'Dr'])}",
                "city": secrets.choice(cls.CITIES),
                "state": secrets.choice(cls.STATES),
                "zip_code": f"{secrets.randbelow(90000) + 10000}",
                "registration_date": (datetime.now() - timedelta(days=secrets.randbelow(365))).strftime("%Y-%m-%d"),
                "last_login": (datetime.now() - timedelta(days=secrets.randbelow(30))).strftime("%Y-%m-%d %H:%M:%S"),
                "status": secrets.choice(["Active", "Inactive", "Suspended"]),
                "credit_limit": secrets.randbelow(50000) + 1000,
                "synthetic": True
            }
            customers.append(customer)
        
        return customers
    
    @classmethod
    def generate_employee_data(cls, count: int = 200) -> List[Dict[str, Any]]:
        """Generate synthetic employee data"""
        employees = []
        
        for i in range(count):
            first_name = secrets.choice(cls.FIRST_NAMES)
            last_name = secrets.choice(cls.LAST_NAMES)
            
            employee = {
                "employee_id": i + 1,
                "first_name": first_name,
                "last_name": last_name,
                "email": f"{first_name.lower()}.{last_name.lower()}@corptech.com",
                "department": secrets.choice(cls.DEPARTMENTS),
                "position": secrets.choice(["Manager", "Senior", "Junior", "Lead", "Director", "VP", "Analyst", "Specialist"]),
                "hire_date": (datetime.now() - timedelta(days=secrets.randbelow(1825))).strftime("%Y-%m-%d"),  # Up to 5 years ago
                "salary": secrets.randbelow(100000) + 40000,
                "manager_id": secrets.randbelow(20) + 1 if i > 20 else None,
                "phone_ext": secrets.randbelow(9000) + 1000,
                "office_location": f"Building {secrets.choice(['A', 'B', 'C'])}, Floor {secrets.randbelow(10) + 1}",
                "status": secrets.choice(["Active", "On Leave", "Terminated"]),
                "synthetic": True
            }
            employees.append(employee)
        
        return employees
    
    @classmethod
    def generate_order_data(cls, count: int = 5000) -> List[Dict[str, Any]]:
        """Generate synthetic order data"""
        orders = []
        
        for i in range(count):
            order_date = datetime.now() - timedelta(days=secrets.randbelow(365))
            
            order = {
                "order_id": i + 1,
                "customer_id": secrets.randbelow(1000) + 1,
                "order_date": order_date.strftime("%Y-%m-%d %H:%M:%S"),
                "total_amount": round(secrets.randbelow(50000) / 100, 2),  # $0.00 to $500.00
                "status": secrets.choice(["Pending", "Processing", "Shipped", "Delivered", "Cancelled"]),
                "payment_method": secrets.choice(["Credit Card", "Debit Card", "PayPal", "Bank Transfer", "Cash"]),
                "shipping_address": f"{secrets.randbelow(9999) + 1} {secrets.choice(['Main', 'Oak', 'Pine'])} St",
                "shipping_city": secrets.choice(cls.CITIES),
                "shipping_state": secrets.choice(cls.STATES),
                "tracking_number": f"TRK{secrets.randbelow(900000000) + 100000000}",
                "notes": secrets.choice([None, "Rush delivery", "Gift wrap", "Fragile items", "Call before delivery"]),
                "synthetic": True
            }
            orders.append(order)
        
        return orders
    
    @classmethod
    def generate_product_data(cls, count: int = 500) -> List[Dict[str, Any]]:
        """Generate synthetic product data"""
        products = []
        
        categories = ["Electronics", "Clothing", "Books", "Home & Garden", "Sports", "Toys", "Automotive"]
        
        for i in range(count):
            category = secrets.choice(categories)
            
            product = {
                "product_id": i + 1,
                "name": f"{category} Item {i + 1}",
                "description": f"High-quality {category.lower()} product with excellent features",
                "category": category,
                "price": round(secrets.randbelow(100000) / 100, 2),  # $0.00 to $1000.00
                "cost": round(secrets.randbelow(50000) / 100, 2),   # Cost is typically less than price
                "stock_quantity": secrets.randbelow(1000),
                "sku": f"SKU{secrets.randbelow(900000) + 100000}",
                "weight": round(secrets.randbelow(5000) / 100, 2),  # 0.00 to 50.00 lbs
                "dimensions": f"{secrets.randbelow(50) + 1}x{secrets.randbelow(50) + 1}x{secrets.randbelow(50) + 1}",
                "supplier_id": secrets.randbelow(50) + 1,
                "created_date": (datetime.now() - timedelta(days=secrets.randbelow(730))).strftime("%Y-%m-%d"),
                "synthetic": True
            }
            products.append(product)
        
        return products

class DatabaseSchema:
    """Manages database schema and synthetic data"""
    
    def __init__(self):
        self.databases = {
            "corptech_db": self._create_corptech_schema(),
            "customer_db": self._create_customer_schema(),
            "hr_system": self._create_hr_schema(),
            "inventory": self._create_inventory_schema()
        }
    
    def _create_corptech_schema(self) -> Dict[str, SyntheticTable]:
        """Create main corporate database schema"""
        tables = {}
        
        # Users table
        users_data = []
        for i in range(100):
            first_name = secrets.choice(SyntheticDataGenerator.FIRST_NAMES)
            last_name = secrets.choice(SyntheticDataGenerator.LAST_NAMES)
            users_data.append({
                "id": i + 1,
                "username": f"{first_name.lower()}.{last_name.lower()}",
                "email": f"{first_name.lower()}.{last_name.lower()}@corptech.com",
                "password_hash": f"$2b$12${secrets.token_hex(22)}",
                "first_name": first_name,
                "last_name": last_name,
                "role": secrets.choice(["admin", "user", "manager", "viewer"]),
                "department": secrets.choice(SyntheticDataGenerator.DEPARTMENTS),
                "created_at": (datetime.now() - timedelta(days=secrets.randbelow(365))).strftime("%Y-%m-%d %H:%M:%S"),
                "last_login": (datetime.now() - timedelta(days=secrets.randbelow(30))).strftime("%Y-%m-%d %H:%M:%S"),
                "active": secrets.choice([True, False])
            })
        
        tables["users"] = SyntheticTable(
            name="users",
            schema="corptech_db",
            columns=[
                {"name": "id", "type": "INT", "primary_key": True, "auto_increment": True},
                {"name": "username", "type": "VARCHAR(50)", "unique": True, "not_null": True},
                {"name": "email", "type": "VARCHAR(100)", "unique": True, "not_null": True},
                {"name": "password_hash", "type": "VARCHAR(255)", "not_null": True},
                {"name": "first_name", "type": "VARCHAR(50)", "not_null": True},
                {"name": "last_name", "type": "VARCHAR(50)", "not_null": True},
                {"name": "role", "type": "ENUM('admin','user','manager','viewer')", "default": "user"},
                {"name": "department", "type": "VARCHAR(50)"},
                {"name": "created_at", "type": "TIMESTAMP", "default": "CURRENT_TIMESTAMP"},
                {"name": "last_login", "type": "TIMESTAMP"},
                {"name": "active", "type": "BOOLEAN", "default": True}
            ],
            rows=users_data
        )
        
        # Sessions table
        sessions_data = []
        for i in range(50):
            sessions_data.append({
                "id": i + 1,
                "user_id": secrets.randbelow(100) + 1,
                "session_token": secrets.token_hex(32),
                "ip_address": f"192.168.1.{secrets.randbelow(254) + 1}",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "created_at": (datetime.now() - timedelta(hours=secrets.randbelow(24))).strftime("%Y-%m-%d %H:%M:%S"),
                "expires_at": (datetime.now() + timedelta(hours=secrets.randbelow(24))).strftime("%Y-%m-%d %H:%M:%S"),
                "active": secrets.choice([True, False])
            })
        
        tables["sessions"] = SyntheticTable(
            name="sessions",
            schema="corptech_db",
            columns=[
                {"name": "id", "type": "INT", "primary_key": True, "auto_increment": True},
                {"name": "user_id", "type": "INT", "foreign_key": "users.id"},
                {"name": "session_token", "type": "VARCHAR(64)", "unique": True, "not_null": True},
                {"name": "ip_address", "type": "VARCHAR(45)"},
                {"name": "user_agent", "type": "TEXT"},
                {"name": "created_at", "type": "TIMESTAMP", "default": "CURRENT_TIMESTAMP"},
                {"name": "expires_at", "type": "TIMESTAMP"},
                {"name": "active", "type": "BOOLEAN", "default": True}
            ],
            rows=sessions_data
        )
        
        return tables
    
    def _create_customer_schema(self) -> Dict[str, SyntheticTable]:
        """Create customer database schema"""
        tables = {}
        
        # Customers table
        customers_data = SyntheticDataGenerator.generate_customer_data(1000)
        
        tables["customers"] = SyntheticTable(
            name="customers",
            schema="customer_db",
            columns=[
                {"name": "customer_id", "type": "INT", "primary_key": True, "auto_increment": True},
                {"name": "first_name", "type": "VARCHAR(50)", "not_null": True},
                {"name": "last_name", "type": "VARCHAR(50)", "not_null": True},
                {"name": "email", "type": "VARCHAR(100)", "unique": True, "not_null": True},
                {"name": "phone", "type": "VARCHAR(20)"},
                {"name": "address", "type": "VARCHAR(255)"},
                {"name": "city", "type": "VARCHAR(50)"},
                {"name": "state", "type": "VARCHAR(2)"},
                {"name": "zip_code", "type": "VARCHAR(10)"},
                {"name": "registration_date", "type": "DATE"},
                {"name": "last_login", "type": "TIMESTAMP"},
                {"name": "status", "type": "ENUM('Active','Inactive','Suspended')", "default": "Active"},
                {"name": "credit_limit", "type": "DECIMAL(10,2)", "default": 0}
            ],
            rows=customers_data
        )
        
        # Orders table
        orders_data = SyntheticDataGenerator.generate_order_data(5000)
        
        tables["orders"] = SyntheticTable(
            name="orders",
            schema="customer_db",
            columns=[
                {"name": "order_id", "type": "INT", "primary_key": True, "auto_increment": True},
                {"name": "customer_id", "type": "INT", "foreign_key": "customers.customer_id"},
                {"name": "order_date", "type": "TIMESTAMP", "default": "CURRENT_TIMESTAMP"},
                {"name": "total_amount", "type": "DECIMAL(10,2)", "not_null": True},
                {"name": "status", "type": "ENUM('Pending','Processing','Shipped','Delivered','Cancelled')", "default": "Pending"},
                {"name": "payment_method", "type": "VARCHAR(50)"},
                {"name": "shipping_address", "type": "VARCHAR(255)"},
                {"name": "shipping_city", "type": "VARCHAR(50)"},
                {"name": "shipping_state", "type": "VARCHAR(2)"},
                {"name": "tracking_number", "type": "VARCHAR(50)"},
                {"name": "notes", "type": "TEXT"}
            ],
            rows=orders_data
        )
        
        return tables
    
    def _create_hr_schema(self) -> Dict[str, SyntheticTable]:
        """Create HR system schema"""
        tables = {}
        
        # Employees table
        employees_data = SyntheticDataGenerator.generate_employee_data(200)
        
        tables["employees"] = SyntheticTable(
            name="employees",
            schema="hr_system",
            columns=[
                {"name": "employee_id", "type": "INT", "primary_key": True, "auto_increment": True},
                {"name": "first_name", "type": "VARCHAR(50)", "not_null": True},
                {"name": "last_name", "type": "VARCHAR(50)", "not_null": True},
                {"name": "email", "type": "VARCHAR(100)", "unique": True, "not_null": True},
                {"name": "department", "type": "VARCHAR(50)"},
                {"name": "position", "type": "VARCHAR(100)"},
                {"name": "hire_date", "type": "DATE"},
                {"name": "salary", "type": "DECIMAL(10,2)"},
                {"name": "manager_id", "type": "INT", "foreign_key": "employees.employee_id"},
                {"name": "phone_ext", "type": "VARCHAR(10)"},
                {"name": "office_location", "type": "VARCHAR(100)"},
                {"name": "status", "type": "ENUM('Active','On Leave','Terminated')", "default": "Active"}
            ],
            rows=employees_data
        )
        
        return tables
    
    def _create_inventory_schema(self) -> Dict[str, SyntheticTable]:
        """Create inventory database schema"""
        tables = {}
        
        # Products table
        products_data = SyntheticDataGenerator.generate_product_data(500)
        
        tables["products"] = SyntheticTable(
            name="products",
            schema="inventory",
            columns=[
                {"name": "product_id", "type": "INT", "primary_key": True, "auto_increment": True},
                {"name": "name", "type": "VARCHAR(255)", "not_null": True},
                {"name": "description", "type": "TEXT"},
                {"name": "category", "type": "VARCHAR(50)"},
                {"name": "price", "type": "DECIMAL(10,2)", "not_null": True},
                {"name": "cost", "type": "DECIMAL(10,2)"},
                {"name": "stock_quantity", "type": "INT", "default": 0},
                {"name": "sku", "type": "VARCHAR(50)", "unique": True},
                {"name": "weight", "type": "DECIMAL(8,2)"},
                {"name": "dimensions", "type": "VARCHAR(50)"},
                {"name": "supplier_id", "type": "INT"},
                {"name": "created_date", "type": "DATE"}
            ],
            rows=products_data
        )
        
        return tables
    
    def get_database(self, db_name: str) -> Optional[Dict[str, SyntheticTable]]:
        """Get database by name"""
        return self.databases.get(db_name)
    
    def get_table(self, db_name: str, table_name: str) -> Optional[SyntheticTable]:
        """Get table by database and table name"""
        db = self.get_database(db_name)
        if db:
            return db.get(table_name)
        return None
    
    def list_databases(self) -> List[str]:
        """List all database names"""
        return list(self.databases.keys())
    
    def list_tables(self, db_name: str) -> List[str]:
        """List all table names in a database"""
        db = self.get_database(db_name)
        if db:
            return list(db.keys())
        return []

class SQLQueryProcessor:
    """Processes SQL queries and returns realistic responses"""
    
    def __init__(self, schema: DatabaseSchema):
        self.schema = schema
        self.current_database = "corptech_db"
    
    def execute_query(self, query: str) -> Tuple[List[Dict[str, Any]], int, Optional[str]]:
        """Execute SQL query and return results, affected rows, and error"""
        
        query = query.strip().rstrip(';')
        
        try:
            # Parse query type
            query_upper = query.upper()
            
            if query_upper.startswith('SELECT'):
                return self._execute_select(query)
            elif query_upper.startswith('INSERT'):
                return self._execute_insert(query)
            elif query_upper.startswith('UPDATE'):
                return self._execute_update(query)
            elif query_upper.startswith('DELETE'):
                return self._execute_delete(query)
            elif query_upper.startswith('SHOW'):
                return self._execute_show(query)
            elif query_upper.startswith('DESCRIBE') or query_upper.startswith('DESC'):
                return self._execute_describe(query)
            elif query_upper.startswith('USE'):
                return self._execute_use(query)
            elif query_upper.startswith('CREATE'):
                return self._execute_create(query)
            elif query_upper.startswith('DROP'):
                return self._execute_drop(query)
            else:
                return [], 0, f"Unknown SQL command: {query.split()[0]}"
                
        except Exception as e:
            return [], 0, f"SQL Error: {str(e)}"
    
    def _execute_select(self, query: str) -> Tuple[List[Dict[str, Any]], int, Optional[str]]:
        """Execute SELECT query"""
        
        # Simple SELECT parsing - this is a basic implementation
        query_upper = query.upper()
        
        # Extract table name
        from_match = re.search(r'FROM\s+(\w+)', query_upper)
        if not from_match:
            return [], 0, "No table specified in FROM clause"
        
        table_name = from_match.group(1).lower()
        
        # Get table data
        table = self.schema.get_table(self.current_database, table_name)
        if not table:
            return [], 0, f"Table '{table_name}' doesn't exist"
        
        # Extract columns
        select_match = re.search(r'SELECT\s+(.*?)\s+FROM', query_upper)
        if not select_match:
            return [], 0, "Invalid SELECT syntax"
        
        columns_str = select_match.group(1).strip()
        
        # Handle SELECT *
        if columns_str == '*':
            selected_columns = [col["name"] for col in table.columns]
        else:
            selected_columns = [col.strip() for col in columns_str.split(',')]
        
        # Apply WHERE clause (basic implementation)
        filtered_rows = table.rows
        where_match = re.search(r'WHERE\s+(.*?)(?:\s+ORDER\s+BY|\s+LIMIT|$)', query_upper)
        if where_match:
            where_clause = where_match.group(1).strip()
            filtered_rows = self._apply_where_clause(table.rows, where_clause)
        
        # Apply LIMIT
        limit_match = re.search(r'LIMIT\s+(\d+)', query_upper)
        if limit_match:
            limit = int(limit_match.group(1))
            filtered_rows = filtered_rows[:limit]
        
        # Select only requested columns
        result_rows = []
        for row in filtered_rows:
            result_row = {}
            for col in selected_columns:
                if col.lower() in [c.lower() for c in row.keys()]:
                    # Find the actual key (case-sensitive)
                    actual_key = next(k for k in row.keys() if k.lower() == col.lower())
                    result_row[col] = row[actual_key]
                else:
                    result_row[col] = None
            result_rows.append(result_row)
        
        return result_rows, len(result_rows), None
    
    def _execute_insert(self, query: str) -> Tuple[List[Dict[str, Any]], int, Optional[str]]:
        """Execute INSERT query"""
        # Simulate INSERT - don't actually modify data
        
        # Extract table name
        match = re.search(r'INSERT\s+INTO\s+(\w+)', query.upper())
        if not match:
            return [], 0, "Invalid INSERT syntax"
        
        table_name = match.group(1).lower()
        
        # Check if table exists
        table = self.schema.get_table(self.current_database, table_name)
        if not table:
            return [], 0, f"Table '{table_name}' doesn't exist"
        
        # Simulate successful insert
        affected_rows = 1
        return [], affected_rows, None
    
    def _execute_update(self, query: str) -> Tuple[List[Dict[str, Any]], int, Optional[str]]:
        """Execute UPDATE query"""
        # Simulate UPDATE - don't actually modify data
        
        # Extract table name
        match = re.search(r'UPDATE\s+(\w+)', query.upper())
        if not match:
            return [], 0, "Invalid UPDATE syntax"
        
        table_name = match.group(1).lower()
        
        # Check if table exists
        table = self.schema.get_table(self.current_database, table_name)
        if not table:
            return [], 0, f"Table '{table_name}' doesn't exist"
        
        # Simulate affected rows based on WHERE clause
        where_match = re.search(r'WHERE\s+(.*?)(?:\s+ORDER\s+BY|\s+LIMIT|$)', query.upper())
        if where_match:
            # Simulate some rows affected
            affected_rows = secrets.randbelow(10) + 1
        else:
            # No WHERE clause - would affect all rows
            affected_rows = len(table.rows)
        
        return [], affected_rows, None
    
    def _execute_delete(self, query: str) -> Tuple[List[Dict[str, Any]], int, Optional[str]]:
        """Execute DELETE query"""
        # Simulate DELETE - don't actually modify data
        
        # Extract table name
        match = re.search(r'DELETE\s+FROM\s+(\w+)', query.upper())
        if not match:
            return [], 0, "Invalid DELETE syntax"
        
        table_name = match.group(1).lower()
        
        # Check if table exists
        table = self.schema.get_table(self.current_database, table_name)
        if not table:
            return [], 0, f"Table '{table_name}' doesn't exist"
        
        # Simulate affected rows based on WHERE clause
        where_match = re.search(r'WHERE\s+(.*?)(?:\s+ORDER\s+BY|\s+LIMIT|$)', query.upper())
        if where_match:
            # Simulate some rows affected
            affected_rows = secrets.randbelow(5) + 1
        else:
            # No WHERE clause - would affect all rows (dangerous!)
            affected_rows = len(table.rows)
        
        return [], affected_rows, None
    
    def _execute_show(self, query: str) -> Tuple[List[Dict[str, Any]], int, Optional[str]]:
        """Execute SHOW query"""
        query_upper = query.upper()
        
        if 'SHOW DATABASES' in query_upper:
            databases = self.schema.list_databases()
            result = [{"Database": db} for db in databases]
            return result, len(result), None
        
        elif 'SHOW TABLES' in query_upper:
            tables = self.schema.list_tables(self.current_database)
            result = [{"Tables_in_" + self.current_database: table} for table in tables]
            return result, len(result), None
        
        elif 'SHOW COLUMNS' in query_upper or 'SHOW FIELDS' in query_upper:
            # Extract table name
            match = re.search(r'FROM\s+(\w+)', query_upper)
            if not match:
                return [], 0, "No table specified"
            
            table_name = match.group(1).lower()
            table = self.schema.get_table(self.current_database, table_name)
            if not table:
                return [], 0, f"Table '{table_name}' doesn't exist"
            
            result = []
            for col in table.columns:
                result.append({
                    "Field": col["name"],
                    "Type": col["type"],
                    "Null": "NO" if col.get("not_null") else "YES",
                    "Key": "PRI" if col.get("primary_key") else ("UNI" if col.get("unique") else ""),
                    "Default": col.get("default", "NULL"),
                    "Extra": "auto_increment" if col.get("auto_increment") else ""
                })
            
            return result, len(result), None
        
        else:
            return [], 0, f"Unknown SHOW command: {query}"
    
    def _execute_describe(self, query: str) -> Tuple[List[Dict[str, Any]], int, Optional[str]]:
        """Execute DESCRIBE query"""
        # Extract table name
        parts = query.split()
        if len(parts) < 2:
            return [], 0, "No table specified"
        
        table_name = parts[1].lower()
        table = self.schema.get_table(self.current_database, table_name)
        if not table:
            return [], 0, f"Table '{table_name}' doesn't exist"
        
        result = []
        for col in table.columns:
            result.append({
                "Field": col["name"],
                "Type": col["type"],
                "Null": "NO" if col.get("not_null") else "YES",
                "Key": "PRI" if col.get("primary_key") else ("UNI" if col.get("unique") else ""),
                "Default": col.get("default", "NULL"),
                "Extra": "auto_increment" if col.get("auto_increment") else ""
            })
        
        return result, len(result), None
    
    def _execute_use(self, query: str) -> Tuple[List[Dict[str, Any]], int, Optional[str]]:
        """Execute USE query"""
        parts = query.split()
        if len(parts) < 2:
            return [], 0, "No database specified"
        
        db_name = parts[1].lower()
        if db_name in self.schema.list_databases():
            self.current_database = db_name
            return [], 0, None
        else:
            return [], 0, f"Unknown database '{db_name}'"
    
    def _execute_create(self, query: str) -> Tuple[List[Dict[str, Any]], int, Optional[str]]:
        """Execute CREATE query"""
        # Simulate CREATE - don't actually create anything
        return [], 0, None
    
    def _execute_drop(self, query: str) -> Tuple[List[Dict[str, Any]], int, Optional[str]]:
        """Execute DROP query"""
        # Simulate DROP - don't actually drop anything
        return [], 1, None
    
    def _apply_where_clause(self, rows: List[Dict[str, Any]], where_clause: str) -> List[Dict[str, Any]]:
        """Apply basic WHERE clause filtering"""
        # This is a very basic implementation
        # In a real system, you'd need a proper SQL parser
        
        filtered_rows = []
        
        # Handle simple equality conditions like "id = 1" or "name = 'John'"
        eq_match = re.search(r'(\w+)\s*=\s*(.+)', where_clause)
        if eq_match:
            column = eq_match.group(1).lower()
            value = eq_match.group(2).strip().strip("'\"")
            
            for row in rows:
                # Find matching column (case-insensitive)
                row_value = None
                for key, val in row.items():
                    if key.lower() == column:
                        row_value = str(val)
                        break
                
                if row_value == value:
                    filtered_rows.append(row)
        else:
            # If we can't parse the WHERE clause, return some random subset
            filtered_rows = rows[:secrets.randbelow(len(rows)) + 1] if rows else []
        
        return filtered_rows

class DatabaseHoneypot:
    """Main Database Honeypot class"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 3306, db_type: str = "mysql"):
        self.host = host
        self.port = port
        self.db_type = db_type.lower()
        self.schema = DatabaseSchema()
        self.sessions: Dict[str, DatabaseSession] = {}
        self.server = None
        
        # Synthetic credentials
        self.credentials = {
            "root": "password",
            "admin": "admin123",
            "user": "user123",
            "dbuser": "dbpass",
            "backup": "backup123"
        }
    
    async def start(self):
        """Start the database honeypot server"""
        try:
            self.server = await asyncio.start_server(
                self._handle_client,
                self.host,
                self.port
            )
            
            logger.info(f"Database Honeypot ({self.db_type}) started on {self.host}:{self.port}")
            
        except Exception as e:
            logger.error(f"Failed to start database honeypot: {e}")
            raise
    
    async def stop(self):
        """Stop the database honeypot server"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("Database Honeypot stopped")
    
    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle client connection"""
        client_addr = writer.get_extra_info('peername')
        session_id = str(uuid.uuid4())
        
        logger.info(f"Database connection from {client_addr}", extra={
            "session_id": session_id,
            "client_addr": client_addr,
            "synthetic": True
        })
        
        try:
            if self.db_type == "mysql":
                await self._handle_mysql_client(reader, writer, session_id, client_addr)
            else:
                await self._handle_generic_client(reader, writer, session_id, client_addr)
        
        except Exception as e:
            logger.error(f"Error handling database client: {e}")
        
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def _handle_mysql_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, session_id: str, client_addr: Tuple[str, int]):
        """Handle MySQL protocol client"""
        
        # Send MySQL handshake
        await self._send_mysql_handshake(writer)
        
        # Read authentication response
        auth_data = await reader.read(1024)
        if not auth_data:
            return
        
        # Parse authentication (simplified)
        username, password = self._parse_mysql_auth(auth_data)
        
        # Log authentication attempt
        logger.info(f"MySQL auth attempt: {username}:{password}", extra={
            "session_id": session_id,
            "username": username,
            "password": password,
            "synthetic": True
        })
        
        # Check credentials
        if username in self.credentials and self.credentials[username] == password:
            # Send OK packet
            await self._send_mysql_ok(writer)
            
            # Create session
            self.sessions[session_id] = DatabaseSession(
                session_id=session_id,
                username=username,
                ip_address=client_addr[0],
                database="corptech_db",
                start_time=datetime.now(),
                last_activity=datetime.now(),
                queries=[],
                connection_info={"protocol": "mysql", "version": "8.0.27"}
            )
            
            logger.info(f"MySQL auth success: {username}", extra={
                "session_id": session_id,
                "username": username,
                "synthetic": True
            })
            
            # Handle queries
            await self._handle_mysql_queries(reader, writer, session_id)
        
        else:
            # Send error packet
            await self._send_mysql_error(writer, "Access denied for user")
            logger.info(f"MySQL auth failed: {username}", extra={
                "session_id": session_id,
                "username": username,
                "synthetic": True
            })
    
    async def _send_mysql_handshake(self, writer: asyncio.StreamWriter):
        """Send MySQL handshake packet"""
        # Simplified MySQL handshake
        handshake = b'\x0a'  # Protocol version
        handshake += b'8.0.27-honeypot\x00'  # Server version
        handshake += struct.pack('<I', 12345)  # Connection ID
        handshake += b'12345678'  # Auth plugin data part 1
        handshake += b'\x00'  # Filler
        handshake += struct.pack('<H', 0xf7ff)  # Capability flags
        handshake += b'\x21'  # Character set
        handshake += struct.pack('<H', 0x0002)  # Status flags
        handshake += struct.pack('<H', 0x0000)  # Capability flags upper
        handshake += b'\x15'  # Auth plugin data length
        handshake += b'\x00' * 10  # Reserved
        handshake += b'87654321abcdefgh'  # Auth plugin data part 2
        handshake += b'mysql_native_password\x00'  # Auth plugin name
        
        # Add packet header
        packet_length = len(handshake)
        header = struct.pack('<I', packet_length)[:-1] + b'\x00'  # Packet length + sequence
        
        writer.write(header + handshake)
        await writer.drain()
    
    def _parse_mysql_auth(self, data: bytes) -> Tuple[str, str]:
        """Parse MySQL authentication packet (simplified)"""
        try:
            # Skip packet header and capability flags
            offset = 4 + 4 + 4 + 1 + 23  # Simplified parsing
            
            # Extract username (null-terminated)
            username_end = data.find(b'\x00', offset)
            if username_end == -1:
                return "unknown", ""
            
            username = data[offset:username_end].decode('utf-8', errors='ignore')
            offset = username_end + 1
            
            # Extract password length and password
            if offset < len(data):
                pass_len = data[offset]
                offset += 1
                if offset + pass_len <= len(data):
                    password = data[offset:offset + pass_len].decode('utf-8', errors='ignore')
                else:
                    password = ""
            else:
                password = ""
            
            return username, password
        
        except Exception:
            return "unknown", ""
    
    async def _send_mysql_ok(self, writer: asyncio.StreamWriter):
        """Send MySQL OK packet"""
        ok_packet = b'\x00'  # OK packet type
        ok_packet += b'\x00'  # Affected rows
        ok_packet += b'\x00'  # Last insert ID
        ok_packet += struct.pack('<H', 0x0002)  # Status flags
        ok_packet += struct.pack('<H', 0x0000)  # Warnings
        
        # Add packet header
        header = struct.pack('<I', len(ok_packet))[:-1] + b'\x01'  # Packet length + sequence
        
        writer.write(header + ok_packet)
        await writer.drain()
    
    async def _send_mysql_error(self, writer: asyncio.StreamWriter, message: str):
        """Send MySQL error packet"""
        error_packet = b'\xff'  # Error packet type
        error_packet += struct.pack('<H', 1045)  # Error code
        error_packet += b'#28000'  # SQL state
        error_packet += message.encode('utf-8')
        
        # Add packet header
        header = struct.pack('<I', len(error_packet))[:-1] + b'\x01'  # Packet length + sequence
        
        writer.write(header + error_packet)
        await writer.drain()
    
    async def _handle_mysql_queries(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, session_id: str):
        """Handle MySQL query packets"""
        query_processor = SQLQueryProcessor(self.schema)
        sequence = 1
        
        while True:
            try:
                # Read packet header
                header = await reader.read(4)
                if not header or len(header) < 4:
                    break
                
                packet_length = struct.unpack('<I', header + b'\x00')[0]
                sequence = header[3]
                
                # Read packet data
                packet_data = await reader.read(packet_length)
                if not packet_data:
                    break
                
                # Parse command
                command_type = packet_data[0]
                
                if command_type == 0x03:  # COM_QUERY
                    query = packet_data[1:].decode('utf-8', errors='ignore')
                    
                    # Log query
                    logger.info(f"MySQL query: {query}", extra={
                        "session_id": session_id,
                        "query": query,
                        "synthetic": True
                    })
                    
                    # Execute query
                    start_time = datetime.now()
                    results, affected_rows, error = query_processor.execute_query(query)
                    execution_time = (datetime.now() - start_time).total_seconds() * 1000
                    
                    # Record query execution
                    if session_id in self.sessions:
                        session = self.sessions[session_id]
                        session.last_activity = datetime.now()
                        session.queries.append(QueryExecution(
                            query=query,
                            timestamp=start_time,
                            session_id=session_id,
                            user=session.username,
                            database=session.database,
                            execution_time_ms=execution_time,
                            rows_affected=affected_rows,
                            result_rows=len(results),
                            error=error
                        ))
                    
                    # Send response
                    if error:
                        await self._send_mysql_query_error(writer, error, sequence + 1)
                    else:
                        await self._send_mysql_query_result(writer, results, sequence + 1)
                
                elif command_type == 0x01:  # COM_QUIT
                    break
                
                else:
                    # Unknown command
                    await self._send_mysql_error(writer, f"Unknown command: {command_type}")
            
            except Exception as e:
                logger.error(f"Error handling MySQL query: {e}")
                break
    
    async def _send_mysql_query_result(self, writer: asyncio.StreamWriter, results: List[Dict[str, Any]], sequence: int):
        """Send MySQL query result set"""
        if not results:
            # Send OK packet for empty result
            ok_packet = b'\x00\x00\x00\x02\x00\x00\x00'
            header = struct.pack('<I', len(ok_packet) - 4)[:-1] + bytes([sequence])
            writer.write(header + ok_packet[4:])
            await writer.drain()
            return
        
        # Send column count
        col_count = len(results[0]) if results else 0
        col_packet = bytes([col_count])
        header = struct.pack('<I', len(col_packet))[:-1] + bytes([sequence])
        writer.write(header + col_packet)
        sequence += 1
        
        # Send column definitions (simplified)
        if results:
            for col_name in results[0].keys():
                col_def = b'def\x00\x00\x00' + col_name.encode('utf-8') + b'\x00\x00\x0c\x21\x00\xff\xff\xff\xff\x00\x00'
                header = struct.pack('<I', len(col_def))[:-1] + bytes([sequence])
                writer.write(header + col_def)
                sequence += 1
        
        # Send EOF packet
        eof_packet = b'\xfe\x00\x00\x02\x00'
        header = struct.pack('<I', len(eof_packet))[:-1] + bytes([sequence])
        writer.write(header + eof_packet)
        sequence += 1
        
        # Send rows
        for row in results:
            row_data = b''
            for value in row.values():
                if value is None:
                    row_data += b'\xfb'  # NULL
                else:
                    value_str = str(value).encode('utf-8')
                    row_data += bytes([len(value_str)]) + value_str
            
            header = struct.pack('<I', len(row_data))[:-1] + bytes([sequence])
            writer.write(header + row_data)
            sequence += 1
        
        # Send final EOF packet
        eof_packet = b'\xfe\x00\x00\x02\x00'
        header = struct.pack('<I', len(eof_packet))[:-1] + bytes([sequence])
        writer.write(header + eof_packet)
        
        await writer.drain()
    
    async def _send_mysql_query_error(self, writer: asyncio.StreamWriter, error: str, sequence: int):
        """Send MySQL query error packet"""
        error_packet = b'\xff'
        error_packet += struct.pack('<H', 1064)  # Syntax error code
        error_packet += b'#42000'
        error_packet += error.encode('utf-8')
        
        header = struct.pack('<I', len(error_packet))[:-1] + bytes([sequence])
        writer.write(header + error_packet)
        await writer.drain()
    
    async def _handle_generic_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, session_id: str, client_addr: Tuple[str, int]):
        """Handle generic database client (for non-MySQL protocols)"""
        
        # Send a generic database greeting
        greeting = f"Welcome to {self.db_type.upper()} Database Server\nLogin: "
        writer.write(greeting.encode('utf-8'))
        await writer.drain()
        
        # Read credentials
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=30.0)
            if not data:
                return
            
            credentials = data.decode('utf-8', errors='ignore').strip()
            parts = credentials.split()
            
            username = parts[0] if parts else "unknown"
            password = parts[1] if len(parts) > 1 else ""
            
            # Log authentication attempt
            logger.info(f"Database auth attempt: {username}:{password}", extra={
                "session_id": session_id,
                "username": username,
                "password": password,
                "synthetic": True
            })
            
            # Check credentials
            if username in self.credentials and self.credentials[username] == password:
                writer.write(b"Authentication successful\nSQL> ")
                await writer.drain()
                
                # Create session
                self.sessions[session_id] = DatabaseSession(
                    session_id=session_id,
                    username=username,
                    ip_address=client_addr[0],
                    database="corptech_db",
                    start_time=datetime.now(),
                    last_activity=datetime.now(),
                    queries=[],
                    connection_info={"protocol": self.db_type, "version": "1.0"}
                )
                
                # Handle queries
                await self._handle_generic_queries(reader, writer, session_id)
            
            else:
                writer.write(b"Authentication failed\n")
                await writer.drain()
        
        except asyncio.TimeoutError:
            writer.write(b"Connection timeout\n")
            await writer.drain()
    
    async def _handle_generic_queries(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, session_id: str):
        """Handle generic SQL queries"""
        query_processor = SQLQueryProcessor(self.schema)
        
        while True:
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=300.0)
                if not data:
                    break
                
                query = data.decode('utf-8', errors='ignore').strip()
                if not query:
                    continue
                
                if query.lower() in ['quit', 'exit', 'bye']:
                    writer.write(b"Goodbye\n")
                    await writer.drain()
                    break
                
                # Log query
                logger.info(f"Database query: {query}", extra={
                    "session_id": session_id,
                    "query": query,
                    "synthetic": True
                })
                
                # Execute query
                start_time = datetime.now()
                results, affected_rows, error = query_processor.execute_query(query)
                execution_time = (datetime.now() - start_time).total_seconds() * 1000
                
                # Record query execution
                if session_id in self.sessions:
                    session = self.sessions[session_id]
                    session.last_activity = datetime.now()
                    session.queries.append(QueryExecution(
                        query=query,
                        timestamp=start_time,
                        session_id=session_id,
                        user=session.username,
                        database=session.database,
                        execution_time_ms=execution_time,
                        rows_affected=affected_rows,
                        result_rows=len(results),
                        error=error
                    ))
                
                # Send response
                if error:
                    response = f"ERROR: {error}\n"
                else:
                    if results:
                        # Format results as table
                        if results:
                            headers = list(results[0].keys())
                            response = " | ".join(headers) + "\n"
                            response += "-" * len(response) + "\n"
                            
                            for row in results[:10]:  # Limit to 10 rows for display
                                row_str = " | ".join(str(row.get(h, "NULL")) for h in headers)
                                response += row_str + "\n"
                            
                            if len(results) > 10:
                                response += f"... ({len(results)} total rows)\n"
                        else:
                            response = "Empty result set\n"
                    else:
                        response = f"Query OK, {affected_rows} rows affected\n"
                
                response += "SQL> "
                writer.write(response.encode('utf-8'))
                await writer.drain()
            
            except asyncio.TimeoutError:
                writer.write(b"Session timeout\n")
                await writer.drain()
                break
            except Exception as e:
                logger.error(f"Error handling database query: {e}")
                break
    
    def get_sessions(self) -> Dict[str, DatabaseSession]:
        """Get all session data for intelligence analysis"""
        return self.sessions

if __name__ == "__main__":
    # Example usage
    async def main():
        honeypot = DatabaseHoneypot(port=3306, db_type="mysql")
        await honeypot.start()
        
        try:
            # Keep running
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await honeypot.stop()
    
    asyncio.run(main())