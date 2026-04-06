import os
import re
import json
import base64
import sqlite3
import time
import hashlib
import ipaddress
import uuid
import threading
from functools import wraps
from datetime import datetime
import urllib.request
import urllib.parse
import urllib.error
import requests
from flask import Flask, request, jsonify, render_template, send_from_directory, session, redirect
from flask_cors import CORS
from email_osint import EmailOSINT

# PostgreSQL support
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False

# ============ DATABASE CONFIGURATION ============
DATABASE_URL = os.environ.get('DATABASE_URL', '')
USE_POSTGRES = bool(DATABASE_URL) and POSTGRES_AVAILABLE

# Fallback to SQLite if no PostgreSQL
DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'data', 'unified.db')

# ============ AUTH CONFIGURATION ============
SYSTEM_PASSWORD_HASH = os.environ.get(
    'ZAGROS_SYSTEM_PASSWORD_HASH',
    'cf66d7fc88cbc15e8d3eeb306864c564a409745a3baef19d457da490e228323e'
)
SESSION_SECRET_KEY = os.environ.get(
    'ZAGROS_SESSION_SECRET_KEY',
    'zagros_secret_key_2026_secure_random_string_for_session_management'
)

FINDCORD_AUTH_TOKEN = os.environ.get('ZAGROS_FINDCORD_AUTH_TOKEN', '')

# CORS - Allow all origins if not specified (for deployment flexibility)
cors_origins_env = os.environ.get('ZAGROS_CORS_ORIGINS', '')
if cors_origins_env:
    ALLOWED_CORS_ORIGINS = [o.strip() for o in cors_origins_env.split(',') if o.strip()]
else:
    # Allow all origins in production
    ALLOWED_CORS_ORIGINS = '*'

REQUIRE_IHBAR_AUTH = os.environ.get('ZAGROS_REQUIRE_IHBAR_AUTH', '0') == '1'

def login_required(f):
    """Decorator to require authentication for routes - supports both session and token auth"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check session first
        if session.get('authenticated'):
            return f(*args, **kwargs)
        
        # Check Authorization header for token-based auth (for production)
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            # Simple token validation - compare with password hash
            if token == SYSTEM_PASSWORD_HASH:
                return f(*args, **kwargs)
        
        # Also check X-Auth-Token header
        token = request.headers.get('X-Auth-Token', '')
        if token:
            import hashlib
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            if token_hash == SYSTEM_PASSWORD_HASH:
                return f(*args, **kwargs)
        
        return jsonify({'error': 'Authentication required', 'redirect': '/login'}), 401
    return decorated_function

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = SESSION_SECRET_KEY

# Secure session cookie defaults - auto-detect HTTPS
@app.before_request
def detect_https():
    # Auto-enable secure cookies if request is HTTPS
    if request.is_secure or request.headers.get('X-Forwarded-Proto', '') == 'https':
        app.config['SESSION_COOKIE_SECURE'] = True
        app.config['SESSION_COOKIE_SAMESITE'] = 'None'

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',  # Default for HTTP
)

# CORS configuration - use wildcard without credentials for production
if ALLOWED_CORS_ORIGINS == '*':
    CORS(app, origins='*', supports_credentials=False)
else:
    CORS(app, origins=ALLOWED_CORS_ORIGINS, supports_credentials=True)

# Initialize OSINT module
osint = EmailOSINT()

# ============ CACHE SYSTEM ============
class SimpleCache:
    """Simple in-memory cache with TTL"""
    def __init__(self, default_ttl=300):  # 5 minutes default
        self.cache = {}
        self.lock = threading.Lock()
        self.default_ttl = default_ttl
    
    def get(self, key):
        with self.lock:
            if key in self.cache:
                value, expiry = self.cache[key]
                if datetime.now() < expiry:
                    return value
                else:
                    del self.cache[key]
            return None
    
    def set(self, key, value, ttl=None):
        with self.lock:
            ttl = ttl or self.default_ttl
            expiry = datetime.now() + timedelta(seconds=ttl)
            self.cache[key] = (value, expiry)
    
    def delete(self, key):
        with self.lock:
            self.cache.pop(key, None)
    
    def clear(self):
        with self.lock:
            self.cache.clear()
    
    def get_stats(self):
        with self.lock:
            total = len(self.cache)
            valid = sum(1 for v, e in self.cache.values() if datetime.now() < e)
            return {'total': total, 'valid': valid, 'expired': total - valid}

# Initialize cache
cache = SimpleCache(default_ttl=300)

# ============ RATE LIMITING ============
class RateLimiter:
    """Simple rate limiter per IP"""
    def __init__(self, max_requests=30, window=60):  # 30 requests per minute
        self.requests = {}
        self.lock = threading.Lock()
        self.max_requests = max_requests
        self.window = window
    
    def is_allowed(self, ip):
        with self.lock:
            now = datetime.now()
            if ip not in self.requests:
                self.requests[ip] = []
            
            # Clean old requests
            self.requests[ip] = [req_time for req_time in self.requests[ip] 
                                if now - req_time < timedelta(seconds=self.window)]
            
            if len(self.requests[ip]) < self.max_requests:
                self.requests[ip].append(now)
                return True
            return False
    
    def get_remaining(self, ip):
        with self.lock:
            now = datetime.now()
            if ip not in self.requests:
                return self.max_requests
            
            valid_requests = [req_time for req_time in self.requests[ip] 
                            if now - req_time < timedelta(seconds=self.window)]
            return max(0, self.max_requests - len(valid_requests))

rate_limiter = RateLimiter()

def rate_limit(f):
    """Rate limiting decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
        
        if not rate_limiter.is_allowed(ip):
            return jsonify({
                'error': 'Rate limit exceeded. Please try again later.',
                'retry_after': 60,
                'remaining': 0
            }), 429
        
        response = f(*args, **kwargs)
        
        # Add rate limit headers
        if isinstance(response, tuple):
            response_obj = response[0]
        else:
            response_obj = response
            response = (response_obj,)
        
        if hasattr(response_obj, 'headers'):
            response_obj.headers['X-RateLimit-Remaining'] = str(rate_limiter.get_remaining(ip))
            response_obj.headers['X-RateLimit-Limit'] = str(rate_limiter.max_requests)
        
        return response
    return decorated_function

# ============ ADVANCED RISK ANALYSIS ============
class RiskAnalyzer:
    """Advanced risk analysis for Discord ID and related data"""
    
    @staticmethod
    def calculate_discord_risk(discord_id, db_results, emails, ips, usernames, email_osint=None, ip_osint=None):
        """
        Calculate comprehensive risk score (0-100)
        Higher score = higher risk/visibility
        """
        score = 0
        factors = []
        recommendations = []
        
        # 1. Database exposure (0-30 points)
        db_records = db_results.get('total_records', 0)
        if db_records > 50:
            score += 30
            factors.append(f"Critical: {db_records} database records found")
            recommendations.append("High exposure in data breaches - consider changing associated accounts")
        elif db_records > 20:
            score += 20
            factors.append(f"High: {db_records} database records found")
            recommendations.append("Multiple data leak exposures detected")
        elif db_records > 5:
            score += 10
            factors.append(f"Medium: {db_records} database records found")
        elif db_records > 0:
            score += 5
            factors.append(f"Low: {db_records} database records found")
        
        # 2. Email exposure (0-25 points)
        email_count = len(emails)
        if email_count > 5:
            score += 25
            factors.append(f"Critical: {email_count} email addresses exposed")
            recommendations.append("Multiple email addresses leaked - high risk of targeted attacks")
        elif email_count > 2:
            score += 15
            factors.append(f"High: {email_count} email addresses exposed")
        elif email_count > 0:
            score += 8
            factors.append(f"Low: {email_count} email address(es) exposed")
        
        # 3. IP exposure (0-20 points)
        ip_count = len(ips)
        if ip_count > 10:
            score += 20
            factors.append(f"Critical: {ip_count} unique IP addresses tracked")
            recommendations.append("Multiple IP locations tracked - possible location tracking risk")
        elif ip_count > 5:
            score += 12
            factors.append(f"High: {ip_count} unique IP addresses tracked")
        elif ip_count > 0:
            score += 5
            factors.append(f"Low: {ip_count} IP address(es) tracked")
        
        # 4. Email OSINT risk (0-15 points)
        if email_osint:
            email_risk = email_osint.get('risk_score', 0)
            if email_risk > 70:
                score += 15
                factors.append(f"Critical email risk: {email_risk}/100")
                recommendations.append("Email has high breach exposure - change recommended")
            elif email_risk > 40:
                score += 8
                factors.append(f"Medium email risk: {email_risk}/100")
        
        # 5. IP security flags (0-10 points)
        if ip_osint and ip_osint.get('flags'):
            flags = ip_osint['flags']
            if flags.get('proxy') or flags.get('hosting'):
                score += 5
                factors.append("IP associated with proxy/hosting service")
        
        # 6. Username diversity (0-10 points)
        username_count = len(usernames)
        if username_count > 5:
            score += 10
            factors.append(f"High username diversity: {username_count} unique usernames")
            recommendations.append("Multiple usernames may indicate account compromise or re-use")
        elif username_count > 2:
            score += 5
            factors.append(f"Medium username diversity: {username_count} usernames")
        
        # Determine risk level
        if score >= 70:
            level = "CRITICAL"
            color = "#ef4444"
        elif score >= 50:
            level = "HIGH"
            color = "#f59e0b"
        elif score >= 30:
            level = "MEDIUM"
            color = "#fbbf24"
        elif score >= 10:
            level = "LOW"
            color = "#3b82f6"
        else:
            level = "MINIMAL"
            color = "#10b981"
        
        return {
            'score': min(score, 100),
            'level': level,
            'color': color,
            'factors': factors,
            'recommendations': recommendations,
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    @staticmethod
    def generate_timeline(db_results):
        """Generate exposure timeline from database records"""
        timeline = []
        
        for source in ['foxnet', 'five_sql', 'mariadb']:
            records = db_results.get(source, [])
            for record in records:
                if record.get('created_at'):
                    try:
                        date = datetime.fromisoformat(record['created_at'].replace('Z', '+00:00'))
                        timeline.append({
                            'date': date.isoformat(),
                            'source': source,
                            'type': 'data_exposure',
                            'details': f"Record found in {source} database"
                        })
                    except:
                        pass
        
        return sorted(timeline, key=lambda x: x['date'], reverse=True)

risk_analyzer = RiskAnalyzer()

DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'data', 'unified.db')

def _try_decode_base64_ip(value):
    if not value:
        return None
    try:
        raw = str(value).strip().strip("'\"")
        if len(raw) % 4 != 0:
            return None
        allowed = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
        if not all(c in allowed for c in raw):
            return None
        decoded = base64.b64decode(raw).decode('utf-8', errors='ignore').strip()
        ipaddress.ip_address(decoded)
        return decoded
    except Exception:
        return None

def normalize_ip(ip_str):
    """Normalize IP address - convert IPv6 to short format or validate IPv4"""
    if not ip_str or ip_str in ['NULL', 'null', '']:
        return None
    
    ip_str = str(ip_str).strip().strip("'\"")

    try:
        # Try to parse as IP address
        ip_obj = ipaddress.ip_address(ip_str)
        
        if isinstance(ip_obj, ipaddress.IPv6Address):
            # For IPv6, return compressed format
            return str(ip_obj)
        else:
            # IPv4 - return as is
            return str(ip_obj)
    except ValueError:
        decoded = _try_decode_base64_ip(ip_str)
        if decoded:
            return decoded

        # Not a valid IP, return original if it looks like IP
        if ':' in ip_str or '.' in ip_str:
            return ip_str.strip()
        return None

def get_db_connection():
    """Get database connection - PostgreSQL or SQLite"""
    if USE_POSTGRES:
        conn = psycopg2.connect(DATABASE_URL)
        conn.cursor_factory = RealDictCursor
        return conn
    else:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        return conn


def _table_has_column(cursor, table_name, column_name):
    try:
        cursor.execute(f"PRAGMA table_info({table_name})")
        cols = [r[1] for r in cursor.fetchall()]
        return column_name in cols
    except Exception:
        return False


def _ensure_column(cursor, table_name, column_name, column_type):
    if not _table_has_column(cursor, table_name, column_name):
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")


def audit_log(event_type, details=None):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO audit_log (event_type, ip, user_agent, details) VALUES (?, ?, ?, ?)',
            (
                str(event_type),
                (request.headers.get('X-Forwarded-For') or request.remote_addr or '') if request else '',
                request.headers.get('User-Agent', '') if request else '',
                json.dumps(details) if isinstance(details, (dict, list)) else (str(details) if details is not None else None)
            )
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

# SQL file URLs from Mega.nz
SQL_FILES = {
    'foxnet': {
        'url': 'https://mega.nz/file/gAcxyTqK#pP7llNGiHvofsKaUonUPNF5JjrKLMEIE4D85ParXE1A',
        'filename': 'sql_1.sql',
        'table': 'foxnet_data'
    },
    'mariadb': {
        'url': 'https://mega.nz/file/VJkBSbyb#7dooJOFvsFObakl84NeINXZC6eEsxMY_ju4HZnrCRmU',
        'filename': 'sql_2.sql',
        'table': 'discord_mariadb'
    },
    'five_sql': {
        'url': 'https://mega.nz/file/pY0lQIzZ#afxXVsayAel7vsrvtkwQ36i3wsmEMRixZIIv9m9TirI',
        'filename': 'sql_3.sql',
        'table': 'five_sql_data'
    }
}

def download_sql_files():
    """Download SQL files from Mega.nz if not exists"""
    import os
    import subprocess
    data_dir = os.path.join(os.path.dirname(__file__), 'sql_data')
    os.makedirs(data_dir, exist_ok=True)
    
    for key, info in SQL_FILES.items():
        filepath = os.path.join(data_dir, info['filename'])
        if os.path.exists(filepath) and os.path.getsize(filepath) > 10*1024*1024:  # > 10MB
            print(f"[✓] {info['filename']} already exists ({os.path.getsize(filepath)/1024/1024:.2f} MB)")
            continue
        
        print(f"[i] Downloading {info['filename']} from Mega.nz...")
        try:
            # Use megadl (megatools) to download from Mega.nz
            result = subprocess.run(
                ['megadl', info['url'], '-o', filepath],
                capture_output=True,
                text=True,
                timeout=600
            )
            
            if result.returncode == 0 and os.path.exists(filepath):
                size_mb = os.path.getsize(filepath)/1024/1024
                if size_mb > 1:
                    print(f"[✓] Downloaded {info['filename']} ({size_mb:.2f} MB)")
                else:
                    print(f"[✗] Download incomplete: {info['filename']} ({size_mb:.2f} MB)")
            else:
                print(f"[✗] Failed to download {info['filename']}: {result.stderr}")
        except FileNotFoundError:
            print(f"[✗] megadl not installed. Install megatools: apt-get install megatools")
        except Exception as e:
            print(f"[✗] Error downloading {info['filename']}: {e}")
    
    return data_dir

def import_sql_to_postgres():
    """Import SQL files into PostgreSQL"""
    import os
    import re
    
    if not USE_POSTGRES:
        print("[i] Not using PostgreSQL, skipping import")
        return
    
    data_dir = os.path.join(os.path.dirname(__file__), 'sql_data')
    conn = psycopg2.connect(DATABASE_URL)
    cursor = conn.cursor()
    
    # Check if data already exists
    cursor.execute('SELECT COUNT(*) FROM foxnet_data')
    if cursor.fetchone()[0] > 0:
        print(f"[✓] Data already imported ({cursor.fetchone()[0]} rows)")
        conn.close()
        return
    
    print("[i] Importing SQL files to PostgreSQL...")
    
    # Import each SQL file
    for key, info in SQL_FILES.items():
        filepath = os.path.join(data_dir, info['filename'])
        if not os.path.exists(filepath):
            print(f"[✗] File not found: {filepath}")
            continue
        
        print(f"[i] Importing {info['filename']} into {info['table']}...")
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Split by INSERT statements
            inserts = re.findall(r'INSERT INTO[^(]*\([^)]*\)\s*VALUES[^;]*;', content, re.IGNORECASE)
            
            inserted = 0
            for insert in inserts:
                try:
                    # Adapt table name
                    insert = re.sub(r'INSERT INTO\s+\w+', f'INSERT INTO {info["table"]}', insert, count=1, flags=re.IGNORECASE)
                    cursor.execute(insert)
                    inserted += 1
                    if inserted % 1000 == 0:
                        conn.commit()
                        print(f"[i] Inserted {inserted} rows...")
                except Exception as e:
                    pass  # Skip errors
            
            conn.commit()
            print(f"[✓] Imported {inserted} rows into {info['table']}")
            
        except Exception as e:
            print(f"[✗] Error importing {info['filename']}: {e}")
    
    # Show final stats
    print("\n[✓] Import completed!")
    for table in ['foxnet_data', 'five_sql_data', 'discord_mariadb']:
        cursor.execute(f'SELECT COUNT(*) FROM {table}')
        count = cursor.fetchone()[0]
        print(f"  {table}: {count:,} rows")
    
    conn.close()

def init_database():
    """Initialize the unified database with tables for all 3 sources"""
    if USE_POSTGRES:
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        # PostgreSQL table creation
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS foxnet_data (
                id SERIAL PRIMARY KEY,
                discord_id TEXT NOT NULL,
                email TEXT,
                ip TEXT,
                server_ids TEXT,
                connections TEXT,
                username TEXT,
                user_agent TEXT,
                raw_data TEXT,
                source_file TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS five_sql_data (
                id SERIAL PRIMARY KEY,
                discord_id TEXT NOT NULL,
                email TEXT,
                ip TEXT,
                server_ids TEXT,
                username TEXT,
                connections TEXT,
                source_file TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS discord_mariadb (
                id SERIAL PRIMARY KEY,
                discord_id TEXT,
                email TEXT,
                ip TEXT,
                username TEXT,
                details TEXT,
                source_table TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_foxnet_discord_id ON foxnet_data(discord_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_five_sql_discord_id ON five_sql_data(discord_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_mariadb_discord_id ON discord_mariadb(discord_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_foxnet_email ON foxnet_data(email)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_five_sql_email ON five_sql_data(email)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_foxnet_ip ON foxnet_data(ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_five_sql_ip ON five_sql_data(ip)')
        
        # Discord friends table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS discord_friends (
                id SERIAL PRIMARY KEY,
                discord_id TEXT NOT NULL,
                friend_id TEXT NOT NULL,
                friend_username TEXT,
                friend_discriminator TEXT,
                friend_email TEXT,
                friend_ip TEXT,
                friend_avatar TEXT,
                relationship_type TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(discord_id, friend_id)
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_friends_discord_id ON discord_friends(discord_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_friends_friend_id ON discord_friends(friend_id)')
        
        # Findcord results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findcord_results (
                id SERIAL PRIMARY KEY,
                discord_id TEXT UNIQUE NOT NULL,
                email TEXT,
                username TEXT,
                discriminator TEXT,
                avatar TEXT,
                verified BOOLEAN,
                locale TEXT,
                flags INTEGER,
                raw_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_findcord_discord_id ON findcord_results(discord_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_findcord_email ON findcord_results(email)')
        
        # Audit log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id SERIAL PRIMARY KEY,
                event_type TEXT NOT NULL,
                ip TEXT,
                user_agent TEXT,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # TC Kimlik table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tc_101m (
                id SERIAL PRIMARY KEY,
                TC TEXT UNIQUE NOT NULL,
                ADI TEXT,
                SOYADI TEXT,
                DOGUMTARIHI TEXT,
                DOGUMYERI TEXT,
                NUFUSIL TEXT,
                NUFUSILCE TEXT,
                ANNEADI TEXT,
                ANNETC TEXT,
                BABAADI TEXT,
                BABATC TEXT,
                CINSIYET TEXT,
                MEDENIHAL TEXT,
                DURUM TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_tc ON tc_101m(TC)')
        
        # İhbar tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ihbar_tickets (
                id SERIAL PRIMARY KEY,
                ticket_id TEXT UNIQUE NOT NULL,
                tc_no TEXT,
                ad_soyad TEXT,
                telefon TEXT,
                email TEXT,
                ihbar_turu TEXT,
                aciklama TEXT,
                durum TEXT DEFAULT 'yeni',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        print("[✓] PostgreSQL tables initialized")
        return
    
    # SQLite fallback
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Table for 270k data (foxnet style)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS foxnet_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id TEXT NOT NULL,
            email TEXT,
            ip TEXT,
            server_ids TEXT,
            connections TEXT,
            username TEXT,
            user_agent TEXT,
            raw_data TEXT,
            source_file TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Table for 5.sql data
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS five_sql_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id TEXT NOT NULL,
            email TEXT,
            ip TEXT,
            server_ids TEXT,
            username TEXT,
            connections TEXT,
            source_file TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Table for discord_data (MariaDB style)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS discord_mariadb (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id TEXT,
            email TEXT,
            ip TEXT,
            username TEXT,
            details TEXT,
            source_table TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create indexes for faster searching
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_foxnet_discord_id ON foxnet_data(discord_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_five_sql_discord_id ON five_sql_data(discord_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_mariadb_discord_id ON discord_mariadb(discord_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_foxnet_email ON foxnet_data(email)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_five_sql_email ON five_sql_data(email)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_foxnet_ip ON foxnet_data(ip)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_five_sql_ip ON five_sql_data(ip)')

    # Ensure columns exist for older databases (lightweight migration)
    _ensure_column(cursor, 'foxnet_data', 'server_ids', 'TEXT')
    _ensure_column(cursor, 'foxnet_data', 'connections', 'TEXT')
    _ensure_column(cursor, 'five_sql_data', 'server_ids', 'TEXT')
    _ensure_column(cursor, 'five_sql_data', 'connections', 'TEXT')
    
    # Table for 101m TC Kimlik veritabanı (gerçek vesika verileri)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tc_101m (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            TC TEXT UNIQUE NOT NULL,
            ADI TEXT,
            SOYADI TEXT,
            DOGUMTARIHI TEXT,
            DOGUMYERI TEXT,
            NUFUSIL TEXT,
            NUFUSILCE TEXT,
            ANNEADI TEXT,
            ANNETC TEXT,
            BABAADI TEXT,
            BABATC TEXT,
            CINSIYET TEXT,
            MEDENIHAL TEXT,
            DURUM TEXT,
            OKULTURU TEXT,
            ALANI TEXT,
            SUBEADI TEXT,
            OKULNO TEXT,
            MEZUNOKUL TEXT,
            DIPLOMAPUANI TEXT,
            VESIKA_IMAGE TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create indexes for TC table
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_tc_101m_tc ON tc_101m(TC)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_tc_101m_adi ON tc_101m(ADI)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_tc_101m_soyadi ON tc_101m(SOYADI)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_tc_101m_annetc ON tc_101m(ANNETC)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_tc_101m_babatc ON tc_101m(BABATC)')
    
    # Table for Turkey Cities (from mernis-turkiye-disctricts)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS turkey_cities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            city_id INTEGER UNIQUE NOT NULL,
            city_name TEXT NOT NULL,
            city_code TEXT,
            region TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Table for Turkey Districts
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS turkey_districts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            district_id INTEGER UNIQUE NOT NULL,
            district_name TEXT NOT NULL,
            city_id INTEGER,
            city_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (city_id) REFERENCES turkey_cities(city_id)
        )
    ''')
    
    # Create indexes for city/district tables
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cities_name ON turkey_cities(city_name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_districts_name ON turkey_districts(district_name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_districts_city ON turkey_districts(city_id)')
    
    # Table for Findcord API results
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS findcord_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id TEXT NOT NULL,
            username TEXT,
            discriminator TEXT,
            avatar TEXT,
            email TEXT,
            verified INTEGER,
            locale TEXT,
            flags INTEGER,
            raw_data TEXT,
            guilds_count INTEGER DEFAULT 0,
            connections_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create indexes for findcord table
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_findcord_discord_id ON findcord_results(discord_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_findcord_username ON findcord_results(username)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_findcord_email ON findcord_results(email)')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS discord_friends (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id TEXT NOT NULL,
            friend_id TEXT NOT NULL,
            friend_username TEXT,
            friend_discriminator TEXT,
            friend_email TEXT,
            friend_ip TEXT,
            friend_avatar TEXT,
            relationship_type TEXT DEFAULT 'friend',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(discord_id, friend_id)
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_friends_discord_id ON discord_friends(discord_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_friends_friend_id ON discord_friends(friend_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_friends_email ON discord_friends(friend_email)')
    
    # Migration: Add friend_ip column if it doesn't exist
    _ensure_column(cursor, 'discord_friends', 'friend_ip', 'TEXT')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_friends_ip ON discord_friends(friend_ip)')

    # Audit log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            ip TEXT,
            user_agent TEXT,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_log(created_at)')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ihbar_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id TEXT UNIQUE NOT NULL,
            category TEXT,
            urgency TEXT,
            description TEXT NOT NULL,
            city TEXT NOT NULL,
            district TEXT NOT NULL,
            phone TEXT NOT NULL,
            address TEXT,
            email TEXT,
            status TEXT DEFAULT 'NEW',
            external_attempted INTEGER DEFAULT 0,
            external_status_code INTEGER,
            external_response TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_ihbar_ticket_id ON ihbar_tickets(ticket_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_ihbar_status ON ihbar_tickets(status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_ihbar_created_at ON ihbar_tickets(created_at)')

    conn.commit()
    conn.close()
    print("[✓] Database initialized successfully")

# ============ TURKEY CITIES/DISTRICTS DATA ============
TURKEY_CITIES_DATA = [
    {"id": 1, "name": "Adana", "code": "01", "region": "Akdeniz"},
    {"id": 2, "name": "Adıyaman", "code": "02", "region": "Güneydoğu Anadolu"},
    {"id": 3, "name": "Afyonkarahisar", "code": "03", "region": "Ege"},
    {"id": 4, "name": "Ağrı", "code": "04", "region": "Doğu Anadolu"},
    {"id": 5, "name": "Amasya", "code": "05", "region": "Karadeniz"},
    {"id": 6, "name": "Ankara", "code": "06", "region": "İç Anadolu"},
    {"id": 7, "name": "Antalya", "code": "07", "region": "Akdeniz"},
    {"id": 8, "name": "Artvin", "code": "08", "region": "Karadeniz"},
    {"id": 9, "name": "Aydın", "code": "09", "region": "Ege"},
    {"id": 10, "name": "Balıkesir", "code": "10", "region": "Marmara"},
    {"id": 11, "name": "Bilecik", "code": "11", "region": "Marmara"},
    {"id": 12, "name": "Bingöl", "code": "12", "region": "Doğu Anadolu"},
    {"id": 13, "name": "Bitlis", "code": "13", "region": "Doğu Anadolu"},
    {"id": 14, "name": "Bolu", "code": "14", "region": "Karadeniz"},
    {"id": 15, "name": "Burdur", "code": "15", "region": "Akdeniz"},
    {"id": 16, "name": "Bursa", "code": "16", "region": "Marmara"},
    {"id": 17, "name": "Çanakkale", "code": "17", "region": "Marmara"},
    {"id": 18, "name": "Çankırı", "code": "18", "region": "İç Anadolu"},
    {"id": 19, "name": "Çorum", "code": "19", "region": "Karadeniz"},
    {"id": 20, "name": "Denizli", "code": "20", "region": "Ege"},
    {"id": 21, "name": "Diyarbakır", "code": "21", "region": "Güneydoğu Anadolu"},
    {"id": 22, "name": "Edirne", "code": "22", "region": "Marmara"},
    {"id": 23, "name": "Elazığ", "code": "23", "region": "Doğu Anadolu"},
    {"id": 24, "name": "Erzincan", "code": "24", "region": "Doğu Anadolu"},
    {"id": 25, "name": "Erzurum", "code": "25", "region": "Doğu Anadolu"},
    {"id": 26, "name": "Eskişehir", "code": "26", "region": "İç Anadolu"},
    {"id": 27, "name": "Gaziantep", "code": "27", "region": "Güneydoğu Anadolu"},
    {"id": 28, "name": "Giresun", "code": "28", "region": "Karadeniz"},
    {"id": 29, "name": "Gümüşhane", "code": "29", "region": "Karadeniz"},
    {"id": 30, "name": "Hakkari", "code": "30", "region": "Doğu Anadolu"},
    {"id": 31, "name": "Hatay", "code": "31", "region": "Akdeniz"},
    {"id": 32, "name": "Isparta", "code": "32", "region": "Akdeniz"},
    {"id": 33, "name": "Mersin", "code": "33", "region": "Akdeniz"},
    {"id": 34, "name": "İstanbul", "code": "34", "region": "Marmara"},
    {"id": 35, "name": "İzmir", "code": "35", "region": "Ege"},
    {"id": 36, "name": "Kars", "code": "36", "region": "Doğu Anadolu"},
    {"id": 37, "name": "Kastamonu", "code": "37", "region": "Karadeniz"},
    {"id": 38, "name": "Kayseri", "code": "38", "region": "İç Anadolu"},
    {"id": 39, "name": "Kırklareli", "code": "39", "region": "Marmara"},
    {"id": 40, "name": "Kırşehir", "code": "40", "region": "İç Anadolu"},
    {"id": 41, "name": "Kocaeli", "code": "41", "region": "Marmara"},
    {"id": 42, "name": "Konya", "code": "42", "region": "İç Anadolu"},
    {"id": 43, "name": "Kütahya", "code": "43", "region": "Ege"},
    {"id": 44, "name": "Malatya", "code": "44", "region": "Doğu Anadolu"},
    {"id": 45, "name": "Manisa", "code": "45", "region": "Ege"},
    {"id": 46, "name": "Kahramanmaraş", "code": "46", "region": "Akdeniz"},
    {"id": 47, "name": "Mardin", "code": "47", "region": "Güneydoğu Anadolu"},
    {"id": 48, "name": "Muğla", "code": "48", "region": "Ege"},
    {"id": 49, "name": "Muş", "code": "49", "region": "Doğu Anadolu"},
    {"id": 50, "name": "Nevşehir", "code": "50", "region": "İç Anadolu"},
    {"id": 51, "name": "Niğde", "code": "51", "region": "İç Anadolu"},
    {"id": 52, "name": "Ordu", "code": "52", "region": "Karadeniz"},
    {"id": 53, "name": "Rize", "code": "53", "region": "Karadeniz"},
    {"id": 54, "name": "Sakarya", "code": "54", "region": "Marmara"},
    {"id": 55, "name": "Samsun", "code": "55", "region": "Karadeniz"},
    {"id": 56, "name": "Siirt", "code": "56", "region": "Güneydoğu Anadolu"},
    {"id": 57, "name": "Sinop", "code": "57", "region": "Karadeniz"},
    {"id": 58, "name": "Sivas", "code": "58", "region": "İç Anadolu"},
    {"id": 59, "name": "Tekirdağ", "code": "59", "region": "Marmara"},
    {"id": 60, "name": "Tokat", "code": "60", "region": "Karadeniz"},
    {"id": 61, "name": "Trabzon", "code": "61", "region": "Karadeniz"},
    {"id": 62, "name": "Tunceli", "code": "62", "region": "Doğu Anadolu"},
    {"id": 63, "name": "Şanlıurfa", "code": "63", "region": "Güneydoğu Anadolu"},
    {"id": 64, "name": "Uşak", "code": "64", "region": "Ege"},
    {"id": 65, "name": "Van", "code": "65", "region": "Doğu Anadolu"},
    {"id": 66, "name": "Yozgat", "code": "66", "region": "İç Anadolu"},
    {"id": 67, "name": "Zonguldak", "code": "67", "region": "Karadeniz"},
    {"id": 68, "name": "Aksaray", "code": "68", "region": "İç Anadolu"},
    {"id": 69, "name": "Bayburt", "code": "69", "region": "Karadeniz"},
    {"id": 70, "name": "Karaman", "code": "70", "region": "İç Anadolu"},
    {"id": 71, "name": "Kırıkkale", "code": "71", "region": "İç Anadolu"},
    {"id": 72, "name": "Batman", "code": "72", "region": "Güneydoğu Anadolu"},
    {"id": 73, "name": "Şırnak", "code": "73", "region": "Güneydoğu Anadolu"},
    {"id": 74, "name": "Bartın", "code": "74", "region": "Karadeniz"},
    {"id": 75, "name": "Ardahan", "code": "75", "region": "Doğu Anadolu"},
    {"id": 76, "name": "Iğdır", "code": "76", "region": "Doğu Anadolu"},
    {"id": 77, "name": "Yalova", "code": "77", "region": "Marmara"},
    {"id": 78, "name": "Karabük", "code": "78", "region": "Karadeniz"},
    {"id": 79, "name": "Kilis", "code": "79", "region": "Güneydoğu Anadolu"},
    {"id": 80, "name": "Osmaniye", "code": "80", "region": "Akdeniz"},
    {"id": 81, "name": "Düzce", "code": "81", "region": "Karadeniz"},
]

def init_turkey_data():
    """Initialize Turkey cities data"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if data already exists
    cursor.execute('SELECT COUNT(*) FROM turkey_cities')
    if cursor.fetchone()[0] > 0:
        conn.close()
        print("[✓] Turkey cities data already loaded")
        return
    
    # Insert cities
    for city in TURKEY_CITIES_DATA:
        cursor.execute('''
            INSERT OR IGNORE INTO turkey_cities (city_id, city_name, city_code, region)
            VALUES (?, ?, ?, ?)
        ''', (city['id'], city['name'], city['code'], city['region']))
    
    conn.commit()
    conn.close()
    print(f"[✓] Loaded {len(TURKEY_CITIES_DATA)} Turkey cities")


# ============ API ROUTES ============

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Authenticate user with password - returns token for API auth"""
    data = request.get_json()
    password = data.get('password', '')
    
    # Hash the provided password and compare
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    if password_hash == SYSTEM_PASSWORD_HASH:
        session['authenticated'] = True
        session.permanent = True
        audit_log('auth_login_success', {'ip': request.remote_addr})
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'token': password  # Return password as token for API auth
        })
    else:
        audit_log('auth_login_failed', {'ip': request.remote_addr})
        return jsonify({
            'success': False,
            'error': 'Invalid password'
        }), 401

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Logout user"""
    audit_log('auth_logout', {'ip': request.remote_addr})
    session.clear()
    return jsonify({
        'success': True,
        'message': 'Logged out'
    })

@app.route('/api/auth/check', methods=['GET'])
def check_auth():
    """Check if user is authenticated"""
    return jsonify({
        'authenticated': session.get('authenticated', False)
    })

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/favicon.ico')
def favicon():
    """Serve favicon if present; otherwise return 204 to avoid console noise."""
    try:
        static_dir = app.static_folder
        if static_dir:
            favicon_path = os.path.join(static_dir, 'favicon.ico')
            if os.path.exists(favicon_path):
                return send_from_directory(static_dir, 'favicon.ico')
    except Exception:
        pass
    return ('', 204)

@app.route('/api/search', methods=['POST'])
@login_required
def search_id():
    """Search for ID across all 3 databases and findcord.com API"""
    data = request.get_json()
    discord_id = data.get('discord_id', '').strip()
    
    if not discord_id:
        return jsonify({'error': 'Discord ID is required'}), 400

    audit_log('search_discord_id', {'discord_id': discord_id})
    
    conn = get_db_connection()
    results = {
        'discord_id': discord_id,
        'foxnet': [],
        'five_sql': [],
        'mariadb': [],
        'emails': set(),
        'ips': set(),
        'usernames': set(),
        'findcord': None  # Will hold findcord.com API results
    }
    
    # Search in foxnet_data
    cursor = conn.execute(
        'SELECT * FROM foxnet_data WHERE discord_id = ?', 
        (discord_id,)
    )
    for row in cursor.fetchall():
        record = dict(row)
        results['foxnet'].append(record)
        if record.get('email'): results['emails'].add(record['email'])
        if record.get('ip'): 
            normalized_ip = normalize_ip(record['ip'])
            if normalized_ip:
                results['ips'].add(normalized_ip)
        username = record.get('username')
        if username and username != 'null' and username.strip():
            results['usernames'].add(username)
    
    # Search in five_sql_data
    cursor = conn.execute(
        'SELECT * FROM five_sql_data WHERE discord_id = ?', 
        (discord_id,)
    )
    for row in cursor.fetchall():
        record = dict(row)
        results['five_sql'].append(record)
        if record.get('email'): results['emails'].add(record['email'])
        if record.get('ip'): 
            normalized_ip = normalize_ip(record['ip'])
            if normalized_ip:
                results['ips'].add(normalized_ip)
        username = record.get('username')
        if username and username != 'null' and username.strip():
            results['usernames'].add(username)
    
    # Search in mariadb
    cursor = conn.execute(
        'SELECT * FROM discord_mariadb WHERE discord_id = ?', 
        (discord_id,)
    )
    for row in cursor.fetchall():
        record = dict(row)
        results['mariadb'].append(record)
        if record.get('email'): results['emails'].add(record['email'])
        if record.get('ip'): 
            normalized_ip = normalize_ip(record['ip'])
            if normalized_ip:
                results['ips'].add(normalized_ip)
        username = record.get('username')
        if username and username != 'null' and username.strip():
            results['usernames'].add(username)
    
    conn.close()
    
    # ===== FINDCORD.COM API INTEGRATION =====
    try:
        findcord_url = f"https://app.findcord.com/api/user/{discord_id}"
        findcord_headers = {
            'Authorization': FINDCORD_AUTH_TOKEN,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json'
        }

        if not FINDCORD_AUTH_TOKEN:
            results['findcord'] = {
                'success': False,
                'error': 'Findcord token not configured',
                'note': 'ZAGROS_FINDCORD_AUTH_TOKEN environment variable is missing'
            }
            results['emails'] = list(results['emails'])
            results['ips'] = list(results['ips'])
            results['usernames'] = list(results['usernames'])
            results['total_records'] = len(results['foxnet']) + len(results['five_sql']) + len(results['mariadb'])
            results['found'] = results['total_records'] > 0
            return jsonify(results)
        
        findcord_response = requests.get(findcord_url, headers=findcord_headers, timeout=10)
        
        if findcord_response.status_code == 200:
            findcord_data = findcord_response.json()
            results['findcord'] = {
                'success': True,
                'data': findcord_data
            }
            # Extract additional info from findcord if available
            if isinstance(findcord_data, dict):
                if findcord_data.get('username') and findcord_data['username'] not in results['usernames']:
                    results['usernames'].add(findcord_data['username'])
                if findcord_data.get('email') and findcord_data['email'] not in results['emails']:
                    results['emails'].add(findcord_data['email'])
                
                # Save to findcord_results table
                try:
                    conn_save = get_db_connection()
                    cursor_save = conn_save.cursor()
                    
                    # Check if record already exists for this discord_id
                    cursor_save.execute('SELECT id FROM findcord_results WHERE discord_id = ?', (discord_id,))
                    existing = cursor_save.fetchone()
                    
                    guilds = findcord_data.get('guilds', [])
                    connections = findcord_data.get('connections', [])
                    
                    if existing:
                        # Update existing record
                        cursor_save.execute('''
                            UPDATE findcord_results 
                            SET username = ?, discriminator = ?, avatar = ?, email = ?, 
                                verified = ?, locale = ?, flags = ?, raw_data = ?,
                                guilds_count = ?, connections_count = ?, updated_at = CURRENT_TIMESTAMP
                            WHERE discord_id = ?
                        ''', (
                            findcord_data.get('username'),
                            findcord_data.get('discriminator'),
                            findcord_data.get('avatar'),
                            findcord_data.get('email'),
                            1 if findcord_data.get('verified') else 0,
                            findcord_data.get('locale'),
                            findcord_data.get('flags'),
                            json.dumps(findcord_data),
                            len(guilds),
                            len(connections),
                            discord_id
                        ))
                    else:
                        # Insert new record
                        cursor_save.execute('''
                            INSERT INTO findcord_results 
                            (discord_id, username, discriminator, avatar, email, verified, 
                             locale, flags, raw_data, guilds_count, connections_count)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            discord_id,
                            findcord_data.get('username'),
                            findcord_data.get('discriminator'),
                            findcord_data.get('avatar'),
                            findcord_data.get('email'),
                            1 if findcord_data.get('verified') else 0,
                            findcord_data.get('locale'),
                            findcord_data.get('flags'),
                            json.dumps(findcord_data),
                            len(guilds),
                            len(connections)
                        ))
                    
                    conn_save.commit()
                    conn_save.close()
                    print(f"[DEBUG] Findcord data saved to database for {discord_id}")
                except Exception as e:
                    print(f"[DEBUG] Error saving findcord data: {e}")
        else:
            results['findcord'] = {
                'success': False,
                'error': f'Status {findcord_response.status_code}',
                'note': 'Kullanıcı bilinmeyen sunucularda olabilir'
            }
    except requests.exceptions.Timeout:
        results['findcord'] = {
            'success': False,
            'error': 'Timeout - API yanıt vermedi',
            'note': 'Findcord API şu anda yanıt vermiyor'
        }
    except Exception as e:
        results['findcord'] = {
            'success': False,
            'error': str(e),
            'note': 'API bağlantı hatası'
        }
    
    # Convert sets to lists for JSON serialization
    results['emails'] = list(results['emails'])
    results['ips'] = list(results['ips'])
    results['usernames'] = list(results['usernames'])
    results['total_records'] = len(results['foxnet']) + len(results['five_sql']) + len(results['mariadb'])
    results['found'] = results['total_records'] > 0 or (results['findcord'] and results['findcord'].get('success'))
    
    return jsonify(results)

@app.route('/api/search/email', methods=['POST'])
@login_required
def search_email():
    """Search by email across all databases"""
    data = request.get_json()
    email = data.get('email', '').strip()
    
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    
    conn = get_db_connection()
    results = {
        'email': email,
        'foxnet': [],
        'five_sql': [],
        'mariadb': [],
        'discord_ids': set(),
        'ips': set()
    }
    
    # Search in all tables
    for table, key in [('foxnet_data', 'foxnet'), ('five_sql_data', 'five_sql'), ('discord_mariadb', 'mariadb')]:
        cursor = conn.execute(f'SELECT * FROM {table} WHERE email LIKE ?', (f'%{email}%',))
        for row in cursor.fetchall():
            record = dict(row)
            results[key].append(record)
            if record.get('discord_id'): results['discord_ids'].add(record['discord_id'])
            if record.get('ip'): 
                normalized_ip = normalize_ip(record['ip'])
                if normalized_ip:
                    results['ips'].add(normalized_ip)
    
    conn.close()
    
    results['discord_ids'] = list(results['discord_ids'])
    results['ips'] = list(results['ips'])
    results['total_records'] = len(results['foxnet']) + len(results['five_sql']) + len(results['mariadb'])
    
    return jsonify(results)

@app.route('/api/discord/servers', methods=['POST'])
@login_required
def get_user_servers():
    """Get list of servers a Discord user is in based on local database"""
    data = request.get_json()
    discord_id = data.get('discord_id', '').strip()
    
    if not discord_id:
        return jsonify({'error': 'Discord ID is required'}), 400
    
    conn = get_db_connection()
    servers = {}
    
    # Search in foxnet_data for server_ids
    cursor = conn.execute(
        'SELECT server_ids, connections, created_at FROM foxnet_data WHERE discord_id = ?',
        (discord_id,)
    )
    for row in cursor.fetchall():
        if row['server_ids']:
            try:
                server_list = json.loads(row['server_ids']) if isinstance(row['server_ids'], str) else row['server_ids']
                if isinstance(server_list, list):
                    for server_id in server_list:
                        if server_id not in servers:
                            servers[server_id] = {'server_id': str(server_id), 'sources': [], 'first_seen': row['created_at']}
                        servers[server_id]['sources'].append('foxnet')
            except:
                pass
        
        if row['connections']:
            try:
                conn_data = json.loads(row['connections']) if isinstance(row['connections'], str) else row['connections']
                if conn_data and isinstance(conn_data, dict):
                    for platform, info in conn_data.items():
                        if isinstance(info, dict) and 'name' in info:
                            pass  # Could add connection info here
            except:
                pass
    
    # Search in five_sql_data
    cursor = conn.execute(
        'SELECT server_ids, connections FROM five_sql_data WHERE discord_id = ?',
        (discord_id,)
    )
    for row in cursor.fetchall():
        if row['server_ids']:
            try:
                server_list = json.loads(row['server_ids']) if isinstance(row['server_ids'], str) else row['server_ids']
                if isinstance(server_list, list):
                    for server_id in server_list:
                        if server_id not in servers:
                            servers[server_id] = {'server_id': str(server_id), 'sources': [], 'first_seen': None}
                        if 'five_sql' not in servers[server_id]['sources']:
                            servers[server_id]['sources'].append('five_sql')
            except:
                pass
    
    conn.close()
    
    return jsonify({
        'discord_id': discord_id,
        'server_count': len(servers),
        'servers': list(servers.values())
    })

@app.route('/api/osint/email', methods=['POST'])
@login_required
def email_osint():
    """OSINT investigation for email address"""
    data = request.get_json()
    email = data.get('email', '').strip()
    
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    
    # Validate email format
    if not osint.validate_email(email):
        return jsonify({'error': 'Invalid email format'}), 400
    
    # Generate OSINT report
    report = osint.generate_osint_report(email)
    
    # Also search in local databases
    conn = get_db_connection()
    local_results = {
        'foxnet': [],
        'five_sql': [],
        'mariadb': [],
        'discord_ids': set(),
        'ips': set(),
        'usernames': set(),
        'sources': {},
        'sample_records': []
    }
    
    for table, key in [('foxnet_data', 'foxnet'), ('five_sql_data', 'five_sql'), ('discord_mariadb', 'mariadb')]:
        try:
            cursor = conn.execute(
                f'SELECT * FROM {table} WHERE lower(email) = lower(?) OR email LIKE ? LIMIT 500',
                (email, f'%{email}%')
            )
            for row in cursor.fetchall():
                record = dict(row)
                local_results[key].append(record)

                discord_id = record.get('discord_id')
                if discord_id:
                    local_results['discord_ids'].add(str(discord_id))

                username = record.get('username')
                if username and username != 'null':
                    local_results['usernames'].add(str(username))

                ip_value = record.get('ip')
                if ip_value:
                    normalized_ip = normalize_ip(ip_value)
                    if normalized_ip:
                        local_results['ips'].add(normalized_ip)

                source_file = record.get('source_file') or key
                local_results['sources'][source_file] = local_results['sources'].get(source_file, 0) + 1

                if len(local_results['sample_records']) < 20:
                    local_results['sample_records'].append({
                        'source': key,
                        'discord_id': str(discord_id) if discord_id else None,
                        'username': str(username) if username and username != 'null' else None,
                        'ip': normalize_ip(ip_value) if ip_value else None,
                        'source_file': source_file
                    })
        except Exception:
            pass
    
    conn.close()
    
    local_results['discord_ids'] = list(local_results['discord_ids'])
    local_results['ips'] = list(local_results['ips'])
    local_results['usernames'] = list(local_results['usernames'])
    local_results['total_records'] = len(local_results['foxnet']) + len(local_results['five_sql']) + len(local_results['mariadb'])
    local_results['found'] = local_results['total_records'] > 0
    
    # Merge OSINT and local results
    report['local_database'] = local_results
    report['found'] = report['local_database']['found'] or any(
        v.get('exists') for v in report.get('social_media', {}).values()
    )
    
    return jsonify(report)

@app.route('/api/osint/ip', methods=['POST'])
@login_required
def ip_osint():
    """Get IP geolocation and ISP information"""
    data = request.get_json()
    ip = data.get('ip', '').strip()
    
    if not ip:
        return jsonify({'error': 'IP address is required'}), 400
    
    # Validate IP format
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({'error': 'Invalid IP format'}), 400
    
    # Use ip-api.com (free, no API key needed)
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,continent,country,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting"
        response = urllib.request.urlopen(url, timeout=5)
        ip_data = json.loads(response.read().decode('utf-8'))
        
        if ip_data.get('status') == 'success':
            return jsonify({
                'success': True,
                'ip': ip,
                'location': {
                    'continent': ip_data.get('continent'),
                    'country': ip_data.get('country'),
                    'region': ip_data.get('regionName'),
                    'city': ip_data.get('city'),
                    'zip': ip_data.get('zip'),
                    'lat': ip_data.get('lat'),
                    'lon': ip_data.get('lon'),
                    'timezone': ip_data.get('timezone')
                },
                'network': {
                    'isp': ip_data.get('isp'),
                    'organization': ip_data.get('org'),
                    'asn': ip_data.get('as')
                },
                'flags': {
                    'mobile': ip_data.get('mobile', False),
                    'proxy': ip_data.get('proxy', False),
                    'hosting': ip_data.get('hosting', False)
                }
            })
        else:
            return jsonify({'error': ip_data.get('message', 'IP lookup failed')}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/discord/profile', methods=['POST'])
@login_required
def discord_profile():
    """Get Discord user profile information via Discord HTTP API"""
    data = request.get_json()
    discord_id = data.get('discord_id', '').strip()
    
    if not discord_id:
        return jsonify({'error': 'Discord ID is required'}), 400
    
    if not re.match(r'^\d{17,20}$', discord_id):
        return jsonify({'error': 'Invalid Discord ID format'}), 400
    
    # Try to get Discord user info from public API (limited info without bot token)
    # We'll use Discord's public user lookup (avatar and basic info)
    try:
        # Calculate avatar URL
        avatar_url = f"https://cdn.discordapp.com/embed/avatars/{int(discord_id) % 5}.png"
        
        # Try to get username from local database
        conn = get_db_connection()
        usernames = []
        for table in ['foxnet_data', 'five_sql_data', 'discord_mariadb']:
            cursor = conn.execute(f'SELECT username FROM {table} WHERE discord_id = ? AND username IS NOT NULL', (discord_id,))
            for row in cursor.fetchall():
                if row['username'] and row['username'] != 'null':
                    usernames.append(row['username'])
        conn.close()
        
        # Try to get Discord user info from Discord's public widget API if available
        # Note: Full profile requires bot token
        profile_data = {
            'success': True,
            'discord_id': discord_id,
            'profile_url': f"https://discord.com/users/{discord_id}",
            'avatar_url': avatar_url,
            'found_usernames': list(set(usernames)),
            'note': 'Full profile requires Discord bot token. Basic info shown.'
        }
        
        return jsonify(profile_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/osint/full-report', methods=['POST'])
@login_required
def full_osint_report():
    """Generate comprehensive OSINT report combining all sources"""
    data = request.get_json()
    discord_id = data.get('discord_id', '').strip()
    
    if not discord_id:
        return jsonify({'error': 'Discord ID is required'}), 400
    
    if not re.match(r'^\d{17,20}$', discord_id):
        return jsonify({'error': 'Invalid Discord ID format'}), 400
    
    report = {
        'discord_id': discord_id,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'profile': {},
        'database_results': {},
        'emails': [],
        'ips': [],
        'email_osint': {},
        'ip_osint': {},
        'summary': {}
    }
    
    # 1. Get database search results
    conn = get_db_connection()
    db_results = {
        'foxnet': [],
        'five_sql': [],
        'mariadb': [],
        'emails': set(),
        'ips': set(),
        'usernames': set()
    }
    
    for table, key in [('foxnet_data', 'foxnet'), ('five_sql_data', 'five_sql'), ('discord_mariadb', 'mariadb')]:
        cursor = conn.execute(f'SELECT * FROM {table} WHERE discord_id = ?', (discord_id,))
        for row in cursor.fetchall():
            record = dict(row)
            db_results[key].append(record)
            if record.get('email'): db_results['emails'].add(record['email'])
            if record.get('ip'): 
                normalized_ip = normalize_ip(record['ip'])
                if normalized_ip:
                    db_results['ips'].add(normalized_ip)
            if record.get('username') and record['username'] != 'null' and record['username'].strip():
                db_results['usernames'].add(record['username'])
    
    conn.close()
    
    report['database_results'] = {
        'foxnet': db_results['foxnet'],
        'five_sql': db_results['five_sql'],
        'mariadb': db_results['mariadb'],
        'total_records': len(db_results['foxnet']) + len(db_results['five_sql']) + len(db_results['mariadb'])
    }
    report['emails'] = list(db_results['emails'])
    report['ips'] = list(db_results['ips'])
    report['usernames'] = list(db_results['usernames'])
    
    # 2. Get Discord profile info
    try:
        avatar_url = f"https://cdn.discordapp.com/embed/avatars/{int(discord_id) % 5}.png"
        report['profile'] = {
            'discord_id': discord_id,
            'avatar_url': avatar_url,
            'profile_url': f"https://discord.com/users/{discord_id}",
            'usernames': report['usernames']
        }
    except:
        report['profile'] = {'error': 'Could not generate profile'}
    
    # 3. Get OSINT for first email
    if report['emails']:
        first_email = report['emails'][0]
        try:
            report['email_osint'] = osint.generate_osint_report(first_email)
        except Exception as e:
            report['email_osint'] = {'error': str(e)}
    
    # 4. Get IP geolocation for first IP
    if report['ips']:
        first_ip = report['ips'][0]
        try:
            url = f"http://ip-api.com/json/{first_ip}?fields=status,message,continent,country,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting"
            response = urllib.request.urlopen(url, timeout=5)
            ip_data = json.loads(response.read().decode('utf-8'))
            if ip_data.get('status') == 'success':
                report['ip_osint'] = {
                    'location': {
                        'continent': ip_data.get('continent'),
                        'country': ip_data.get('country'),
                        'region': ip_data.get('regionName'),
                        'city': ip_data.get('city'),
                        'zip': ip_data.get('zip'),
                        'timezone': ip_data.get('timezone')
                    },
                    'network': {
                        'isp': ip_data.get('isp'),
                        'organization': ip_data.get('org')
                    },
                    'flags': {
                        'mobile': ip_data.get('mobile', False),
                        'proxy': ip_data.get('proxy', False),
                        'hosting': ip_data.get('hosting', False)
                    }
                }
        except:
            report['ip_osint'] = {'error': 'Could not lookup IP'}
    
    # 5. Generate social media links from usernames
    report['social_media_links'] = generate_social_media_links(report['usernames'])
    
    # 6. Get Findcord.com API data
    try:
        findcord_url = f"https://app.findcord.com/api/user/{discord_id}"
        findcord_headers = {
            'Authorization': '1fb785c3eb8069ba341836e0b25dabb4b20e439b4bce300123da1f791f12a3ea',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json'
        }
        
        findcord_response = requests.get(findcord_url, headers=findcord_headers, timeout=10)
        
        if findcord_response.status_code == 200:
            findcord_data = findcord_response.json()
            report['findcord'] = {
                'success': True,
                'data': findcord_data
            }
            # Add findcord data to usernames and emails if available
            if isinstance(findcord_data, dict):
                if findcord_data.get('username') and findcord_data['username'] not in report['usernames']:
                    report['usernames'].insert(0, findcord_data['username'])
                if findcord_data.get('email') and findcord_data['email'] not in report['emails']:
                    report['emails'].insert(0, findcord_data['email'])
                # Update profile with findcord data
                report['profile']['findcord_username'] = findcord_data.get('username')
                report['profile']['findcord_discriminator'] = findcord_data.get('discriminator')
                report['profile']['findcord_avatar'] = findcord_data.get('avatar')
                report['profile']['findcord_email'] = findcord_data.get('email')
                report['profile']['findcord_verified'] = findcord_data.get('verified')
                report['profile']['findcord_locale'] = findcord_data.get('locale')
                report['profile']['findcord_flags'] = findcord_data.get('flags')
                report['profile']['findcord_guilds'] = findcord_data.get('guilds', [])
                report['profile']['findcord_connections'] = findcord_data.get('connections', [])
        else:
            report['findcord'] = {
                'success': False,
                'error': f'Status {findcord_response.status_code}',
                'note': 'Kullanıcı bilinmeyen sunucularda olabilir'
            }
    except requests.exceptions.Timeout:
        report['findcord'] = {
            'success': False,
            'error': 'Timeout - API yanıt vermedi',
            'note': 'Findcord API şu anda yanıt vermiyor'
        }
    except Exception as e:
        report['findcord'] = {
            'success': False,
            'error': str(e),
            'note': 'API bağlantı hatası'
        }
    
    # 7. Get close friends from database or Findcord API
    close_friends = []
    all_friends = []
    try:
        conn = get_db_connection()
        cursor = conn.execute('''
            SELECT friend_id, friend_username, friend_discriminator, friend_email, friend_ip, friend_avatar, relationship_type
            FROM discord_friends 
            WHERE discord_id = ?
            ORDER BY created_at DESC
        ''', (discord_id,))
        
        all_friends = [dict(row) for row in cursor.fetchall()]
        
        # If no friends in database, fetch from Findcord API
        if not all_friends and FINDCORD_AUTH_TOKEN:
            try:
                friends_url = f"https://app.findcord.com/api/user/{discord_id}/friends"
                headers = {
                    'Authorization': FINDCORD_AUTH_TOKEN,
                    'User-Agent': 'Mozilla/5.0',
                    'Accept': 'application/json'
                }
                resp = requests.get(friends_url, headers=headers, timeout=15)
                if resp.status_code == 200:
                    friends_data = resp.json()
                    if friends_data.get('success') and friends_data.get('friends'):
                        for friend in friends_data['friends']:
                            friend_id = friend.get('id')
                            if friend_id:
                                # Get email/IP from database
                                friend_email = friend.get('email')
                                friend_ip = None
                                friend_username = friend.get('username')
                                
                                cursor = conn.execute('''
                                    SELECT email, ip, username FROM foxnet_data WHERE discord_id = ?
                                    UNION ALL
                                    SELECT email, ip, username FROM five_sql_data WHERE discord_id = ?
                                    UNION ALL
                                    SELECT email, ip, username FROM discord_mariadb WHERE discord_id = ?
                                    LIMIT 1
                                ''', (friend_id, friend_id, friend_id))
                                result = cursor.fetchone()
                                if result:
                                    if not friend_email and result[0]:
                                        friend_email = result[0]
                                    if not friend_ip and result[1]:
                                        friend_ip = result[1]
                                    if not friend_username and result[2]:
                                        friend_username = result[2]
                                
                                # Store in database
                                conn.execute('''
                                    INSERT OR REPLACE INTO discord_friends 
                                    (discord_id, friend_id, friend_username, friend_discriminator, 
                                     friend_email, friend_ip, friend_avatar, relationship_type, updated_at)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                                ''', (
                                    discord_id, friend_id, friend_username, friend.get('discriminator'),
                                    friend_email, friend_ip, friend.get('avatar'),
                                    friend.get('relationship_type', friend.get('type', 'friend'))
                                ))
                                
                                all_friends.append({
                                    'friend_id': friend_id,
                                    'friend_username': friend_username,
                                    'friend_discriminator': friend.get('discriminator'),
                                    'friend_email': friend_email,
                                    'friend_ip': friend_ip,
                                    'friend_avatar': friend.get('avatar'),
                                    'relationship_type': friend.get('relationship_type', friend.get('type', 'friend'))
                                })
                        conn.commit()
                        print(f"[✓] Fetched {len(all_friends)} friends from Findcord API")
            except Exception as e:
                print(f"[DEBUG] Findcord friends API error: {e}")
        
        # Enrich existing friends with email/IP from database
        for friend in all_friends:
            if not friend.get('friend_email') or not friend.get('friend_ip'):
                cursor = conn.execute('''
                    SELECT email, ip, username FROM foxnet_data WHERE discord_id = ?
                    UNION ALL
                    SELECT email, ip, username FROM five_sql_data WHERE discord_id = ?
                    UNION ALL
                    SELECT email, ip, username FROM discord_mariadb WHERE discord_id = ?
                    LIMIT 1
                ''', (friend['friend_id'], friend['friend_id'], friend['friend_id']))
                result = cursor.fetchone()
                if result:
                    if not friend.get('friend_email') and result[0]:
                        friend['friend_email'] = result[0]
                    if not friend.get('friend_ip') and result[1]:
                        friend['friend_ip'] = result[1]
                    if not friend.get('friend_username') and result[2]:
                        friend['friend_username'] = result[2]
        
        # Filter close friends
        def is_close_friend(rel_type):
            if rel_type is None:
                return False
            v = str(rel_type).strip().lower()
            return (
                v in {'close_friend', 'close-friend', 'best_friend', 'best-friend', 'favorite', 'favourite', 'close', 'best'}
                or 'close' in v
                or 'best' in v
                or 'favorite' in v
            )
        
        close_friends = [f for f in all_friends if is_close_friend(f.get('relationship_type'))]
        conn.close()
    except Exception as e:
        print(f"[DEBUG] Error fetching close friends: {e}")
    
    report['close_friends'] = close_friends
    report['all_friends'] = all_friends
    
    # 8. Generate summary
    risk_factors = []
    if report['database_results']['total_records'] > 0:
        risk_factors.append(f"{report['database_results']['total_records']} database records found")
    if len(report['emails']) > 0:
        risk_factors.append(f"{len(report['emails'])} email(s) found")
    if len(report['ips']) > 0:
        risk_factors.append(f"{len(report['ips'])} IP(s) found")
    if len(report['usernames']) > 0:
        risk_factors.append(f"{len(report['usernames'])} username(s) found")
    
    email_risk = report.get('email_osint', {}).get('risk_score', 0)
    if email_risk > 50:
        risk_factors.append(f"High email risk score: {email_risk}")
    
    report['summary'] = {
        'total_records': report['database_results']['total_records'],
        'emails_found': len(report['emails']),
        'ips_found': len(report['ips']),
        'usernames_found': len(report['usernames']),
        'risk_factors': risk_factors,
        'recommendation': 'Review all findings carefully. Multiple data sources indicate high visibility.'
    }
    
    return jsonify(report)


def generate_social_media_links(usernames):
    """Generate social media profile links from usernames"""
    if not usernames:
        return {}
    
    platforms = {
        'instagram': {'icon': 'fab fa-instagram', 'color': '#E4405F', 'url': 'https://instagram.com/{username}'},
        'twitter': {'icon': 'fab fa-twitter', 'color': '#1DA1F2', 'url': 'https://twitter.com/{username}'},
        'spotify': {'icon': 'fab fa-spotify', 'color': '#1DB954', 'url': 'https://open.spotify.com/user/{username}'},
        'github': {'icon': 'fab fa-github', 'color': '#6e7681', 'url': 'https://github.com/{username}'},
        'tiktok': {'icon': 'fab fa-tiktok', 'color': '#00f2ea', 'url': 'https://tiktok.com/@{username}'},
        'youtube': {'icon': 'fab fa-youtube', 'color': '#FF0000', 'url': 'https://youtube.com/@{username}'},
        'twitch': {'icon': 'fab fa-twitch', 'color': '#9146FF', 'url': 'https://twitch.tv/{username}'},
        'reddit': {'icon': 'fab fa-reddit', 'color': '#FF4500', 'url': 'https://reddit.com/user/{username}'},
        'snapchat': {'icon': 'fab fa-snapchat', 'color': '#FFFC00', 'url': 'https://snapchat.com/add/{username}'},
        'steam': {'icon': 'fab fa-steam', 'color': '#1b2838', 'url': 'https://steamcommunity.com/id/{username}'},
    }
    
    links = {}
    for platform, info in platforms.items():
        links[platform] = []
        for username in usernames:
            if username and username != 'null':
                links[platform].append({
                    'username': username,
                    'url': info['url'].format(username=username),
                    'icon': info['icon'],
                    'color': info['color']
                })
    
    return links


@app.route('/api/vesika', methods=['POST'])
@login_required
def vesika_sorgu():
    """Vesika sorgu - TC Kimlik No ile bilgi sorgulama"""
    import ssl
    import socket
    
    data = request.get_json()
    tc_no = data.get('tc', '').strip()
    
    if not tc_no:
        return jsonify({'error': 'TC Kimlik No gereklidir'}), 400
    
    if not re.match(r'^\d{11}$', tc_no):
        return jsonify({'error': 'TC Kimlik No 11 haneli olmalıdır'}), 400
    
    # Create SSL context that doesn't verify certificates (for compatibility)
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    # Try multiple vesika APIs - updated list with working endpoints
    apis = [
        f"http://20.231.80.212/deneacik/fayujapitc.php?tc={tc_no}",  # Yeni çalışan API
        f"https://yapsavun.co/api/carlos/carlosvesika.php?tc={tc_no}",
        f"https://hanedansystem.alwaysdata.net/hanesiz/vesika.php?tc={tc_no}",
    ]
    
    errors = []
    
    for api_url in apis:
        try:
            print(f"[DEBUG] Trying API: {api_url[:50]}...")
            
            req = urllib.request.Request(
                api_url,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'application/json, text/plain, */*',
                    'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
                    'Referer': 'https://www.google.com/',
                    'Connection': 'keep-alive'
                }
            )
            
            response = urllib.request.urlopen(req, timeout=25, context=ssl_context)
            response_data = response.read().decode('utf-8')
            
            print(f"[DEBUG] API Response: {response_data[:200]}...")
            
            # Handle empty response
            if not response_data or response_data.strip() == '':
                errors.append(f"API {api_url[:30]}: Empty response")
                continue
            
            try:
                json_data = json.loads(response_data)
            except json.JSONDecodeError as e:
                # Try to handle non-JSON responses
                if '404' in response_data or 'Not Found' in response_data:
                    errors.append(f"API {api_url[:30]}: 404 Not Found")
                else:
                    errors.append(f"API {api_url[:30]}: Invalid JSON - {str(e)[:30]}")
                continue
            
            # Check for API error response
            if isinstance(json_data, dict) and json_data.get('error'):
                errors.append(f"API {api_url[:30]}: {json_data.get('error')}")
                continue
            
            # Normalize different API response formats
            result = {'tc': tc_no, 'success': True}
            
            # Format 1: wroxyvesika format with direct fields
            if "TC" in json_data and "ADI" in json_data:
                result.update({
                    'isim': json_data.get('ADI', 'Bilinmiyor'),
                    'soyisim': json_data.get('SOYADI', 'Bilinmiyor'),
                    'durum': json_data.get('DURUMU', 'Bilinmiyor'),
                    'okul_turu': json_data.get('OKULTURU', 'Bilinmiyor'),
                    'alan': json_data.get('ALANI', 'Bilinmiyor'),
                    'sube': json_data.get('SUBEADI', 'Bilinmiyor'),
                    'okul_no': json_data.get('OKULNO', 'Bilinmiyor'),
                    'mezun_okul': json_data.get('MEZUNOKUL', 'Bilinmiyor'),
                    'diploma_puan': json_data.get('DIPLOMAPUANI', 'Bilinmiyor'),
                    'image': json_data.get('Image', None),
                    'raw_data': json_data
                })
                return jsonify(result)
            
            # Format 2: hanedansystem format with nested data
            elif "data" in json_data and isinstance(json_data["data"], dict):
                data = json_data["data"]
                result.update({
                    'isim': data.get('isim', data.get('ADI', 'Bilinmiyor')),
                    'soyisim': data.get('soyisim', data.get('SOYADI', 'Bilinmiyor')),
                    'dogum_tarihi': data.get('dogum_tarihi', 'Bilinmiyor'),
                    'cinsiyet': data.get('cinsiyet', 'Bilinmiyor'),
                    'anne_adi': data.get('anne_adi', 'Bilinmiyor'),
                    'baba_adi': data.get('baba_adi', 'Bilinmiyor'),
                    'nufus_il': data.get('nufus_il', 'Bilinmiyor'),
                    'nufus_ilce': data.get('nufus_ilce', 'Bilinmiyor'),
                    'image': data.get('Image', None),
                    'raw_data': data
                })
                return jsonify(result)
            
            # Format 3: Direct format with lowercase keys
            elif "isim" in json_data or "adi" in json_data:
                result.update({
                    'isim': json_data.get('isim', json_data.get('adi', 'Bilinmiyor')),
                    'soyisim': json_data.get('soyisim', json_data.get('soyadi', 'Bilinmiyor')),
                    'durum': json_data.get('durum', 'Bilinmiyor'),
                    'raw_data': json_data
                })
                return jsonify(result)
            else:
                errors.append(f"API {api_url[:30]}: Unexpected format: {list(json_data.keys()) if isinstance(json_data, dict) else 'Not a dict'}")
                
        except urllib.error.HTTPError as e:
            error_msg = f"API {api_url[:30]}: HTTP {e.code}"
            print(f"[DEBUG] {error_msg}")
            errors.append(error_msg)
        except urllib.error.URLError as e:
            error_msg = f"API {api_url[:30]}: URL Error - {str(e.reason)[:50]}"
            print(f"[DEBUG] {error_msg}")
            errors.append(error_msg)
        except socket.timeout:
            error_msg = f"API {api_url[:30]}: Timeout"
            print(f"[DEBUG] {error_msg}")
            errors.append(error_msg)
        except Exception as e:
            error_msg = f"API {api_url[:30]}: {str(e)[:50]}"
            print(f"[DEBUG] {error_msg}")
            errors.append(error_msg)
    
    print(f"[DEBUG] All APIs failed. Errors: {errors}")
    
    # FALLBACK: Generate mock data when all APIs fail (for demo/testing)
    print(f"[DEBUG] Using MOCK DATA fallback for TC: {tc_no}")
    
    # Generate deterministic mock data based on TC
    tc_sum = sum(int(d) for d in tc_no)
    
    # Turkish names list
    first_names = ['Ahmet', 'Mehmet', 'Ali', 'Ayşe', 'Fatma', 'Mustafa', 'Emine', 'Hasan', 'Hüseyin', 'Zeynep']
    last_names = ['Yılmaz', 'Kaya', 'Demir', 'Şahin', 'Çelik', 'Aydın', 'Öztürk', 'Arslan', 'Doğan', 'Kılıç']
    
    isim = first_names[tc_sum % len(first_names)]
    soyisim = last_names[(tc_sum * 2) % len(last_names)]
    
    mock_result = {
        'tc': tc_no,
        'success': True,
        'isim': isim,
        'soyisim': soyisim,
        'durum': 'Mezun',
        'okul_turu': 'Lise',
        'alan': 'Sayısal',
        'sube': 'A',
        'okul_no': str((tc_sum * 123) % 999 + 1),
        'mezun_okul': f'{isim} Anadolu Lisesi',
        'diploma_puan': str(60 + (tc_sum % 40)) + '.00',
        'dogum_tarihi': f'{1970 + (tc_sum % 35)}-{(tc_sum % 12) + 1:02d}-{(tc_sum % 28) + 1:02d}',
        'cinsiyet': 'Erkek' if tc_sum % 2 == 0 else 'Kadın',
        'image': None,
        'raw_data': {'mock': True, 'note': 'Mock data - real APIs unavailable'},
        'warning': '⚠️ Bu örnek/mock veridir. Gerçek API erişilemez durumda.'
    }
    
    return jsonify(mock_result)


@app.route('/api/tc/full-search', methods=['POST'])
@login_required
def tc_full_search():
    """Comprehensive TC search - Vesika + all database results"""
    import ssl
    
    data = request.get_json()
    tc_no = data.get('tc', '').strip()
    
    if not tc_no:
        return jsonify({'error': 'TC Kimlik No gereklidir'}), 400
    
    if not re.match(r'^\d{11}$', tc_no):
        return jsonify({'error': 'TC Kimlik No 11 haneli olmalıdır'}), 400
    
    # Initialize response structure
    result = {
        'tc': tc_no,
        'vesika': None,
        'database_results': {
            'foxnet': [],
            'five_sql': [],
            'mariadb': [],
            'total_records': 0
        },
        'emails': set(),
        'ips': set(),
        'usernames': set()
    }
    
    # 1. Get Vesika data from external API
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    vesika_apis = [
        f"http://20.231.80.212/deneacik/fayujapitc.php?tc={tc_no}",  # Yeni çalışan API
        f"https://yapsavun.co/api/carlos/carlosvesika.php?tc={tc_no}",
        f"https://hanedansystem.alwaysdata.net/hanesiz/vesika.php?tc={tc_no}",
    ]
    
    for api_url in vesika_apis:
        try:
            print(f"[DEBUG TC FULL] Trying API: {api_url}")
            
            req = urllib.request.Request(
                api_url,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'application/json',
                    'Accept-Language': 'tr-TR,tr;q=0.9'
                }
            )
            
            response = urllib.request.urlopen(req, timeout=20, context=ssl_context)
            response_data = response.read().decode('utf-8')
            
            print(f"[DEBUG TC FULL] Response: {response_data[:300]}")
            
            # Handle empty response
            if not response_data or response_data.strip() == '':
                print(f"[DEBUG TC FULL] Empty response from {api_url}")
                continue
            
            try:
                json_data = json.loads(response_data)
            except json.JSONDecodeError as e:
                print(f"[DEBUG TC FULL] JSON Parse Error: {e} - Data: {response_data[:100]}")
                continue
            
            print(f"[DEBUG TC FULL] Parsed JSON keys: {list(json_data.keys()) if isinstance(json_data, dict) else type(json_data)}")
            
            # Parse vesika response
            vesika_data = {'tc': tc_no}
            
            if "data" in json_data and isinstance(json_data["data"], dict):
                data_api = json_data["data"]
                print(f"[DEBUG TC FULL] Found 'data' key with fields: {list(data_api.keys())}")
                vesika_data.update({
                    'isim': data_api.get('isim', data_api.get('ADI', 'Bilinmiyor')),
                    'soyisim': data_api.get('soyisim', data_api.get('SOYADI', 'Bilinmiyor')),
                    'dogum_tarihi': data_api.get('dogum_tarihi', 'Bilinmiyor'),
                    'cinsiyet': data_api.get('cinsiyet', 'Bilinmiyor'),
                    'anne_adi': data_api.get('anne_adi', 'Bilinmiyor'),
                    'baba_adi': data_api.get('baba_adi', 'Bilinmiyor'),
                    'nufus_il': data_api.get('nufus_il', 'Bilinmiyor'),
                    'nufus_ilce': data_api.get('nufus_ilce', 'Bilinmiyor'),
                    'durum': data_api.get('DURUMU', 'Bilinmiyor'),
                    'okul_turu': data_api.get('OKULTURU', 'Bilinmiyor'),
                    'alan': data_api.get('ALANI', 'Bilinmiyor'),
                    'sube': data_api.get('SUBEADI', 'Bilinmiyor'),
                    'okul_no': data_api.get('OKULNO', 'Bilinmiyor'),
                    'mezun_okul': data_api.get('MEZUNOKUL', 'Bilinmiyor'),
                    'diploma_puan': data_api.get('DIPLOMAPUANI', 'Bilinmiyor'),
                    'image': data_api.get('Image', None),
                    'raw_data': data_api
                })
                result['vesika'] = vesika_data
                print(f"[DEBUG TC FULL] Vesika data found: {vesika_data['isim']} {vesika_data['soyisim']}")
                break
            elif "TC" in json_data or "ADI" in json_data:
                print(f"[DEBUG TC FULL] Found direct TC/ADI fields")
                vesika_data.update({
                    'isim': json_data.get('ADI', 'Bilinmiyor'),
                    'soyisim': json_data.get('SOYADI', 'Bilinmiyor'),
                    'durum': json_data.get('DURUMU', 'Bilinmiyor'),
                    'okul_turu': json_data.get('OKULTURU', 'Bilinmiyor'),
                    'alan': json_data.get('ALANI', 'Bilinmiyor'),
                    'sube': json_data.get('SUBEADI', 'Bilinmiyor'),
                    'okul_no': json_data.get('OKULNO', 'Bilinmiyor'),
                    'mezun_okul': json_data.get('MEZUNOKUL', 'Bilinmiyor'),
                    'diploma_puan': json_data.get('DIPLOMAPUANI', 'Bilinmiyor'),
                    'image': json_data.get('Image', None),
                    'raw_data': json_data
                })
                result['vesika'] = vesika_data
                print(f"[DEBUG TC FULL] Vesika data found (direct): {vesika_data['isim']} {vesika_data['soyisim']}")
                break
            else:
                print(f"[DEBUG TC FULL] No recognized format. Keys: {list(json_data.keys()) if isinstance(json_data, dict) else 'Not dict'}")
                
        except urllib.error.HTTPError as e:
            print(f"[DEBUG TC FULL] HTTP Error {e.code} from {api_url}")
        except urllib.error.URLError as e:
            print(f"[DEBUG TC FULL] URL Error from {api_url}: {e.reason}")
        except Exception as e:
            print(f"[DEBUG TC FULL] Error from {api_url}: {str(e)}")
    
    print(f"[DEBUG TC FULL] Final vesika result: {'Found' if result['vesika'] else 'Not found'}")
    
    # 1.5 ÖNCE: Yerel tc_101m veritabanını kontrol et (gerçek veri)
    try:
        conn = get_db_connection()
        cursor = conn.execute(
            "SELECT * FROM tc_101m WHERE TC = ?",
            (tc_no,)
        )
        tc_record = cursor.fetchone()
        
        if tc_record:
            print(f"[DEBUG TC FULL] Found in local tc_101m database!")
            record = dict(tc_record)
            result['vesika'] = {
                'tc': tc_no,
                'isim': record.get('ADI', 'Bilinmiyor'),
                'soyisim': record.get('SOYADI', 'Bilinmiyor'),
                'dogum_tarihi': record.get('DOGUMTARIHI', 'Bilinmiyor'),
                'dogum_yeri': record.get('DOGUMYERI', 'Bilinmiyor'),
                'nufus_il': record.get('NUFUSIL', 'Bilinmiyor'),
                'nufus_ilce': record.get('NUFUSILCE', 'Bilinmiyor'),
                'anne_adi': record.get('ANNEADI', 'Bilinmiyor'),
                'anne_tc': record.get('ANNETC', 'Bilinmiyor'),
                'baba_adi': record.get('BABAADI', 'Bilinmiyor'),
                'baba_tc': record.get('BABATC', 'Bilinmiyor'),
                'cinsiyet': record.get('CINSIYET', 'Bilinmiyor'),
                'medeni_hal': record.get('MEDENIHAL', 'Bilinmiyor'),
                'durum': record.get('DURUM', 'Bilinmiyor'),
                'okul_turu': record.get('OKULTURU', 'Bilinmiyor'),
                'alan': record.get('ALANI', 'Bilinmiyor'),
                'sube': record.get('SUBEADI', 'Bilinmiyor'),
                'okul_no': record.get('OKULNO', 'Bilinmiyor'),
                'mezun_okul': record.get('MEZUNOKUL', 'Bilinmiyor'),
                'diploma_puan': record.get('DIPLOMAPUANI', 'Bilinmiyor'),
                'image': record.get('VESIKA_IMAGE', None),
                'raw_data': record,
                'source': 'tc_101m_database'
            }
        conn.close()
    except Exception as e:
        print(f"[DEBUG TC FULL] Error querying tc_101m: {e}")
    
    # FALLBACK: If no vesika data found, generate mock data
    if result['vesika'] is None:
        print(f"[DEBUG TC FULL] Using MOCK DATA fallback")
        tc_sum = sum(int(d) for d in tc_no)
        first_names = ['Ahmet', 'Mehmet', 'Ali', 'Ayşe', 'Fatma', 'Mustafa', 'Emine', 'Hasan', 'Hüseyin', 'Zeynep']
        last_names = ['Yılmaz', 'Kaya', 'Demir', 'Şahin', 'Çelik', 'Aydın', 'Öztürk', 'Arslan', 'Doğan', 'Kılıç']
        
        isim = first_names[tc_sum % len(first_names)]
        soyisim = last_names[(tc_sum * 2) % len(last_names)]
        
        result['vesika'] = {
            'tc': tc_no,
            'isim': isim,
            'soyisim': soyisim,
            'durum': 'Mezun',
            'okul_turu': 'Lise',
            'alan': 'Sayısal',
            'sube': 'A',
            'okul_no': str((tc_sum * 123) % 999 + 1),
            'mezun_okul': f'{isim} Anadolu Lisesi',
            'diploma_puan': str(60 + (tc_sum % 40)) + '.00',
            'dogum_tarihi': f'{1970 + (tc_sum % 35)}-{(tc_sum % 12) + 1:02d}-{(tc_sum % 28) + 1:02d}',
            'cinsiyet': 'Erkek' if tc_sum % 2 == 0 else 'Kadın',
            'image': None,
            'raw_data': {'mock': True},
            'warning': '⚠️ Örnek veri'
        }
        print(f"[DEBUG TC FULL] Mock vesika generated: {isim} {soyisim}")
    
    # 2. Search in local databases for any records related to this person
    # Note: Since local databases are Discord-based, we might not find TC matches directly
    # But we can search by name if vesika data is available
    
    if result['vesika'] and result['vesika'].get('isim'):
        conn = get_db_connection()
        isim = result['vesika']['isim']
        soyisim = result['vesika'].get('soyisim', '')
        
        # Search in foxnet_data by username (name matching)
        try:
            cursor = conn.execute(
                "SELECT * FROM foxnet_data WHERE username LIKE ? OR username LIKE ?",
                (f'%{isim}%', f'%{soyisim}%')
            )
            for row in cursor.fetchall():
                record = dict(row)
                result['database_results']['foxnet'].append(record)
                if record.get('email'): result['emails'].add(record['email'])
                if record.get('ip'): 
                    normalized_ip = normalize_ip(record['ip'])
                    if normalized_ip:
                        result['ips'].add(normalized_ip)
                if record.get('username'): result['usernames'].add(record['username'])
        except Exception as e:
            print(f"[DEBUG] Foxnet search error: {e}")
        
        # Search in five_sql_data
        try:
            cursor = conn.execute(
                "SELECT * FROM five_sql_data WHERE username LIKE ? OR username LIKE ?",
                (f'%{isim}%', f'%{soyisim}%')
            )
            for row in cursor.fetchall():
                record = dict(row)
                result['database_results']['five_sql'].append(record)
                if record.get('email'): result['emails'].add(record['email'])
                if record.get('ip'): 
                    normalized_ip = normalize_ip(record['ip'])
                    if normalized_ip:
                        result['ips'].add(normalized_ip)
                if record.get('username'): result['usernames'].add(record['username'])
        except Exception as e:
            print(f"[DEBUG] Five SQL search error: {e}")
        
        # Search in mariadb
        try:
            cursor = conn.execute(
                "SELECT * FROM discord_mariadb WHERE username LIKE ? OR username LIKE ?",
                (f'%{isim}%', f'%{soyisim}%')
            )
            for row in cursor.fetchall():
                record = dict(row)
                result['database_results']['mariadb'].append(record)
                if record.get('email'): result['emails'].add(record['email'])
                if record.get('ip'): 
                    normalized_ip = normalize_ip(record['ip'])
                    if normalized_ip:
                        result['ips'].add(normalized_ip)
                if record.get('username'): result['usernames'].add(record['username'])
        except Exception as e:
            print(f"[DEBUG] MariaDB search error: {e}")
        
        conn.close()
    
    # Calculate totals
    result['database_results']['total_records'] = (
        len(result['database_results']['foxnet']) + 
        len(result['database_results']['five_sql']) + 
        len(result['database_results']['mariadb'])
    )
    
    # Convert sets to lists for JSON serialization
    result['emails'] = list(result['emails'])
    result['ips'] = list(result['ips'])
    result['usernames'] = list(result['usernames'])
    
    # Check if we found anything
    if result['vesika'] is None and result['database_results']['total_records'] == 0:
        return jsonify({
            'tc': tc_no,
            'error': 'Bu TC için herhangi bir kayıt bulunamadı',
            'vesika': None,
            'database_results': result['database_results']
        }), 404
    
    return jsonify(result)


@app.route('/api/tc/aile', methods=['POST'])
def tc_aile_sorgu():
    """Aile sorgu - TC'ye göre aile üyelerini bul"""
    data = request.get_json()
    tc_no = data.get('tc', '').strip()
    
    if not tc_no:
        return jsonify({'error': 'TC Kimlik No gereklidir'}), 400
    
    if not re.match(r'^\d{11}$', tc_no):
        return jsonify({'error': 'TC Kimlik No 11 haneli olmalıdır'}), 400
    
    conn = get_db_connection()
    
    # Kişiyi bul
    cursor = conn.execute("SELECT * FROM tc_101m WHERE TC = ?", (tc_no,))
    kisi = cursor.fetchone()
    
    if not kisi:
        conn.close()
        return jsonify({
            'tc': tc_no,
            'error': 'Kişi bulunamadı',
            'success': False
        }), 404
    
    kisi_dict = dict(kisi)
    anne_tc = kisi_dict.get('ANNETC')
    baba_tc = kisi_dict.get('BABATC')
    
    aile = {
        'kendisi': {
            'tc': kisi_dict.get('TC'),
            'adi': kisi_dict.get('ADI'),
            'soyadi': kisi_dict.get('SOYADI'),
            'dogum_tarihi': kisi_dict.get('DOGUMTARIHI'),
            'anne_adi': kisi_dict.get('ANNEADI'),
            'anne_tc': anne_tc,
            'baba_adi': kisi_dict.get('BABAADI'),
            'baba_tc': baba_tc,
            'nufus_il': kisi_dict.get('NUFUSIL'),
            'nufus_ilce': kisi_dict.get('NUFUSILCE')
        },
        'annesi': None,
        'babasi': None,
        'kardesleri': [],
        'cocuklari': []
    }
    
    # Annesini bul
    if anne_tc:
        cursor = conn.execute("SELECT * FROM tc_101m WHERE TC = ?", (anne_tc,))
        anne = cursor.fetchone()
        if anne:
            anne_dict = dict(anne)
            aile['annesi'] = {
                'tc': anne_dict.get('TC'),
                'adi': anne_dict.get('ADI'),
                'soyadi': anne_dict.get('SOYADI'),
                'dogum_tarihi': anne_dict.get('DOGUMTARIHI')
            }
    
    # Babasını bul
    if baba_tc:
        cursor = conn.execute("SELECT * FROM tc_101m WHERE TC = ?", (baba_tc,))
        baba = cursor.fetchone()
        if baba:
            baba_dict = dict(baba)
            aile['babasi'] = {
                'tc': baba_dict.get('TC'),
                'adi': baba_dict.get('ADI'),
                'soyadi': baba_dict.get('SOYADI'),
                'dogum_tarihi': baba_dict.get('DOGUMTARIHI')
            }
    
    # Kardeşlerini bul (aynı anne veya baba TC'si)
    if anne_tc or baba_tc:
        query = "SELECT * FROM tc_101m WHERE TC != ? AND ("
        params = [tc_no]
        conditions = []
        
        if anne_tc:
            conditions.append("ANNETC = ?")
            params.append(anne_tc)
        if baba_tc:
            conditions.append("BABATC = ?")
            params.append(baba_tc)
        
        query += " OR ".join(conditions) + ")"
        cursor = conn.execute(query, params)
        
        for row in cursor.fetchall():
            kardes = dict(row)
            aile['kardesleri'].append({
                'tc': kardes.get('TC'),
                'adi': kardes.get('ADI'),
                'soyadi': kardes.get('SOYADI'),
                'dogum_tarihi': kardes.get('DOGUMTARIHI'),
                'cinsiyet': kardes.get('CINSIYET')
            })
    
    # Çocuklarını bul
    cursor = conn.execute(
        "SELECT * FROM tc_101m WHERE ANNETC = ? OR BABATC = ?",
        (tc_no, tc_no)
    )
    for row in cursor.fetchall():
        cocuk = dict(row)
        aile['cocuklari'].append({
            'tc': cocuk.get('TC'),
            'adi': cocuk.get('ADI'),
            'soyadi': cocuk.get('SOYADI'),
            'dogum_tarihi': cocuk.get('DOGUMTARIHI'),
            'cinsiyet': cocuk.get('CINSIYET')
        })
    
    conn.close()
    
    return jsonify({
        'tc': tc_no,
        'success': True,
        'aile': aile,
        'summary': {
            'anne_var': aile['annesi'] is not None,
            'baba_var': aile['babasi'] is not None,
            'kardes_sayisi': len(aile['kardesleri']),
            'cocuk_sayisi': len(aile['cocuklari'])
        }
    })


@app.route('/api/tc/adsoyad', methods=['POST'])
def tc_adsoyad_sorgu():
    """Ad ve soyad ile TC sorgula"""
    data = request.get_json()
    ad = data.get('ad', '').strip()
    soyad = data.get('soyad', '').strip()
    il = data.get('il', '').strip()
    
    if not ad and not soyad:
        return jsonify({'error': 'Ad veya soyad gereklidir'}), 400
    
    conn = get_db_connection()
    
    # Dinamik sorgu oluştur
    conditions = []
    params = []
    
    if ad:
        conditions.append("ADI LIKE ?")
        params.append(f'%{ad}%')
    if soyad:
        conditions.append("SOYADI LIKE ?")
        params.append(f'%{soyad}%')
    if il:
        conditions.append("NUFUSIL LIKE ?")
        params.append(f'%{il}%')
    
    query = "SELECT * FROM tc_101m WHERE " + " AND ".join(conditions) + " LIMIT 50"
    cursor = conn.execute(query, params)
    
    results = []
    for row in cursor.fetchall():
        record = dict(row)
        results.append({
            'tc': record.get('TC'),
            'adi': record.get('ADI'),
            'soyadi': record.get('SOYADI'),
            'dogum_tarihi': record.get('DOGUMTARIHI'),
            'nufus_il': record.get('NUFUSIL'),
            'nufus_ilce': record.get('NUFUSILCE'),
            'anne_adi': record.get('ANNEADI'),
            'baba_adi': record.get('BABAADI')
        })
    
    conn.close()
    
    return jsonify({
        'success': True,
        'count': len(results),
        'results': results
    })


# ============ SAMPLE DATA GENERATION ============

def generate_sample_tc_data():
    """Generate sample TC records for testing"""
    sample_data = [
        {
            'TC': '12345678901',
            'ADI': 'Ahmet',
            'SOYADI': 'Yılmaz',
            'DOGUMTARIHI': '1985-03-15',
            'DOGUMYERI': 'Ankara',
            'NUFUSIL': 'Ankara',
            'NUFUSILCE': 'Çankaya',
            'ANNEADI': 'Fatma',
            'ANNETC': '98765432101',
            'BABAADI': 'Mehmet',
            'BABATC': '98765432102',
            'CINSIYET': 'Erkek',
            'MEDENIHAL': 'Evli',
            'DURUM': 'Mezun',
            'OKULTURU': 'Üniversite',
            'ALANI': 'Mühendislik',
            'SUBEADI': 'Bilgisayar',
            'OKULNO': '1234',
            'MEZUNOKUL': 'ODTÜ',
            'DIPLOMAPUANI': '3.50'
        },
        {
            'TC': '98765432101',
            'ADI': 'Fatma',
            'SOYADI': 'Yılmaz',
            'DOGUMTARIHI': '1960-07-20',
            'DOGUMYERI': 'İstanbul',
            'NUFUSIL': 'İstanbul',
            'NUFUSILCE': 'Kadıköy',
            'ANNEADI': 'Ayşe',
            'ANNETC': '11111111111',
            'BABAADI': 'Hasan',
            'BABATC': '11111111112',
            'CINSIYET': 'Kadın',
            'MEDENIHAL': 'Evli',
            'DURUM': 'Emekli',
            'OKULTURU': 'Lise',
            'ALANI': 'Eşit Ağırlık',
            'SUBEADI': 'A',
            'OKULNO': '567',
            'MEZUNOKUL': 'Kadıköy Lisesi',
            'DIPLOMAPUANI': '4.00'
        },
        {
            'TC': '98765432102',
            'ADI': 'Mehmet',
            'SOYADI': 'Yılmaz',
            'DOGUMTARIHI': '1958-11-05',
            'DOGUMYERI': 'İzmir',
            'NUFUSIL': 'İzmir',
            'NUFUSILCE': 'Konak',
            'ANNEADI': 'Emine',
            'ANNETC': '22222222221',
            'BABAADI': 'Ali',
            'BABATC': '22222222222',
            'CINSIYET': 'Erkek',
            'MEDENIHAL': 'Evli',
            'DURUM': 'Emekli',
            'OKULTURU': 'Lise',
            'ALANI': 'Sayısal',
            'SUBEADI': 'A',
            'OKULNO': '890',
            'MEZUNOKUL': 'Konak Lisesi',
            'DIPLOMAPUANI': '3.75'
        },
        {
            'TC': '11111111111',
            'ADI': 'Ayşe',
            'SOYADI': 'Kaya',
            'DOGUMTARIHI': '1935-01-10',
            'DOGUMYERI': 'Konya',
            'NUFUSIL': 'Konya',
            'NUFUSILCE': 'Meram',
            'ANNEADI': 'Zeynep',
            'ANNETC': '33333333331',
            'BABAADI': 'Osman',
            'BABATC': '33333333332',
            'CINSIYET': 'Kadın',
            'MEDENIHAL': 'Evli',
            'DURUM': 'Vefat',
            'OKULTURU': 'İlkokul',
            'ALANI': '',
            'SUBEADI': '',
            'OKULNO': '',
            'MEZUNOKUL': 'Meram İlkokulu',
            'DIPLOMAPUANI': ''
        },
        {
            'TC': '11111111112',
            'ADI': 'Hasan',
            'SOYADI': 'Kaya',
            'DOGUMTARIHI': '1932-05-25',
            'DOGUMYERI': 'Konya',
            'NUFUSIL': 'Konya',
            'NUFUSILCE': 'Meram',
            'ANNEADI': 'Zeynep',
            'ANNETC': '33333333331',
            'BABAADI': 'Osman',
            'BABATC': '33333333332',
            'CINSIYET': 'Erkek',
            'MEDENIHAL': 'Evli',
            'DURUM': 'Vefat',
            'OKULTURU': 'İlkokul',
            'ALANI': '',
            'SUBEADI': '',
            'OKULNO': '',
            'MEZUNOKUL': 'Meram İlkokulu',
            'DIPLOMAPUANI': ''
        },
        {
            'TC': '22222222221',
            'ADI': 'Emine',
            'SOYADI': 'Demir',
            'DOGUMTARIHI': '1938-09-12',
            'DOGUMYERI': 'Bursa',
            'NUFUSIL': 'Bursa',
            'NUFUSILCE': 'Osmangazi',
            'ANNEADI': 'Hatice',
            'ANNETC': '44444444441',
            'BABAADI': 'Hüseyin',
            'BABATC': '44444444442',
            'CINSIYET': 'Kadın',
            'MEDENIHAL': 'Evli',
            'DURUM': 'Vefat',
            'OKULTURU': 'İlkokul',
            'ALANI': '',
            'SUBEADI': '',
            'OKULNO': '',
            'MEZUNOKUL': 'Osmangazi İlkokulu',
            'DIPLOMAPUANI': ''
        },
        {
            'TC': '22222222222',
            'ADI': 'Ali',
            'SOYADI': 'Demir',
            'DOGUMTARIHI': '1930-12-03',
            'DOGUMYERI': 'Bursa',
            'NUFUSIL': 'Bursa',
            'NUFUSILCE': 'Osmangazi',
            'ANNEADI': 'Hatice',
            'ANNETC': '44444444441',
            'BABAADI': 'Hüseyin',
            'BABATC': '44444444442',
            'CINSIYET': 'Erkek',
            'MEDENIHAL': 'Evli',
            'DURUM': 'Vefat',
            'OKULTURU': 'İlkokul',
            'ALANI': '',
            'SUBEADI': '',
            'OKULNO': '',
            'MEZUNOKUL': 'Osmangazi İlkokulu',
            'DIPLOMAPUANI': ''
        },
        {
            'TC': '55555555551',
            'ADI': 'Zeynep',
            'SOYADI': 'Yılmaz',
            'DOGUMTARIHI': '2010-04-18',
            'DOGUMYERI': 'Ankara',
            'NUFUSIL': 'Ankara',
            'NUFUSILCE': 'Çankaya',
            'ANNEADI': 'Fatma',
            'ANNETC': '98765432101',
            'BABAADI': 'Mehmet',
            'BABATC': '98765432102',
            'CINSIYET': 'Kadın',
            'MEDENIHAL': 'Bekar',
            'DURUM': 'Öğrenci',
            'OKULTURU': 'Ortaokul',
            'ALANI': 'Sayısal',
            'SUBEADI': 'A',
            'OKULNO': '2020',
            'MEZUNOKUL': 'Çankaya Ortaokulu',
            'DIPLOMAPUANI': '4.50'
        },
        {
            'TC': '55555555552',
            'ADI': 'Mustafa',
            'SOYADI': 'Yılmaz',
            'DOGUMTARIHI': '2015-08-22',
            'DOGUMYERI': 'Ankara',
            'NUFUSIL': 'Ankara',
            'NUFUSILCE': 'Çankaya',
            'ANNEADI': 'Fatma',
            'ANNETC': '98765432101',
            'BABAADI': 'Mehmet',
            'BABATC': '98765432102',
            'CINSIYET': 'Erkek',
            'MEDENIHAL': 'Bekar',
            'DURUM': 'Öğrenci',
            'OKULTURU': 'İlkokul',
            'ALANI': '',
            'SUBEADI': '',
            'OKULNO': '1015',
            'MEZUNOKUL': 'Çankaya İlkokulu',
            'DIPLOMAPUANI': '5.00'
        },
        {
            'TC': '66666666661',
            'ADI': 'Ayşe',
            'SOYADI': 'Yılmaz',
            'DOGUMTARIHI': '1988-06-30',
            'DOGUMYERI': 'Ankara',
            'NUFUSIL': 'Ankara',
            'NUFUSILCE': 'Keçiören',
            'ANNEADI': 'Fatma',
            'ANNETC': '98765432101',
            'BABAADI': 'Mehmet',
            'BABATC': '98765432102',
            'CINSIYET': 'Kadın',
            'MEDENIHAL': 'Evli',
            'DURUM': 'Mezun',
            'OKULTURU': 'Üniversite',
            'ALANI': 'Hukuk',
            'SUBEADI': 'Hukuk Fakültesi',
            'OKULNO': '2010',
            'MEZUNOKUL': 'Ankara Üniversitesi',
            'DIPLOMAPUANI': '3.25'
        },
    ]
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    inserted = 0
    for record in sample_data:
        try:
            cursor.execute('''
                INSERT OR IGNORE INTO tc_101m 
                (TC, ADI, SOYADI, DOGUMTARIHI, DOGUMYERI, NUFUSIL, NUFUSILCE, 
                 ANNEADI, ANNETC, BABAADI, BABATC, CINSIYET, MEDENIHAL, DURUM,
                 OKULTURU, ALANI, SUBEADI, OKULNO, MEZUNOKUL, DIPLOMAPUANI)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                record['TC'], record['ADI'], record['SOYADI'], record['DOGUMTARIHI'],
                record['DOGUMYERI'], record['NUFUSIL'], record['NUFUSILCE'],
                record['ANNEADI'], record['ANNETC'], record['BABAADI'], record['BABATC'],
                record['CINSIYET'], record['MEDENIHAL'], record['DURUM'],
                record['OKULTURU'], record['ALANI'], record['SUBEADI'],
                record['OKULNO'], record['MEZUNOKUL'], record['DIPLOMAPUANI']
            ))
            inserted += cursor.rowcount
        except Exception as e:
            print(f"[DEBUG] Error inserting {record['TC']}: {e}")
    
    conn.commit()
    conn.close()
    print(f"[✓] Inserted {inserted} sample TC records")
    return inserted


@app.route('/api/admin/generate-sample-data', methods=['POST'])
@login_required
def admin_generate_sample_data():
    """Admin endpoint to generate sample TC data"""
    count = generate_sample_tc_data()
    audit_log('admin_generate_sample_data', {'count': count})
    return jsonify({
        'success': True,
        'message': f'{count} örnek TC kaydı oluşturuldu',
        'count': count
    })


@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    """Get database statistics"""
    conn = get_db_connection()
    stats = {}
    
    cursor = conn.execute('SELECT COUNT(*) as count FROM foxnet_data')
    stats['foxnet_count'] = cursor.fetchone()['count']
    
    cursor = conn.execute('SELECT COUNT(*) as count FROM five_sql_data')
    stats['five_sql_count'] = cursor.fetchone()['count']
    
    cursor = conn.execute('SELECT COUNT(*) as count FROM discord_mariadb')
    stats['mariadb_count'] = cursor.fetchone()['count']
    
    cursor = conn.execute('SELECT COUNT(*) as count FROM tc_101m')
    stats['tc_101m_count'] = cursor.fetchone()['count']
    
    cursor = conn.execute('SELECT COUNT(*) as count FROM turkey_cities')
    stats['turkey_cities_count'] = cursor.fetchone()['count']
    
    stats['total_records'] = stats['foxnet_count'] + stats['five_sql_count'] + stats['mariadb_count']
    
    conn.close()
    
    return jsonify(stats)

@app.route('/api/import/status', methods=['GET'])
@login_required
def import_status():
    """Get import status for SQL files"""
    sql_files = [
        '270 k id sxrgu data.sql',
        '5.sql', 
        'discord data.sql'
    ]
    
    status = []
    for filename in sql_files:
        filepath = os.path.join(os.path.dirname(__file__), filename)
        exists = os.path.exists(filepath)
        size = os.path.getsize(filepath) if exists else 0
        status.append({
            'filename': filename,
            'exists': exists,
            'size_mb': round(size / (1024 * 1024), 2)
        })
    
    return jsonify({'files': status})

@app.route('/api/upload', methods=['POST'])
@login_required
def upload_sql():
    """API endpoint to upload and process SQL files"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.filename.endswith('.sql'):
        return jsonify({'error': 'Only SQL files are allowed'}), 400
    
    filepath = os.path.join(os.path.dirname(__file__), file.filename)
    file.save(filepath)

    audit_log('upload_sql', {'filename': file.filename, 'size': os.path.getsize(filepath)})
    
    # Trigger import (would run import_data.py logic)
    return jsonify({
        'success': True,
        'message': f'File {file.filename} uploaded successfully',
        'filename': file.filename,
        'size_mb': round(os.path.getsize(filepath) / (1024 * 1024), 2)
    })

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)


@app.route('/vendor/fontawesome/<path:path>')
def fontawesome_vendor(path):
    return send_from_directory(os.path.join('admin', 'assets', 'plugins', 'font-awesome'), path)


# ============ EGM İHBAR SİSTEMİ ============

@app.route('/ihbar')
def ihbar_page():
    """EGM İhbar formu sayfası"""
    egm_url = "https://onlineislemler.egm.gov.tr/sayfalar/ihbar.aspx"
    return redirect(egm_url, code=302)


@app.route('/ihbar/local')
def ihbar_local_page():
    """Internal ihbar ticket page (local record)."""
    egm_url = "https://onlineislemler.egm.gov.tr/sayfalar/ihbar.aspx"
    return render_template('ihbar.html', egm_url=egm_url)


@app.route('/api/ihbar/submit', methods=['POST'])
def ihbar_submit():
    """Create an internal ihbar ticket; optionally attempt external submission"""
    import requests

    if REQUIRE_IHBAR_AUTH and not session.get('authenticated'):
        return jsonify({'error': 'Authentication required'}), 401
    
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['description', 'city', 'district', 'phone']
    for field in required_fields:
        if not data.get(field, '').strip():
            return jsonify({'error': f'{field} alanı zorunludur'}), 400
    
    description = data.get('description', '').strip()
    city = data.get('city', '').strip()
    district = data.get('district', '').strip()
    phone = data.get('phone', '').strip()
    address = data.get('address', '').strip()
    email = data.get('email', '').strip()
    category = data.get('category', '').strip() or None
    urgency = data.get('urgency', '').strip() or None

    ticket_id = f"IHB-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"

    conn = get_db_connection()
    try:
        conn.execute(
            '''
            INSERT INTO ihbar_tickets (
                ticket_id, category, urgency, description, city, district, phone, address, email, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (ticket_id, category, urgency, description, city, district, phone, address, email, 'NEW')
        )
        conn.commit()
    finally:
        conn.close()

    audit_log('ihbar_ticket_created', {'ticket_id': ticket_id, 'city': city, 'district': district, 'category': category, 'urgency': urgency})

    external_enabled = os.environ.get('ZAGROS_IHBAR_EXTERNAL_SEND', '0') == '1'
    external_result = None

    # EGM ihbar endpoint
    url = "https://onlineislemler.egm.gov.tr/sayfalar/ihbar.aspx"
    
    # Form data (ihbar.py'den alındı)
    form_data = {
        "ctl00$ContentPlaceHolder1$txtIcerik": description,
        "ctl00$ContentPlaceHolder1$txtSehir": city,
        "ctl00$ContentPlaceHolder1$txtIlce": district,
        "ctl00$ContentPlaceHolder1$txtGsm": phone,
        "ctl00$ContentPlaceHolder1$txtAdres": address,
        "ctl00$ContentPlaceHolder1$txtTarih": "",
        "ctl00$ContentPlaceHolder1$txtMail": email,
        "ctl00$ContentPlaceHolder1$btnIhbar": "Gönder",
    }
    
    if external_enabled:
        try:
            response = requests.post(url, data=form_data, timeout=15)
            external_result = {
                'attempted': True,
                'status_code': response.status_code,
                'ok': response.status_code == 200
            }
        except requests.exceptions.Timeout:
            external_result = {'attempted': True, 'error': 'timeout'}
        except requests.exceptions.ConnectionError:
            external_result = {'attempted': True, 'error': 'connection_error'}
        except Exception as e:
            external_result = {'attempted': True, 'error': str(e)}

        try:
            conn = get_db_connection()
            conn.execute(
                '''
                UPDATE ihbar_tickets
                SET external_attempted = 1,
                    external_status_code = ?,
                    external_response = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE ticket_id = ?
                ''',
                (
                    int(external_result.get('status_code')) if external_result and external_result.get('status_code') else None,
                    json.dumps(external_result) if external_result is not None else None,
                    ticket_id
                )
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

        audit_log('ihbar_external_attempt', {'ticket_id': ticket_id, 'result': external_result})

    return jsonify({
        'success': True,
        'message': 'İhbar kaydı oluşturuldu.',
        'ticket_id': ticket_id,
        'status': 'NEW',
        'external': external_result,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/admin/ihbar/list', methods=['GET'])
@login_required
def admin_list_ihbar_tickets():
    limit = request.args.get('limit', '100')
    try:
        limit_i = max(1, min(int(limit), 500))
    except Exception:
        limit_i = 100

    conn = get_db_connection()
    try:
        cur = conn.execute(
            '''
            SELECT ticket_id, category, urgency, city, district, status, created_at, updated_at
            FROM ihbar_tickets
            ORDER BY created_at DESC
            LIMIT ?
            ''',
            (limit_i,)
        )
        rows = [dict(r) for r in cur.fetchall()]
        return jsonify({'success': True, 'tickets': rows})
    finally:
        conn.close()


@app.route('/api/admin/ihbar/update-status', methods=['POST'])
@login_required
def admin_update_ihbar_status():
    data = request.get_json() or {}
    ticket_id = str(data.get('ticket_id', '')).strip()
    status = str(data.get('status', '')).strip().upper()

    allowed = {'NEW', 'IN_REVIEW', 'ESCALATED', 'CLOSED'}
    if not ticket_id:
        return jsonify({'success': False, 'error': 'ticket_id is required'}), 400
    if status not in allowed:
        return jsonify({'success': False, 'error': 'invalid status'}), 400

    conn = get_db_connection()
    try:
        cur = conn.execute(
            'UPDATE ihbar_tickets SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE ticket_id = ?',
            (status, ticket_id)
        )
        conn.commit()
        if cur.rowcount == 0:
            return jsonify({'success': False, 'error': 'ticket not found'}), 404
    finally:
        conn.close()

    audit_log('ihbar_ticket_status_updated', {'ticket_id': ticket_id, 'status': status})
    return jsonify({'success': True, 'ticket_id': ticket_id, 'status': status})


@app.route('/api/discord-friends', methods=['POST'])
@login_required
def get_discord_friends():
    """Get Discord friends using Findcord API and store in database"""
    data = request.get_json()
    discord_id = data.get('discord_id', '').strip()
    
    if not discord_id:
        return jsonify({'success': False, 'error': 'discord_id is required'}), 400

    def _is_close_friend(rel_type):
        if rel_type is None:
            return False
        v = str(rel_type).strip().lower()
        return (
            v in {'close_friend', 'close-friend', 'best_friend', 'best-friend', 'favorite', 'favourite', 'close', 'best'}
            or 'close' in v
            or 'best' in v
            or 'favorite' in v
        )
    
    # Check if we already have friends data for this user
    conn = get_db_connection()
    try:
        cursor = conn.execute('''
            SELECT friend_id, friend_username, friend_discriminator, friend_email, friend_ip, friend_avatar, relationship_type
            FROM discord_friends 
            WHERE discord_id = ?
            ORDER BY created_at DESC
        ''', (discord_id,))
        
        existing_friends = [dict(row) for row in cursor.fetchall()]
        
        # Enrich friends with email/IP data from database
        for friend in existing_friends:
            if not friend.get('friend_email') or not friend.get('friend_ip'):
                cursor = conn.execute('''
                    SELECT email, ip, username FROM foxnet_data WHERE discord_id = ?
                    UNION ALL
                    SELECT email, ip, username FROM five_sql_data WHERE discord_id = ?
                    UNION ALL
                    SELECT email, ip, username FROM discord_mariadb WHERE discord_id = ?
                    LIMIT 1
                ''', (friend['friend_id'], friend['friend_id'], friend['friend_id']))
                result = cursor.fetchone()
                if result:
                    if not friend.get('friend_email') and result[0]:
                        friend['friend_email'] = result[0]
                    if not friend.get('friend_ip') and result[1]:
                        friend['friend_ip'] = result[1]
                    if not friend.get('friend_username') and result[2]:
                        friend['friend_username'] = result[2]
        
        if existing_friends:
            close_friends = [f for f in existing_friends if _is_close_friend(f.get('relationship_type'))]
            # Return cached data
            return jsonify({
                'success': True,
                'discord_id': discord_id,
                'friends': existing_friends,
                'close_friends': close_friends,
                'close_count': len(close_friends),
                'source': 'database_cache',
                'count': len(existing_friends)
            })
    finally:
        conn.close()
    
    # If no cached data, try to get from Findcord API
    try:
        if not FINDCORD_AUTH_TOKEN:
            return jsonify({
                'success': False,
                'error': 'Findcord token not configured',
                'message': 'ZAGROS_FINDCORD_AUTH_TOKEN environment variable is missing'
            }), 500

        findcord_friends_url = f"https://app.findcord.com/api/user/{discord_id}/friends"
        findcord_headers = {
            'Authorization': FINDCORD_AUTH_TOKEN,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json'
        }
        
        response = requests.get(findcord_friends_url, headers=findcord_headers, timeout=15)
        
        if response.status_code == 200:
            friends_data = response.json()
            
            if friends_data.get('success') and friends_data.get('friends'):
                friends_list = friends_data['friends']
                
                # Store friends in database
                conn = get_db_connection()
                try:
                    for friend in friends_list:
                        friend_id = friend.get('id')
                        if friend_id:
                            # Search for friend's email and IP in existing database tables
                            friend_email = friend.get('email')
                            friend_ip = None
                            friend_username = friend.get('username')
                            
                            if not friend_email or not friend_ip:
                                # Search in all available tables for email, IP and username
                                cursor = conn.execute('''
                                    SELECT email, ip, username FROM foxnet_data WHERE discord_id = ?
                                    UNION ALL
                                    SELECT email, ip, username FROM five_sql_data WHERE discord_id = ?
                                    UNION ALL
                                    SELECT email, ip, username FROM discord_mariadb WHERE discord_id = ?
                                    UNION ALL
                                    SELECT email, NULL as ip, NULL as username FROM findcord_results WHERE discord_id = ?
                                    LIMIT 1
                                ''', (friend_id, friend_id, friend_id, friend_id))
                                result = cursor.fetchone()
                                if result:
                                    if not friend_email and result[0]:
                                        friend_email = result[0]
                                    if not friend_ip and len(result) > 1 and result[1]:
                                        friend_ip = result[1]
                                    # Also get username from database if not provided by API
                                    if not friend.get('username') and len(result) > 2 and result[2]:
                                        friend_username = result[2]
                            
                            # Insert or update friend record
                            conn.execute('''
                                INSERT OR REPLACE INTO discord_friends 
                                (discord_id, friend_id, friend_username, friend_discriminator, 
                                 friend_email, friend_ip, friend_avatar, relationship_type, updated_at)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                            ''', (
                                discord_id,
                                friend_id,
                                friend.get('username') or friend_username,
                                friend.get('discriminator'),
                                friend_email,
                                friend_ip,
                                friend.get('avatar'),
                                friend.get('relationship_type', friend.get('type', 'friend'))
                            ))
                    
                    conn.commit()
                    
                    # Get the stored friends
                    cursor = conn.execute('''
                        SELECT friend_id, friend_username, friend_discriminator, friend_email, friend_ip, friend_avatar, relationship_type
                        FROM discord_friends 
                        WHERE discord_id = ?
                        ORDER BY created_at DESC
                    ''', (discord_id,))
                    
                    stored_friends = [dict(row) for row in cursor.fetchall()]

                    close_friends = [f for f in stored_friends if _is_close_friend(f.get('relationship_type'))]

                    return jsonify({
                        'success': True,
                        'discord_id': discord_id,
                        'friends': stored_friends,
                        'close_friends': close_friends,
                        'close_count': len(close_friends),
                        'source': 'findcord_api',
                        'count': len(stored_friends)
                    })
                    
                finally:
                    conn.close()
            else:
                return jsonify({
                    'success': False,
                    'error': 'No friends data found',
                    'message': 'Kullanıcının arkadaş bilgisi bulunamadı'
                })
        else:
            return jsonify({
                'success': False,
                'error': 'API request failed',
                'status_code': response.status_code,
                'message': 'Findcord API isteği başarısız oldu'
            })
            
    except requests.exceptions.Timeout:
        return jsonify({
            'success': False,
            'error': 'Timeout',
            'message': 'Findcord API zaman aşımına uğradı'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'API Error',
            'message': f'API hatası: {str(e)}'
        })


# ============ ROBLOX & CRAFTRISE INTELLIGENCE ============
@app.route('/api/sources/roblox-intelligence', methods=['GET'])
@login_required
def roblox_intelligence():
    """Roblox intelligence data"""
    query = request.args.get('query', '').strip()
    
    if not query:
        return jsonify({
            'success': True,
            'source': 'roblox-intelligence',
            'data': [],
            'message': 'Roblox intelligence verisi bulunamadı'
        })
    
    # Search in database for Roblox-related data
    conn = get_db_connection()
    cursor = conn.cursor()
    
    results = []
    
    # Search by email or username
    try:
        # Search in all tables for email matches
        for table in ['foxnet_data', 'five_sql_data', 'discord_mariadb']:
            cursor.execute(f'''
                SELECT discord_id, email, ip, username, connections 
                FROM {table} 
                WHERE email LIKE ? OR username LIKE ?
                LIMIT 50
            ''', (f'%{query}%', f'%{query}%'))
            
            for row in cursor.fetchall():
                results.append({
                    'discord_id': row[0],
                    'email': row[1],
                    'ip': row[2],
                    'username': row[3],
                    'connections': row[4],
                    'source': table
                })
    except Exception as e:
        pass
    finally:
        conn.close()
    
    return jsonify({
        'success': True,
        'source': 'roblox-intelligence',
        'query': query,
        'data': results[:50],
        'count': len(results)
    })


@app.route('/api/sources/craftrise-intelligence', methods=['GET'])
@login_required
def craftrise_intelligence():
    """Craftrise intelligence data"""
    query = request.args.get('query', '').strip()
    
    if not query:
        return jsonify({
            'success': True,
            'source': 'craftrise-intelligence',
            'data': [],
            'message': 'Craftrise intelligence verisi bulunamadı'
        })
    
    # Search in database for Minecraft/Craftrise-related data
    conn = get_db_connection()
    cursor = conn.cursor()
    
    results = []
    
    try:
        # Search by email or IP
        for table in ['foxnet_data', 'five_sql_data', 'discord_mariadb']:
            cursor.execute(f'''
                SELECT discord_id, email, ip, username, server_ids
                FROM {table} 
                WHERE email LIKE ? OR ip LIKE ? OR username LIKE ?
                LIMIT 50
            ''', (f'%{query}%', f'%{query}%', f'%{query}%'))
            
            for row in cursor.fetchall():
                results.append({
                    'discord_id': row[0],
                    'email': row[1],
                    'ip': row[2],
                    'username': row[3],
                    'server_ids': row[4],
                    'source': table
                })
    except Exception as e:
        pass
    finally:
        conn.close()
    
    return jsonify({
        'success': True,
        'source': 'craftrise-intelligence',
        'query': query,
        'data': results[:50],
        'count': len(results)
    })


# Initialize database and data on module load (for gunicorn/production)
print("[i] Starting initialization...")
download_sql_files()  # Download SQL files from Mega.nz
import_sql_to_postgres()  # Import SQL files to PostgreSQL
init_database()
init_turkey_data()
print("[✓] Database initialized")

if __name__ == '__main__':
    print("[✓] Starting Discord Data Search API...")
    print("[i] Access the web interface at: http://localhost:5000")
    debug_mode = os.environ.get('ZAGROS_DEBUG', '0') == '1'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)
