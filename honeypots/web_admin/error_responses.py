"""
Realistic Error Messages and Response System for Web Admin Portal Honeypot

Provides realistic error messages, HTTP responses, and system behaviors
that would be expected from a real corporate admin portal.
"""

import secrets
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime

@dataclass
class ErrorResponse:
    """Structured error response"""
    code: str
    message: str
    details: Optional[str] = None
    timestamp: str = ""
    synthetic: bool = True
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

class RealisticErrorGenerator:
    """Generates realistic error messages and responses"""
    
    # Authentication errors
    AUTH_ERRORS = [
        ErrorResponse("AUTH_001", "Invalid username or password"),
        ErrorResponse("AUTH_002", "Authentication failed", "Please check your credentials and try again"),
        ErrorResponse("AUTH_003", "Access denied", "Your account may be locked or disabled"),
        ErrorResponse("AUTH_004", "Session expired", "Please log in again to continue"),
        ErrorResponse("AUTH_005", "Too many failed attempts", "Account temporarily locked for security"),
        ErrorResponse("AUTH_006", "Invalid session token", "Please refresh the page and try again"),
        ErrorResponse("AUTH_007", "Insufficient privileges", "You don't have permission to access this resource"),
    ]
    
    # Database errors
    DB_ERRORS = [
        ErrorResponse("DB_001", "Database connection failed", "Unable to connect to user database"),
        ErrorResponse("DB_002", "Query timeout", "The database query took too long to execute"),
        ErrorResponse("DB_003", "Record not found", "The requested user record does not exist"),
        ErrorResponse("DB_004", "Constraint violation", "Unable to update user due to data constraints"),
        ErrorResponse("DB_005", "Database maintenance", "System temporarily unavailable for maintenance"),
        ErrorResponse("DB_006", "Connection pool exhausted", "Too many concurrent database connections"),
    ]
    
    # System errors
    SYSTEM_ERRORS = [
        ErrorResponse("SYS_001", "Internal server error", "An unexpected error occurred"),
        ErrorResponse("SYS_002", "Service unavailable", "The requested service is temporarily unavailable"),
        ErrorResponse("SYS_003", "Configuration error", "System configuration issue detected"),
        ErrorResponse("SYS_004", "Resource limit exceeded", "System resource limits have been reached"),
        ErrorResponse("SYS_005", "Network timeout", "Network connection timed out"),
        ErrorResponse("SYS_006", "File system error", "Unable to access required system files"),
    ]
    
    # Validation errors
    VALIDATION_ERRORS = [
        ErrorResponse("VAL_001", "Invalid input format", "The provided data format is incorrect"),
        ErrorResponse("VAL_002", "Required field missing", "One or more required fields are empty"),
        ErrorResponse("VAL_003", "Data length exceeded", "Input data exceeds maximum allowed length"),
        ErrorResponse("VAL_004", "Invalid characters", "Input contains invalid or restricted characters"),
        ErrorResponse("VAL_005", "Format mismatch", "Data format does not match expected pattern"),
        ErrorResponse("VAL_006", "Duplicate entry", "A record with this information already exists"),
    ]
    
    # Permission errors
    PERMISSION_ERRORS = [
        ErrorResponse("PERM_001", "Access denied", "You don't have permission to perform this action"),
        ErrorResponse("PERM_002", "Role restriction", "Your current role doesn't allow this operation"),
        ErrorResponse("PERM_003", "Department restriction", "Access limited to specific departments"),
        ErrorResponse("PERM_004", "Time restriction", "This action is not allowed during current hours"),
        ErrorResponse("PERM_005", "IP restriction", "Access denied from your current location"),
        ErrorResponse("PERM_006", "License limitation", "Feature not available with current license"),
    ]
    
    @classmethod
    def get_auth_error(cls) -> ErrorResponse:
        """Get a random authentication error"""
        return secrets.choice(cls.AUTH_ERRORS)
    
    @classmethod
    def get_db_error(cls) -> ErrorResponse:
        """Get a random database error"""
        return secrets.choice(cls.DB_ERRORS)
    
    @classmethod
    def get_system_error(cls) -> ErrorResponse:
        """Get a random system error"""
        return secrets.choice(cls.SYSTEM_ERRORS)
    
    @classmethod
    def get_validation_error(cls) -> ErrorResponse:
        """Get a random validation error"""
        return secrets.choice(cls.VALIDATION_ERRORS)
    
    @classmethod
    def get_permission_error(cls) -> ErrorResponse:
        """Get a random permission error"""
        return secrets.choice(cls.PERMISSION_ERRORS)
    
    @classmethod
    def get_contextual_error(cls, context: str) -> ErrorResponse:
        """Get an error appropriate for the given context"""
        context_map = {
            "login": cls.AUTH_ERRORS,
            "database": cls.DB_ERRORS,
            "system": cls.SYSTEM_ERRORS,
            "validation": cls.VALIDATION_ERRORS,
            "permission": cls.PERMISSION_ERRORS,
        }
        
        error_list = context_map.get(context, cls.SYSTEM_ERRORS)
        return secrets.choice(error_list)

class HTTPResponseGenerator:
    """Generates realistic HTTP responses and headers"""
    
    # Common server headers that would appear on a real admin portal
    COMMON_HEADERS = {
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3",
        "X-Frame-Options": "SAMEORIGIN",
        "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0"
    }
    
    # Response templates for different scenarios
    ERROR_TEMPLATES = {
        "404": {
            "status": 404,
            "title": "Page Not Found",
            "message": "The requested page could not be found on this server.",
            "details": "Please check the URL and try again, or contact your system administrator."
        },
        "403": {
            "status": 403,
            "title": "Access Forbidden",
            "message": "You don't have permission to access this resource.",
            "details": "Contact your system administrator if you believe this is an error."
        },
        "500": {
            "status": 500,
            "title": "Internal Server Error",
            "message": "The server encountered an internal error and was unable to complete your request.",
            "details": "Please try again later or contact technical support."
        },
        "503": {
            "status": 503,
            "title": "Service Unavailable",
            "message": "The server is temporarily unable to service your request.",
            "details": "This may be due to maintenance or high server load. Please try again later."
        }
    }
    
    @classmethod
    def get_error_page(cls, error_code: str) -> Dict:
        """Generate a realistic error page"""
        template = cls.ERROR_TEMPLATES.get(error_code, cls.ERROR_TEMPLATES["500"])
        
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{template['title']} - CorpTech Admin Portal</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 50px; background: #f5f5f5; }}
                .error-container {{ max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .error-code {{ font-size: 4em; font-weight: bold; color: #d32f2f; margin-bottom: 20px; }}
                .error-title {{ font-size: 1.5em; margin-bottom: 15px; color: #333; }}
                .error-message {{ margin-bottom: 20px; color: #666; }}
                .error-details {{ font-size: 0.9em; color: #888; }}
                .back-link {{ margin-top: 30px; }}
                .back-link a {{ color: #007cba; text-decoration: none; }}
                .back-link a:hover {{ text-decoration: underline; }}
            </style>
        </head>
        <body>
            <div class="error-container">
                <div class="error-code">{template['status']}</div>
                <div class="error-title">{template['title']}</div>
                <div class="error-message">{template['message']}</div>
                <div class="error-details">{template['details']}</div>
                <div class="back-link">
                    <a href="/">← Return to Dashboard</a>
                </div>
            </div>
        </body>
        </html>
        """
        
        return {
            "html": html_template,
            "status": template['status'],
            "headers": cls.COMMON_HEADERS
        }
    
    @classmethod
    def get_maintenance_page(cls) -> Dict:
        """Generate a maintenance page"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>System Maintenance - CorpTech Admin Portal</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 50px; background: #f5f5f5; text-align: center; }
                .maintenance-container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .maintenance-icon { font-size: 4em; margin-bottom: 20px; }
                .maintenance-title { font-size: 1.5em; margin-bottom: 15px; color: #333; }
                .maintenance-message { margin-bottom: 20px; color: #666; }
                .maintenance-time { font-weight: bold; color: #007cba; }
            </style>
        </head>
        <body>
            <div class="maintenance-container">
                <div class="maintenance-icon">🔧</div>
                <div class="maintenance-title">Scheduled Maintenance</div>
                <div class="maintenance-message">
                    The CorpTech Admin Portal is currently undergoing scheduled maintenance.
                    We apologize for any inconvenience.
                </div>
                <div class="maintenance-time">
                    Estimated completion: 2:00 AM EST
                </div>
                <div style="margin-top: 30px; font-size: 0.9em; color: #888;">
                    For urgent issues, please contact IT support at ext. 5555
                </div>
            </div>
        </body>
        </html>
        """
        
        return {
            "html": html_template,
            "status": 503,
            "headers": cls.COMMON_HEADERS
        }

class SessionManager:
    """Manages realistic session behavior and timeouts"""
    
    def __init__(self):
        self.session_timeout = 3600  # 1 hour
        self.max_sessions = 100
        self.session_warnings = [
            "Your session will expire in 5 minutes due to inactivity",
            "Session timeout warning: Please save your work",
            "For security reasons, your session will expire soon"
        ]
    
    def is_session_valid(self, session_start: datetime) -> bool:
        """Check if session is still valid"""
        elapsed = (datetime.now() - session_start).total_seconds()
        return elapsed < self.session_timeout
    
    def get_session_warning(self) -> str:
        """Get a random session warning message"""
        return secrets.choice(self.session_warnings)
    
    def generate_csrf_token(self) -> str:
        """Generate a realistic CSRF token"""
        return secrets.token_urlsafe(32)

class SecurityResponseGenerator:
    """Generates security-related responses and behaviors"""
    
    SECURITY_MESSAGES = [
        "Multiple failed login attempts detected from your IP address",
        "Unusual activity detected on your account",
        "Security policy requires password change every 90 days",
        "Your account will be locked after 3 more failed attempts",
        "Two-factor authentication is required for admin access",
        "VPN connection required for external access"
    ]
    
    LOCKOUT_MESSAGES = [
        "Account temporarily locked due to security policy",
        "Too many failed login attempts - account disabled for 15 minutes",
        "Security lockout in effect - contact administrator",
        "Account access suspended pending security review"
    ]
    
    @classmethod
    def get_security_warning(cls) -> str:
        """Get a random security warning"""
        return secrets.choice(cls.SECURITY_MESSAGES)
    
    @classmethod
    def get_lockout_message(cls) -> str:
        """Get a random lockout message"""
        return secrets.choice(cls.LOCKOUT_MESSAGES)
    
    @classmethod
    def should_trigger_security_response(cls, failed_attempts: int) -> bool:
        """Determine if security response should be triggered"""
        # Realistic thresholds for security responses
        if failed_attempts >= 3:
            return secrets.randbelow(100) < 80  # 80% chance after 3 attempts
        elif failed_attempts >= 5:
            return True  # Always trigger after 5 attempts
        return False