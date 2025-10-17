"""
Email Honeypot Implementation

Creates a realistic SMTP/IMAP server with synthetic accounts,
email conversations, and realistic email-based attack detection.
"""

import asyncio
import logging
import secrets
import hashlib
import uuid
import email
import smtplib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
import threading
import socket
import base64
import quopri

logger = logging.getLogger(__name__)

@dataclass
class SyntheticEmail:
    """Synthetic email message"""
    message_id: str
    from_address: str
    to_addresses: List[str]
    cc_addresses: List[str]
    bcc_addresses: List[str]
    subject: str
    body: str
    html_body: Optional[str]
    timestamp: datetime
    attachments: List[Dict[str, Any]]
    headers: Dict[str, str]
    synthetic: bool = True
    fingerprint: str = ""
    
    def __post_init__(self):
        if not self.fingerprint:
            data = f"{self.message_id}{self.from_address}{self.subject}{self.timestamp}"
            self.fingerprint = hashlib.sha256(data.encode()).hexdigest()[:16]

@dataclass
class EmailAccount:
    """Synthetic email account"""
    email_address: str
    password: str
    display_name: str
    department: str
    inbox: List[SyntheticEmail]
    sent: List[SyntheticEmail]
    drafts: List[SyntheticEmail]
    deleted: List[SyntheticEmail]
    contacts: List[Dict[str, str]]
    synthetic: bool = True

@dataclass
class EmailAccess:
    """Email access record"""
    action: str  # 'login', 'send', 'read', 'delete', 'search'
    timestamp: datetime
    session_id: str
    user: str
    ip_address: str
    protocol: str  # 'smtp', 'imap', 'pop3'
    details: Dict[str, Any]
    success: bool
    synthetic: bool = True

@dataclass
class EmailSession:
    """Email session tracking"""
    session_id: str
    username: str
    ip_address: str
    protocol: str
    start_time: datetime
    last_activity: datetime
    email_accesses: List[EmailAccess]
    connection_info: Dict[str, Any]
    synthetic: bool = True

class SyntheticEmailGenerator:
    """Generates realistic synthetic emails and conversations"""
    
    EMAIL_TEMPLATES = {
        "meeting_invitation": {
            "subject": "Meeting Invitation: {meeting_title}",
            "body": """Hi {recipient_name},

You're invited to attend the following meeting:

Subject: {meeting_title}
Date: {meeting_date}
Time: {meeting_time}
Location: {meeting_location}
Duration: {duration}

Agenda:
{agenda}

Please confirm your attendance by replying to this email.

Best regards,
{sender_name}

--- 
This is an automated message from CorpTech Calendar System
"""
        },
        
        "project_update": {
            "subject": "Project Update: {project_name}",
            "body": """Team,

Here's the latest update on {project_name}:

Current Status: {status}
Completion: {completion_percentage}%
Next Milestone: {next_milestone}

Recent Accomplishments:
- {accomplishment_1}
- {accomplishment_2}
- {accomplishment_3}

Upcoming Tasks:
- {task_1}
- {task_2}
- {task_3}

Issues/Blockers:
{issues}

Please let me know if you have any questions or concerns.

Best regards,
{sender_name}
Project Manager
"""
        },
        
        "security_alert": {
            "subject": "SECURITY ALERT: {alert_type}",
            "body": """ATTENTION: Security Alert

Alert Type: {alert_type}
Severity: {severity}
Detected: {detection_time}
Affected Systems: {affected_systems}

Description:
{description}

Immediate Actions Required:
1. {action_1}
2. {action_2}
3. {action_3}

If you have any questions, please contact the Security Team immediately at security@corptech.com or call (555) 123-HELP.

Do not ignore this message.

CorpTech Security Team
"""
        },
        
        "hr_announcement": {
            "subject": "HR Announcement: {announcement_type}",
            "body": """Dear Team,

{announcement_type}

{announcement_details}

Key Information:
- Effective Date: {effective_date}
- Applies To: {applies_to}
- Contact: {contact_person}

Please review the attached policy document for complete details.

If you have questions, please contact HR at hr@corptech.com.

Best regards,
{sender_name}
Human Resources Department
"""
        },
        
        "customer_inquiry": {
            "subject": "Customer Inquiry: {inquiry_type}",
            "body": """Hello,

We received the following inquiry from a customer:

Customer: {customer_name}
Company: {customer_company}
Email: {customer_email}
Phone: {customer_phone}

Inquiry Type: {inquiry_type}
Priority: {priority}

Message:
{customer_message}

Please respond within {response_time} hours.

Customer Support System
"""
        },
        
        "vendor_communication": {
            "subject": "Vendor Communication: {vendor_name}",
            "body": """Dear {recipient_name},

We have received communication from {vendor_name} regarding {subject_matter}.

Vendor Contact: {vendor_contact}
Reference Number: {reference_number}
Date Received: {date_received}

Summary:
{summary}

Action Required: {action_required}
Deadline: {deadline}

Please review and take appropriate action.

Best regards,
{sender_name}
Procurement Department
"""
        }
    }
    
    DEPARTMENTS = [
        "Engineering", "Marketing", "Sales", "HR", "Finance", "Operations",
        "Legal", "IT", "Customer Support", "Product", "Research", "Executive"
    ]
    
    NAMES = [
        "John Smith", "Jane Doe", "Michael Johnson", "Sarah Wilson",
        "David Brown", "Lisa Davis", "Robert Miller", "Emily Garcia",
        "James Rodriguez", "Jessica Martinez", "William Anderson", "Ashley Taylor",
        "Christopher Lee", "Amanda White", "Daniel Harris", "Rebecca Clark"
    ]
    
    COMPANIES = [
        "TechCorp Solutions", "DataFlow Industries", "CloudFirst Systems",
        "Innovation Partners", "Digital Dynamics", "CyberSoft Inc",
        "NetWorks Global", "InfoTech Solutions", "SystemsPlus Ltd"
    ]
    
    @classmethod
    def generate_email_accounts(cls, count: int = 50) -> List[EmailAccount]:
        """Generate synthetic email accounts"""
        accounts = []
        
        for i in range(count):
            name = secrets.choice(cls.NAMES)
            first_name, last_name = name.split(' ', 1)
            email_address = f"{first_name.lower()}.{last_name.lower()}@corptech.com"
            department = secrets.choice(cls.DEPARTMENTS)
            
            # Generate contacts
            contacts = []
            for j in range(secrets.randbelow(20) + 5):
                contact_name = secrets.choice(cls.NAMES)
                contact_first, contact_last = contact_name.split(' ', 1)
                contact_email = f"{contact_first.lower()}.{contact_last.lower()}@{secrets.choice(['corptech.com', 'gmail.com', 'company.com'])}"
                contacts.append({
                    "name": contact_name,
                    "email": contact_email,
                    "department": secrets.choice(cls.DEPARTMENTS)
                })
            
            account = EmailAccount(
                email_address=email_address,
                password=f"password{i+1}",  # Weak passwords for honeypot
                display_name=name,
                department=department,
                inbox=[],
                sent=[],
                drafts=[],
                deleted=[],
                contacts=contacts
            )
            
            accounts.append(account)
        
        return accounts
    
    @classmethod
    def generate_email(cls, template_type: str, from_account: EmailAccount, to_accounts: List[EmailAccount], **kwargs) -> SyntheticEmail:
        """Generate a synthetic email from template"""
        
        if template_type not in cls.EMAIL_TEMPLATES:
            template_type = "project_update"
        
        template = cls.EMAIL_TEMPLATES[template_type]
        
        # Generate default values based on template type
        defaults = cls._get_template_defaults(template_type, from_account, to_accounts)
        
        # Merge provided kwargs with defaults
        params = {**defaults, **kwargs}
        
        # Generate email content
        subject = template["subject"].format(**params)
        body = template["body"].format(**params)
        
        # Create email
        email_msg = SyntheticEmail(
            message_id=f"<{uuid.uuid4()}@corptech.com>",
            from_address=from_account.email_address,
            to_addresses=[acc.email_address for acc in to_accounts],
            cc_addresses=[],
            bcc_addresses=[],
            subject=subject,
            body=body,
            html_body=None,
            timestamp=datetime.now() - timedelta(days=secrets.randbelow(30)),
            attachments=[],
            headers={
                "From": f"{from_account.display_name} <{from_account.email_address}>",
                "To": ", ".join([f"{acc.display_name} <{acc.email_address}>" for acc in to_accounts]),
                "Subject": subject,
                "Date": (datetime.now() - timedelta(days=secrets.randbelow(30))).strftime("%a, %d %b %Y %H:%M:%S %z"),
                "Message-ID": f"<{uuid.uuid4()}@corptech.com>",
                "X-Mailer": "CorpTech Mail System 2.1"
            }
        )
        
        return email_msg
    
    @classmethod
    def _get_template_defaults(cls, template_type: str, from_account: EmailAccount, to_accounts: List[EmailAccount]) -> Dict[str, Any]:
        """Get default values for email template"""
        
        recipient_name = to_accounts[0].display_name.split()[0] if to_accounts else "Team"
        sender_name = from_account.display_name
        
        if template_type == "meeting_invitation":
            meeting_date = (datetime.now() + timedelta(days=secrets.randbelow(14) + 1)).strftime("%Y-%m-%d")
            meeting_time = f"{secrets.randbelow(8) + 9}:00 AM"
            
            return {
                "recipient_name": recipient_name,
                "sender_name": sender_name,
                "meeting_title": secrets.choice([
                    "Weekly Team Standup", "Project Review Meeting", "Budget Planning Session",
                    "Quarterly Business Review", "Strategy Planning", "Client Presentation"
                ]),
                "meeting_date": meeting_date,
                "meeting_time": meeting_time,
                "meeting_location": secrets.choice([
                    "Conference Room A", "Main Conference Room", "Zoom Meeting",
                    "Building B - Floor 3", "Executive Boardroom"
                ]),
                "duration": secrets.choice(["30 minutes", "1 hour", "1.5 hours", "2 hours"]),
                "agenda": "1. Review previous action items\n2. Current project status\n3. Upcoming milestones\n4. Q&A and discussion"
            }
        
        elif template_type == "project_update":
            return {
                "sender_name": sender_name,
                "project_name": secrets.choice([
                    "Phoenix Initiative", "Cloud Migration", "Mobile App Development",
                    "Security Enhancement", "Digital Transformation", "Customer Portal"
                ]),
                "status": secrets.choice(["On Track", "At Risk", "Behind Schedule", "Ahead of Schedule"]),
                "completion_percentage": secrets.randbelow(100),
                "next_milestone": secrets.choice([
                    "Alpha Release", "Beta Testing", "User Acceptance Testing",
                    "Production Deployment", "Feature Complete", "Code Review"
                ]),
                "accomplishment_1": "Completed user interface design",
                "accomplishment_2": "Finished backend API development",
                "accomplishment_3": "Conducted security review",
                "task_1": "Begin integration testing",
                "task_2": "Prepare deployment documentation",
                "task_3": "Schedule user training sessions",
                "issues": "Minor performance optimization needed in database queries."
            }
        
        elif template_type == "security_alert":
            return {
                "alert_type": secrets.choice([
                    "Suspicious Login Activity", "Malware Detection", "Phishing Attempt",
                    "Unauthorized Access", "Data Breach Attempt", "System Vulnerability"
                ]),
                "severity": secrets.choice(["High", "Critical", "Medium"]),
                "detection_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "affected_systems": secrets.choice([
                    "Email Server", "Database Server", "Web Application",
                    "File Server", "Network Infrastructure", "User Workstations"
                ]),
                "description": "Automated security monitoring has detected suspicious activity that requires immediate attention.",
                "action_1": "Change your password immediately",
                "action_2": "Review recent account activity",
                "action_3": "Report any suspicious emails or activities"
            }
        
        elif template_type == "hr_announcement":
            return {
                "sender_name": sender_name,
                "announcement_type": secrets.choice([
                    "Policy Update", "Benefits Enrollment", "Holiday Schedule",
                    "Training Program", "Performance Review Process", "New Hire Announcement"
                ]),
                "announcement_details": "We are implementing new policies to improve workplace efficiency and employee satisfaction.",
                "effective_date": (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d"),
                "applies_to": "All employees",
                "contact_person": "HR Department"
            }
        
        elif template_type == "customer_inquiry":
            return {
                "customer_name": secrets.choice(cls.NAMES),
                "customer_company": secrets.choice(cls.COMPANIES),
                "customer_email": f"contact@{secrets.choice(['techcorp', 'dataflow', 'cloudfirst'])}.com",
                "customer_phone": f"({secrets.randbelow(900) + 100}) {secrets.randbelow(900) + 100}-{secrets.randbelow(9000) + 1000}",
                "inquiry_type": secrets.choice([
                    "Technical Support", "Billing Question", "Feature Request",
                    "Product Information", "Partnership Inquiry", "General Question"
                ]),
                "priority": secrets.choice(["High", "Medium", "Low"]),
                "customer_message": "I am interested in learning more about your services and would like to schedule a demo.",
                "response_time": secrets.choice(["24", "48", "72"])
            }
        
        elif template_type == "vendor_communication":
            return {
                "recipient_name": recipient_name,
                "sender_name": sender_name,
                "vendor_name": secrets.choice(cls.COMPANIES),
                "subject_matter": secrets.choice([
                    "Contract Renewal", "Service Update", "Billing Issue",
                    "Product Enhancement", "Support Request", "Partnership Proposal"
                ]),
                "vendor_contact": f"{secrets.choice(cls.NAMES)} <contact@vendor.com>",
                "reference_number": f"REF-{secrets.randbelow(900000) + 100000}",
                "date_received": datetime.now().strftime("%Y-%m-%d"),
                "summary": "Vendor has provided updated terms and conditions for our service agreement.",
                "action_required": "Review and approve updated contract terms",
                "deadline": (datetime.now() + timedelta(days=14)).strftime("%Y-%m-%d")
            }
        
        else:
            return {
                "sender_name": sender_name,
                "recipient_name": recipient_name
            }

class EmailHoneypot:
    """Main Email Honeypot class supporting SMTP and IMAP protocols"""
    
    def __init__(self, host: str = "0.0.0.0", smtp_port: int = 2525, imap_port: int = 1143):
        self.host = host
        self.smtp_port = smtp_port
        self.imap_port = imap_port
        
        # Generate synthetic email accounts
        self.accounts = {acc.email_address: acc for acc in SyntheticEmailGenerator.generate_email_accounts(50)}
        
        # Generate synthetic email conversations
        self._generate_email_conversations()
        
        # Session tracking
        self.sessions: Dict[str, EmailSession] = {}
        
        # Server components
        self.smtp_server = None
        self.imap_server = None
        self.smtp_thread = None
        self.imap_thread = None
    
    def _generate_email_conversations(self):
        """Generate realistic email conversations between accounts"""
        
        account_list = list(self.accounts.values())
        
        # Generate various types of emails
        for _ in range(200):  # Generate 200 emails total
            
            # Select random accounts
            from_account = secrets.choice(account_list)
            import random
            to_accounts = random.sample([acc for acc in account_list if acc != from_account], 
                                       min(secrets.randbelow(3) + 1, len(account_list) - 1))
            
            # Select email type
            email_type = secrets.choice([
                "meeting_invitation", "project_update", "security_alert",
                "hr_announcement", "customer_inquiry", "vendor_communication"
            ])
            
            # Generate email
            email_msg = SyntheticEmailGenerator.generate_email(email_type, from_account, to_accounts)
            
            # Add to sender's sent folder
            from_account.sent.append(email_msg)
            
            # Add to recipients' inboxes
            for to_account in to_accounts:
                to_account.inbox.append(email_msg)
    
    async def start(self):
        """Start the email honeypot servers"""
        try:
            # Start SMTP server
            self.smtp_thread = threading.Thread(target=self._run_smtp_server, daemon=True)
            self.smtp_thread.start()
            
            # Start IMAP server
            self.imap_thread = threading.Thread(target=self._run_imap_server, daemon=True)
            self.imap_thread.start()
            
            logger.info(f"Email Honeypot started - SMTP on {self.host}:{self.smtp_port}, IMAP on {self.host}:{self.imap_port}")
            
        except Exception as e:
            logger.error(f"Failed to start email honeypot: {e}")
            raise
    
    def _run_smtp_server(self):
        """Run SMTP server in thread"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.smtp_port))
            server_socket.listen(5)
            
            logger.info(f"SMTP server listening on {self.host}:{self.smtp_port}")
            
            while True:
                client_socket, client_addr = server_socket.accept()
                threading.Thread(
                    target=self._handle_smtp_client,
                    args=(client_socket, client_addr),
                    daemon=True
                ).start()
        
        except Exception as e:
            logger.error(f"SMTP server error: {e}")
    
    def _run_imap_server(self):
        """Run IMAP server in thread"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.imap_port))
            server_socket.listen(5)
            
            logger.info(f"IMAP server listening on {self.host}:{self.imap_port}")
            
            while True:
                client_socket, client_addr = server_socket.accept()
                threading.Thread(
                    target=self._handle_imap_client,
                    args=(client_socket, client_addr),
                    daemon=True
                ).start()
        
        except Exception as e:
            logger.error(f"IMAP server error: {e}")
    
    def _handle_smtp_client(self, client_socket: socket.socket, client_addr: Tuple[str, int]):
        """Handle SMTP client connection"""
        session_id = str(uuid.uuid4())
        
        logger.info(f"SMTP connection from {client_addr}", extra={
            "session_id": session_id,
            "ip_address": client_addr[0],
            "protocol": "smtp",
            "synthetic": True
        })
        
        try:
            # Send SMTP greeting
            client_socket.send(b"220 corptech.com ESMTP CorpTech Mail Server\r\n")
            
            authenticated = False
            username = None
            
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                
                command = data.decode('utf-8', errors='ignore').strip()
                logger.info(f"SMTP command: {command}", extra={
                    "session_id": session_id,
                    "command": command,
                    "synthetic": True
                })
                
                if command.upper().startswith('EHLO') or command.upper().startswith('HELO'):
                    response = b"250-corptech.com Hello\r\n250-AUTH PLAIN LOGIN\r\n250 OK\r\n"
                    client_socket.send(response)
                
                elif command.upper().startswith('AUTH PLAIN'):
                    # Handle AUTH PLAIN
                    if len(command.split()) > 2:
                        auth_data = command.split()[2]
                    else:
                        client_socket.send(b"334 \r\n")
                        auth_data = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
                    
                    try:
                        decoded = base64.b64decode(auth_data).decode('utf-8')
                        parts = decoded.split('\x00')
                        if len(parts) >= 3:
                            username = parts[1]
                            password = parts[2]
                            
                            # Check credentials
                            if username in self.accounts and self.accounts[username].password == password:
                                authenticated = True
                                client_socket.send(b"235 Authentication successful\r\n")
                                
                                # Log successful authentication
                                logger.info(f"SMTP auth success: {username}", extra={
                                    "session_id": session_id,
                                    "username": username,
                                    "synthetic": True
                                })
                            else:
                                client_socket.send(b"535 Authentication failed\r\n")
                                logger.info(f"SMTP auth failed: {username}", extra={
                                    "session_id": session_id,
                                    "username": username,
                                    "synthetic": True
                                })
                        else:
                            client_socket.send(b"535 Authentication failed\r\n")
                    except Exception:
                        client_socket.send(b"535 Authentication failed\r\n")
                
                elif command.upper().startswith('MAIL FROM:'):
                    if authenticated:
                        client_socket.send(b"250 OK\r\n")
                    else:
                        client_socket.send(b"530 Authentication required\r\n")
                
                elif command.upper().startswith('RCPT TO:'):
                    if authenticated:
                        client_socket.send(b"250 OK\r\n")
                    else:
                        client_socket.send(b"530 Authentication required\r\n")
                
                elif command.upper().startswith('DATA'):
                    if authenticated:
                        client_socket.send(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                        
                        # Receive email data
                        email_data = b""
                        while True:
                            line = client_socket.recv(1024)
                            email_data += line
                            if b"\r\n.\r\n" in email_data:
                                break
                        
                        # Log email sending
                        logger.info(f"SMTP email sent by {username}", extra={
                            "session_id": session_id,
                            "username": username,
                            "action": "send_email",
                            "synthetic": True
                        })
                        
                        client_socket.send(b"250 OK: Message accepted\r\n")
                    else:
                        client_socket.send(b"530 Authentication required\r\n")
                
                elif command.upper().startswith('QUIT'):
                    client_socket.send(b"221 Bye\r\n")
                    break
                
                else:
                    client_socket.send(b"500 Command not recognized\r\n")
        
        except Exception as e:
            logger.error(f"SMTP client error: {e}")
        
        finally:
            client_socket.close()
            
            # Store session data
            if username:
                session = EmailSession(
                    session_id=session_id,
                    username=username,
                    ip_address=client_addr[0],
                    protocol="smtp",
                    start_time=datetime.now(),
                    last_activity=datetime.now(),
                    email_accesses=[],
                    connection_info={"client_addr": client_addr}
                )
                self.sessions[session_id] = session
    
    def _handle_imap_client(self, client_socket: socket.socket, client_addr: Tuple[str, int]):
        """Handle IMAP client connection"""
        session_id = str(uuid.uuid4())
        
        logger.info(f"IMAP connection from {client_addr}", extra={
            "session_id": session_id,
            "ip_address": client_addr[0],
            "protocol": "imap",
            "synthetic": True
        })
        
        try:
            # Send IMAP greeting
            client_socket.send(b"* OK CorpTech IMAP Server Ready\r\n")
            
            authenticated = False
            username = None
            selected_mailbox = None
            
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                
                command_line = data.decode('utf-8', errors='ignore').strip()
                logger.info(f"IMAP command: {command_line}", extra={
                    "session_id": session_id,
                    "command": command_line,
                    "synthetic": True
                })
                
                parts = command_line.split(' ', 2)
                if len(parts) < 2:
                    continue
                
                tag = parts[0]
                command = parts[1].upper()
                args = parts[2] if len(parts) > 2 else ""
                
                if command == 'LOGIN':
                    # Parse LOGIN command
                    login_parts = args.split(' ', 1)
                    if len(login_parts) >= 2:
                        username = login_parts[0].strip('"')
                        password = login_parts[1].strip('"')
                        
                        # Check credentials
                        if username in self.accounts and self.accounts[username].password == password:
                            authenticated = True
                            response = f"{tag} OK LOGIN completed\r\n"
                            
                            logger.info(f"IMAP auth success: {username}", extra={
                                "session_id": session_id,
                                "username": username,
                                "synthetic": True
                            })
                        else:
                            response = f"{tag} NO LOGIN failed\r\n"
                            logger.info(f"IMAP auth failed: {username}", extra={
                                "session_id": session_id,
                                "username": username,
                                "synthetic": True
                            })
                    else:
                        response = f"{tag} BAD LOGIN command error\r\n"
                    
                    client_socket.send(response.encode('utf-8'))
                
                elif command == 'LIST':
                    if authenticated:
                        # List mailboxes
                        response = f'* LIST () "/" "INBOX"\r\n'
                        response += f'* LIST () "/" "Sent"\r\n'
                        response += f'* LIST () "/" "Drafts"\r\n'
                        response += f'* LIST () "/" "Deleted"\r\n'
                        response += f'{tag} OK LIST completed\r\n'
                    else:
                        response = f"{tag} NO Not authenticated\r\n"
                    
                    client_socket.send(response.encode('utf-8'))
                
                elif command == 'SELECT':
                    if authenticated:
                        mailbox = args.strip('"')
                        selected_mailbox = mailbox.upper()
                        
                        # Get message count for selected mailbox
                        account = self.accounts[username]
                        if selected_mailbox == "INBOX":
                            msg_count = len(account.inbox)
                        elif selected_mailbox == "SENT":
                            msg_count = len(account.sent)
                        elif selected_mailbox == "DRAFTS":
                            msg_count = len(account.drafts)
                        elif selected_mailbox == "DELETED":
                            msg_count = len(account.deleted)
                        else:
                            msg_count = 0
                        
                        response = f"* {msg_count} EXISTS\r\n"
                        response += f"* 0 RECENT\r\n"
                        response += f"* OK [UIDVALIDITY 1] UIDs valid\r\n"
                        response += f"{tag} OK [{selected_mailbox}] SELECT completed\r\n"
                        
                        logger.info(f"IMAP mailbox selected: {mailbox}", extra={
                            "session_id": session_id,
                            "username": username,
                            "mailbox": mailbox,
                            "synthetic": True
                        })
                    else:
                        response = f"{tag} NO Not authenticated\r\n"
                    
                    client_socket.send(response.encode('utf-8'))
                
                elif command == 'FETCH':
                    if authenticated and selected_mailbox:
                        # Simple FETCH implementation
                        account = self.accounts[username]
                        
                        if selected_mailbox == "INBOX":
                            messages = account.inbox
                        elif selected_mailbox == "SENT":
                            messages = account.sent
                        else:
                            messages = []
                        
                        # Return first message if available
                        if messages:
                            msg = messages[0]
                            response = f"* 1 FETCH (ENVELOPE (\"{msg.timestamp.strftime('%d-%b-%Y %H:%M:%S %z')}\" \"{msg.subject}\" ((\"{msg.headers.get('From', '')}\" NIL NIL NIL)) NIL NIL NIL NIL NIL) BODY[TEXT] \"{msg.body[:100]}...\")\r\n"
                            response += f"{tag} OK FETCH completed\r\n"
                        else:
                            response = f"{tag} OK FETCH completed (no messages)\r\n"
                        
                        logger.info(f"IMAP fetch messages", extra={
                            "session_id": session_id,
                            "username": username,
                            "mailbox": selected_mailbox,
                            "synthetic": True
                        })
                    else:
                        response = f"{tag} NO Not authenticated or no mailbox selected\r\n"
                    
                    client_socket.send(response.encode('utf-8'))
                
                elif command == 'LOGOUT':
                    response = f"* BYE IMAP4rev1 Server logging out\r\n{tag} OK LOGOUT completed\r\n"
                    client_socket.send(response.encode('utf-8'))
                    break
                
                else:
                    response = f"{tag} BAD Command not implemented\r\n"
                    client_socket.send(response.encode('utf-8'))
        
        except Exception as e:
            logger.error(f"IMAP client error: {e}")
        
        finally:
            client_socket.close()
            
            # Store session data
            if username:
                session = EmailSession(
                    session_id=session_id,
                    username=username,
                    ip_address=client_addr[0],
                    protocol="imap",
                    start_time=datetime.now(),
                    last_activity=datetime.now(),
                    email_accesses=[],
                    connection_info={"client_addr": client_addr}
                )
                self.sessions[session_id] = session
    
    async def stop(self):
        """Stop the email honeypot servers"""
        try:
            logger.info("Email Honeypot stopped")
        except Exception as e:
            logger.error(f"Error stopping email honeypot: {e}")
    
    def get_sessions(self) -> Dict[str, EmailSession]:
        """Get all session data for intelligence analysis"""
        return self.sessions
    
    def get_accounts(self) -> Dict[str, EmailAccount]:
        """Get all email accounts"""
        return self.accounts
    
    def get_account_emails(self, email_address: str, mailbox: str = "inbox") -> List[SyntheticEmail]:
        """Get emails for specific account and mailbox"""
        if email_address not in self.accounts:
            return []
        
        account = self.accounts[email_address]
        
        if mailbox.lower() == "inbox":
            return account.inbox
        elif mailbox.lower() == "sent":
            return account.sent
        elif mailbox.lower() == "drafts":
            return account.drafts
        elif mailbox.lower() == "deleted":
            return account.deleted
        else:
            return []

if __name__ == "__main__":
    # Example usage
    async def main():
        honeypot = EmailHoneypot()
        await honeypot.start()
        
        try:
            # Keep running
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await honeypot.stop()
    
    asyncio.run(main())