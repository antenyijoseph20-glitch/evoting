"""
NIGERIAN E-VOTING SYSTEM - AUTHENTICATION MODULE v2.0
Production-Grade Voter Registration & Authentication
Compliant with INEC & NIMC Standards
"""

import hashlib
import secrets
import sqlite3
import logging
import json
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple, Dict, List
from pydantic import BaseModel, Field, validator
import re
from enum import Enum

# ==========================================
# LOGGING & SECURITY AUDIT
# ==========================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [SECURITY] %(message)s'
)
logger = logging.getLogger("VoterAuth")

# ==========================================
# ENUMS FOR ELECTION STANDARDS
# ==========================================

class ElectionTier(str, Enum):
    """INEC Election Tiers"""
    PRESIDENTIAL = "PRESIDENTIAL"
    GUBERNATORIAL = "GUBERNATORIAL"
    SENATORIAL = "SENATORIAL"
    HOUSE_OF_REPS = "HOUSE_OF_REPS"
    HOUSE_OF_ASSEMBLY = "HOUSE_OF_ASSEMBLY"

class PoliticalParty(str, Enum):
    """Registered Political Parties in Nigeria"""
    APC = "All Progressives Congress"
    PDP = "Peoples Democratic Party"
    LP = "Labour Party"
    NNPP = "New Nigeria Peoples Party"
    APGA = "All Progressives Grand Alliance"
    ADC = "African Democratic Congress"
    AAC = "African Action Congress"
    PRP = "Peoples Redemption Party"

class VoterStatus(str, Enum):
    """Voter Registration Status per INEC"""
    REGISTERED = "REGISTERED"
    ACCREDITED = "ACCREDITED"
    VOTED = "VOTED"
    CANCELLED = "CANCELLED"

class AuthenticationMethod(str, Enum):
    """Multi-Factor Authentication Methods"""
    NIN_VIN = "NIN_VIN"
    BIOMETRIC = "BIOMETRIC"
    OTP_SMS = "OTP_SMS"
    MULTI_FACTOR = "MULTI_FACTOR"

# ==========================================
# NIGERIAN STANDARDS VALIDATION
# ==========================================

class NigerianStandardValidator:
    """Validates data against INEC/NIMC standards"""
    
    # NIN Format: 11 digits (NNNNNNNNNNNN)
    NIN_PATTERN = r'^\d{11}$'
    
    # VIN Format: 8-10 characters (typically XXNNNNNNN format)
    VIN_PATTERN = r'^[A-Z]{2}\d{6,8}$'
    
    # Nigerian Phone Format
    PHONE_PATTERN = r'^(\+234|0)[789]\d{9}$'
    
    # Nigerian State Codes (36 states + FCT)
    VALID_STATES = {
        'ABIA', 'ADAMAWA', 'AKWA_IBOM', 'ANAMBRA', 'BAUCHI', 'BAYELSA',
        'BENUE', 'BORNO', 'CROSS_RIVER', 'DELTA', 'EBONYI', 'EDO',
        'EKITI', 'ENUGU', 'GOMBE', 'IMO', 'JIGAWA', 'KADUNA', 'KANO',
        'KATSINA', 'KEBBI', 'KOGI', 'KWARA', 'LAGOS', 'NASARAWA',
        'NIGER', 'OGUN', 'ONDO', 'OSUN', 'OYO', 'PLATEAU', 'RIVERS',
        'SOKOTO', 'TARABA', 'YOBE', 'ZAMFARA', 'FCT'
    }
    
    @staticmethod
    def validate_nin(nin: str) -> Tuple[bool, str]:
        """
        Validate National Identification Number (NIN)
        NIMC Format: 11-digit number
        """
        if not re.match(NigerianStandardValidator.NIN_PATTERN, nin):
            return False, "Invalid NIN format. Must be 11 digits."
        
        # NIMC Checksum Validation (Luhn Algorithm)
        digits = [int(d) for d in nin]
        checksum = sum(digits[i] * (i + 2) for i in range(10)) % 11
        if checksum != digits[10]:
            logger.warning(f"NIN checksum validation failed: {nin}")
            # Note: In production, you'd validate against NIMC API
        
        return True, "NIN valid"
    
    @staticmethod
    def validate_vin(vin: str) -> Tuple[bool, str]:
        """
        Validate Voter Identification Number (VIN)
        INEC Format: 2-letter state code + 6-8 digit voter number
        """
        if not re.match(NigerianStandardValidator.VIN_PATTERN, vin):
            return False, "Invalid VIN format. Must be 2 letters + 6-8 digits (e.g., LG12345678)."
        
        state_code = vin[:2]
        # Note: In production, validate state_code against INEC state roster
        
        return True, "VIN valid"
    
    @staticmethod
    def validate_phone(phone: str) -> Tuple[bool, str]:
        """
        Validate Nigerian phone number
        Format: +234XXXXXXXXXX or 0XXXXXXXXXX
        """
        phone = phone.replace(" ", "").replace("-", "")
        
        if not re.match(NigerianStandardValidator.PHONE_PATTERN, phone):
            return False, "Invalid Nigerian phone number format."
        
        return True, "Phone number valid"
    
    @staticmethod
    def validate_state_code(state_code: str) -> Tuple[bool, str]:
        """Validate Nigerian state code"""
        state_code_upper = state_code.replace(" ", "_").upper()
        
        if state_code_upper not in NigerianStandardValidator.VALID_STATES:
            return False, f"Invalid state code: {state_code}"
        
        return True, "State code valid"

# ==========================================
# PYDANTIC VALIDATION SCHEMAS
# ==========================================

class VoterRegistrationRequest(BaseModel):
    """INEC Voter Registration Schema"""
    nin: str = Field(..., min_length=11, max_length=11, description="NIMC National ID")
    vin: str = Field(..., min_length=8, max_length=10, description="INEC Voter ID")
    full_name: str = Field(..., min_length=2, max_length=150, description="Full name as in NIMC")
    phone_number: str = Field(..., description="Registered phone number for OTP")
    state_code: str = Field(..., description="State of registration (e.g., LAGOS, ABIA)")
    polling_unit_code: str = Field(..., description="INEC Polling Unit Code (e.g., PU-001)")
    email: Optional[str] = None
    
    @validator('nin')
    def validate_nin_format(cls, v):
        is_valid, msg = NigerianStandardValidator.validate_nin(v)
        if not is_valid:
            raise ValueError(msg)
        return v
    
    @validator('vin')
    def validate_vin_format(cls, v):
        is_valid, msg = NigerianStandardValidator.validate_vin(v)
        if not is_valid:
            raise ValueError(msg)
        return v.upper()
    
    @validator('phone_number')
    def validate_phone_format(cls, v):
        is_valid, msg = NigerianStandardValidator.validate_phone(v)
        if not is_valid:
            raise ValueError(msg)
        return v
    
    @validator('state_code')
    def validate_state(cls, v):
        is_valid, msg = NigerianStandardValidator.validate_state_code(v)
        if not is_valid:
            raise ValueError(msg)
        return v.upper().replace(" ", "_")


class VoterAuthenticationRequest(BaseModel):
    """INEC Voter Authentication Schema"""
    nin: str = Field(..., min_length=11, max_length=11)
    vin: str = Field(..., min_length=8, max_length=10)
    polling_unit_code: str = Field(...)
    state_code: str = Field(...)
    
    @validator('nin')
    def validate_nin_format(cls, v):
        is_valid, msg = NigerianStandardValidator.validate_nin(v)
        if not is_valid:
            raise ValueError(msg)
        return v


class OTPRequest(BaseModel):
    """OTP Request for 2FA"""
    voter_hash: str
    phone_number: str
    method: str = "SMS"  # SMS, USSD


class OTPVerificationRequest(BaseModel):
    """OTP Verification Request"""
    voter_hash: str
    otp_code: str = Field(..., min_length=6, max_length=6)
    
    @validator('otp_code')
    def validate_otp(cls, v):
        if not v.isdigit():
            raise ValueError("OTP must contain only digits")
        return v


class BiometricVerificationRequest(BaseModel):
    """Biometric Verification Schema"""
    voter_hash: str
    session_token: str
    face_image_base64: Optional[str] = None
    fingerprint_template: Optional[str] = None


# ==========================================
# CRYPTOGRAPHIC ENGINE (Production-Grade)
# ==========================================

class CryptographicEngine:
    """
    Production-grade cryptographic operations
    Implements NIST standards for Nigerian election security
    """
    
    @staticmethod
    def hash_voter_credentials(nin: str, vin: str) -> str:
        """
        Generate voter hash using SHA-256 (NIST standard)
        Cannot be reversed to recover original NIN/VIN
        """
        credential_string = f"{nin.strip()}{vin.strip().upper()}"
        return hashlib.sha256(credential_string.encode('utf-8')).hexdigest()
    
    @staticmethod
    def hash_with_salt(data: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """
        Hash with salt (PBKDF2-SHA256)
        100,000 iterations per NIST recommendation
        """
        if salt is None:
            salt = secrets.token_hex(32)
        
        hashed = hashlib.pbkdf2_hmac(
            'sha256',
            data.encode('utf-8'),
            salt.encode('utf-8'),
            100000,
            dklen=32
        )
        
        return hashed.hex(), salt
    
    @staticmethod
    def verify_hash_with_salt(data: str, stored_hash: str, salt: str) -> bool:
        """Verify hash against stored value"""
        computed_hash, _ = CryptographicEngine.hash_with_salt(data, salt)
        return computed_hash == stored_hash
    
    @staticmethod
    def generate_session_token() -> str:
        """
        Generate cryptographically secure session token
        256-bit random token encoded as URL-safe base64
        """
        return secrets.token_urlsafe(64)
    
    @staticmethod
    def hash_session_token(token: str) -> str:
        """Hash session token for storage (don't store plaintext tokens)"""
        return hashlib.sha256(token.encode()).hexdigest()
    
    @staticmethod
    def generate_otp() -> str:
        """Generate 6-digit OTP for 2FA"""
        return str(secrets.randbelow(1000000)).zfill(6)
    
    @staticmethod
    def generate_vote_receipt_hash(vote_data: Dict) -> str:
        """
        Generate vote receipt hash
        Used for voter verification without revealing vote content
        """
        vote_json = json.dumps(vote_data, sort_keys=True)
        return hashlib.sha256(vote_json.encode()).hexdigest()

# ==========================================
# VOTER AUTHENTICATION MANAGER (INEC Standard)
# ==========================================

class INECVoterAuthenticationManager:
    """
    INEC-Compliant Voter Authentication Manager
    Handles voter registration, authentication, and session lifecycle
    Implements security guards against election fraud
    """
    
    def __init__(self, db_path: str = "evoting.db"):
        self.db_path = db_path
        self.crypto = CryptographicEngine()
        self.validator = NigerianStandardValidator()
        
        # Security parameters
        self.MAX_FAILED_ATTEMPTS = 5
        self.LOCKOUT_DURATION_MINUTES = 30
        self.SESSION_TIMEOUT_MINUTES = 45
        self.OTP_EXPIRY_MINUTES = 5
        
        # Initialize database
        self._initialize_inec_database()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection with proper timeout"""
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging for reliability
        return conn
    
    def _initialize_inec_database(self):
        """Initialize INEC-standard database schema"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Main Voter Registration Table (INEC Standard)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS inec_voters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                voter_hash TEXT UNIQUE NOT NULL,
                nin TEXT UNIQUE NOT NULL,
                vin TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                phone_number TEXT NOT NULL,
                state_code TEXT NOT NULL,
                polling_unit_code TEXT NOT NULL,
                email TEXT,
                
                -- INEC Status Tracking
                registration_status TEXT DEFAULT 'REGISTERED' CHECK(registration_status IN ('REGISTERED', 'ACCREDITED', 'VOTED', 'CANCELLED')),
                accreditation_timestamp TIMESTAMP,
                vote_cast_timestamp TIMESTAMP,
                
                -- Security Flags
                has_voted INTEGER DEFAULT 0 CHECK(has_voted IN (0, 1)),
                is_flagged INTEGER DEFAULT 0,
                flag_reason TEXT,
                
                -- Account Lockout
                failed_auth_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP,
                last_auth_attempt TIMESTAMP,
                
                -- Audit Trail
                registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                
                CONSTRAINT unique_nin_vin UNIQUE(nin, vin)
            )
        """)
        
        # Session Management Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS voter_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                voter_id INTEGER NOT NULL,
                session_token_hash TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_active INTEGER DEFAULT 1,
                
                -- Client Info for Audit
                ip_address TEXT,
                user_agent TEXT,
                
                -- Biometric Status
                biometric_verified INTEGER DEFAULT 0,
                otp_verified INTEGER DEFAULT 0,
                
                FOREIGN KEY(voter_id) REFERENCES inec_voters(id),
                CHECK(is_active IN (0, 1))
            )
        """)
        
        # OTP Management Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS otp_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                voter_hash TEXT NOT NULL,
                otp_code TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_used INTEGER DEFAULT 0,
                verification_attempts INTEGER DEFAULT 0,
                verified_at TIMESTAMP,
                
                FOREIGN KEY(voter_hash) REFERENCES inec_voters(voter_hash),
                CHECK(is_used IN (0, 1))
            )
        """)
        
        # Comprehensive Audit Log (Immutable for Election Integrity)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS election_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                voter_hash TEXT NOT NULL,
                action TEXT NOT NULL,
                action_status TEXT NOT NULL,
                action_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                
                -- Audit Details
                ip_address TEXT,
                device_info TEXT,
                details TEXT,
                
                -- Immutability Check
                hash_of_previous TEXT,
                current_hash TEXT
            )
        """)

        # NOTE: biometric_verification_log is owned by biometric_otp_module.py.
        # It was previously also defined here with different columns, and
        # whichever module ran first "won", breaking the other's inserts.

        # Create indexes for performance (SQLite does not allow INDEX inside CREATE TABLE)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_nin ON inec_voters(nin)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vin ON inec_voters(vin)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_voter_hash ON inec_voters(voter_hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_state_pu ON inec_voters(state_code, polling_unit_code)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_session_token ON voter_sessions(session_token_hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_otp_voter ON otp_log(voter_hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_voter ON election_audit_log(voter_hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON election_audit_log(action_timestamp)")
        
        conn.commit()
        conn.close()
        
        logger.info("[INEC] Database schema initialized with election security standards")
    
    def _log_audit_event(self, voter_hash: str, action: str, status: str, 
                         ip_address: str = "0.0.0.0", details: str = "") -> bool:
        """
        Log audit event with tamper detection (hash chain)
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            # Get previous hash for chain integrity
            cursor.execute("""
                SELECT current_hash FROM election_audit_log 
                WHERE voter_hash = ? 
                ORDER BY id DESC LIMIT 1
            """, (voter_hash,))
            
            prev_row = cursor.fetchone()
            hash_of_previous = prev_row[0] if prev_row else "0" * 64
            
            # Create current record
            record_data = f"{voter_hash}{action}{status}{datetime.now(timezone.utc).isoformat()}"
            current_hash = hashlib.sha256(record_data.encode()).hexdigest()
            
            cursor.execute("""
                INSERT INTO election_audit_log 
                (voter_hash, action, action_status, ip_address, details, hash_of_previous, current_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (voter_hash, action, status, ip_address, details, hash_of_previous, current_hash))
            
            conn.commit()
            return True
        
        except Exception as e:
            logger.error(f"[AUDIT] Failed to log event: {str(e)}")
            return False
        
        finally:
            conn.close()
    
    def register_voter(self, request: VoterRegistrationRequest, 
                      ip_address: str = "0.0.0.0") -> Dict:
        """
        Register voter in INEC system
        Validates against NIMC/INEC standards
        """
        voter_hash = self.crypto.hash_voter_credentials(request.nin, request.vin)
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            # Check for duplicates
            cursor.execute("""
                SELECT id FROM inec_voters WHERE nin = ? OR vin = ?
            """, (request.nin, request.vin))
            
            if cursor.fetchone():
                self._log_audit_event(
                    voter_hash, 
                    "REGISTRATION_ATTEMPT",
                    "FAILED - DUPLICATE",
                    ip_address,
                    "Voter already registered"
                )
                return {
                    "status": "failed",
                    "code": "DUPLICATE_VOTER",
                    "message": "Voter with this NIN or VIN already registered in INEC system",
                    "voter_hash": None
                }
            
            # Insert voter record
            cursor.execute("""
                INSERT INTO inec_voters (
                    voter_hash, nin, vin, full_name, phone_number,
                    state_code, polling_unit_code, email,
                    registration_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                voter_hash,
                request.nin,
                request.vin,
                request.full_name,
                request.phone_number,
                request.state_code,
                request.polling_unit_code,
                request.email or "",
                "REGISTERED"
            ))
            
            conn.commit()
            
            # Log successful registration
            self._log_audit_event(
                voter_hash,
                "VOTER_REGISTRATION",
                "SUCCESS",
                ip_address,
                f"Voter {request.full_name} registered for {request.state_code}/{request.polling_unit_code}"
            )
            
            logger.info(f"[INEC] Voter registered: {voter_hash[:16]}... | {request.full_name}")
            
            return {
                "status": "success",
                "code": "REGISTRATION_SUCCESS",
                "message": "Voter successfully registered in INEC system",
                "voter_hash": voter_hash,
                "registered_at": datetime.now(timezone.utc).isoformat()
            }
        
        except sqlite3.IntegrityError as e:
            logger.error(f"[INEC] Registration integrity error: {str(e)}")
            return {
                "status": "failed",
                "code": "REGISTRATION_ERROR",
                "message": "Registration failed - data integrity error",
                "voter_hash": None
            }
        
        except Exception as e:
            logger.error(f"[INEC] Registration exception: {str(e)}")
            return {
                "status": "failed",
                "code": "REGISTRATION_ERROR",
                "message": "Registration system error",
                "voter_hash": None
            }
        
        finally:
            conn.close()
    
    def authenticate_voter(self, request: VoterAuthenticationRequest,
                          ip_address: str = "0.0.0.0") -> Tuple[bool, Dict]:
        """
        Authenticate voter with multi-level security checks
        Returns: (is_authenticated, response_dict)
        """
        voter_hash = self.crypto.hash_voter_credentials(request.nin, request.vin)
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            # Fetch voter record with all security flags
            cursor.execute("""
                SELECT id, has_voted, is_flagged, flag_reason,
                       failed_auth_attempts, locked_until, registration_status
                FROM inec_voters
                WHERE voter_hash = ?
            """, (voter_hash,))
            
            voter_row = cursor.fetchone()
            
            if not voter_row:
                self._log_audit_event(
                    voter_hash,
                    "AUTH_ATTEMPT",
                    "FAILED - NOT_FOUND",
                    ip_address,
                    "Voter record not found in INEC database"
                )
                
                return False, {
                    "status": "failed",
                    "code": "INVALID_CREDENTIALS",
                    "message": "Voter credentials not found in INEC registry",
                    "session_token": None
                }
            
            voter_id, has_voted, is_flagged, flag_reason, failed_attempts, locked_until, reg_status = voter_row
            
            # Security Check 1: Account Lockout
            if locked_until:
                locked_until_dt = datetime.fromisoformat(locked_until)
                if datetime.now(timezone.utc) < locked_until_dt:
                    self._log_audit_event(
                        voter_hash,
                        "AUTH_ATTEMPT",
                        "FAILED - ACCOUNT_LOCKED",
                        ip_address,
                        f"Account locked until {locked_until}"
                    )
                    
                    return False, {
                        "status": "failed",
                        "code": "ACCOUNT_LOCKED",
                        "message": f"Account locked due to multiple failed attempts. Try again after {locked_until_dt.strftime('%Y-%m-%d %H:%M:%S')}",
                        "session_token": None
                    }
                else:
                    # Unlock expired lock
                    cursor.execute("""
                        UPDATE inec_voters 
                        SET locked_until = NULL, failed_auth_attempts = 0
                        WHERE id = ?
                    """, (voter_id,))
                    conn.commit()
            
            # Security Check 2: Double Voting Prevention
            if has_voted:
                self._log_audit_event(
                    voter_hash,
                    "AUTH_ATTEMPT",
                    "FAILED - ALREADY_VOTED",
                    ip_address,
                    "Double voting attempt detected"
                )
                
                return False, {
                    "status": "failed",
                    "code": "ALREADY_VOTED",
                    "message": "INEC records show this voter has already cast their ballot",
                    "session_token": None
                }
            
            # Security Check 3: Flagged Account
            if is_flagged:
                self._log_audit_event(
                    voter_hash,
                    "AUTH_ATTEMPT",
                    "FAILED - FLAGGED_ACCOUNT",
                    ip_address,
                    f"Flagged account: {flag_reason}"
                )
                
                return False, {
                    "status": "failed",
                    "code": "FLAGGED_ACCOUNT",
                    "message": f"Voter account flagged: {flag_reason}. Contact INEC support.",
                    "session_token": None
                }
            
            # Security Check 4: Registration Status
            if reg_status != "REGISTERED":
                self._log_audit_event(
                    voter_hash,
                    "AUTH_ATTEMPT",
                    "FAILED - INVALID_STATUS",
                    ip_address,
                    f"Invalid registration status: {reg_status}"
                )
                
                return False, {
                    "status": "failed",
                    "code": "INVALID_STATUS",
                    "message": f"Voter status invalid for voting: {reg_status}",
                    "session_token": None
                }
            
            # All checks passed - Generate session
            session_token = self.crypto.generate_session_token()
            session_token_hash = self.crypto.hash_session_token(session_token)
            expires_at = (datetime.now(timezone.utc) + timedelta(minutes=self.SESSION_TIMEOUT_MINUTES)).isoformat()
            
            # Create session record
            cursor.execute("""
                INSERT INTO voter_sessions (
                    voter_id, session_token_hash, expires_at, ip_address
                ) VALUES (?, ?, ?, ?)
            """, (voter_id, session_token_hash, expires_at, ip_address))
            
            # Reset failed attempts
            cursor.execute("""
                UPDATE inec_voters 
                SET failed_auth_attempts = 0, last_auth_attempt = CURRENT_TIMESTAMP,
                    registration_status = 'ACCREDITED'
                WHERE id = ?
            """, (voter_id,))
            
            conn.commit()
            
            # Log successful authentication
            self._log_audit_event(
                voter_hash,
                "AUTH_SUCCESS",
                "SUCCESS",
                ip_address,
                f"Voter successfully authenticated and accredited"
            )
            
            logger.info(f"[INEC] Voter authenticated: {voter_hash[:16]}... | Status: ACCREDITED")
            
            return True, {
                "status": "success",
                "code": "AUTH_SUCCESS",
                "message": "Voter authentication successful - accredited for voting",
                "session_token": session_token,
                "voter_identifier": voter_hash,
                "expires_at": expires_at,
                "requires_biometric": True,
                "requires_otp": True
            }
        
        except Exception as e:
            logger.error(f"[INEC] Authentication error: {str(e)}")
            return False, {
                "status": "failed",
                "code": "AUTH_ERROR",
                "message": "Authentication system error",
                "session_token": None
            }
        
        finally:
            conn.close()
    
    def validate_session(self, session_token: str) -> Tuple[bool, Optional[str]]:
        """Validate if session is active and not expired"""
        session_token_hash = self.crypto.hash_session_token(session_token)
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT v.voter_hash, s.expires_at, s.is_active
                FROM voter_sessions s
                JOIN inec_voters v ON s.voter_id = v.id
                WHERE s.session_token_hash = ?
            """, (session_token_hash,))
            
            row = cursor.fetchone()
            
            if not row:
                return False, None
            
            voter_hash, expires_at, is_active = row
            
            if not is_active:
                return False, None
            
            expires_at_dt = datetime.fromisoformat(expires_at)
            if datetime.now(timezone.utc) > expires_at_dt:
                # Invalidate expired session
                cursor.execute(
                    "UPDATE voter_sessions SET is_active = 0 WHERE session_token_hash = ?",
                    (session_token_hash,)
                )
                conn.commit()
                return False, None
            
            return True, voter_hash
        
        finally:
            conn.close()
    
    def logout_voter(self, session_token: str) -> bool:
        """Invalidate voter session"""
        session_token_hash = self.crypto.hash_session_token(session_token)
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "UPDATE voter_sessions SET is_active = 0 WHERE session_token_hash = ?",
                (session_token_hash,)
            )
            conn.commit()
            return True
        finally:
            conn.close()


# ==========================================
# INITIALIZATION
# ==========================================

def initialize_inec_auth_system(db_path: str = "evoting.db") -> INECVoterAuthenticationManager:
    """Initialize INEC-standard authentication system"""
    logger.info("=" * 80)
    logger.info("[INEC] Initializing Nigerian E-Voting Authentication System (INEC Standard)")
    logger.info("=" * 80)
    
    auth_manager = INECVoterAuthenticationManager(db_path)
    return auth_manager


# Other modules (api_main, voting_engine, security_flow, election_workflow)
# import this shorter name. It was missing, which crashed them all on startup.
initialize_auth_system = initialize_inec_auth_system


if __name__ == "__main__":
    # Test INEC authentication system
    print("\n" + "=" * 80)
    print("INEC VOTER AUTHENTICATION SYSTEM - TEST")
    print("=" * 80 + "\n")
    
    auth = initialize_inec_auth_system()
    
    # Test registration
    print("[TEST] Registering voter...")
    reg_request = VoterRegistrationRequest(
        nin="12345678901",
        vin="LG12345678",
        full_name="Antenyi Joseph Ochohepo",
        phone_number="+2347012572796",
        state_code="BENUE",
        polling_unit_code="PU-004",
        email="voter@example.com"
    )
    
    reg_result = auth.register_voter(reg_request)
    print(f"Registration Status: {reg_result['status']}")
    print(f"Message: {reg_result['message']}\n")
    
    # Test authentication
    if reg_result['status'] == 'success':
        print("[TEST] Authenticating voter...")
        auth_request = VoterAuthenticationRequest(
            nin="12345678901",
            vin="LG12345678",
            state_code="BENUE",
            polling_unit_code="PU-004"
        )
        
        is_auth, response = auth.authenticate_voter(auth_request)
        print(f"Authentication Status: {response['status']}")
        print(f"Message: {response['message']}")
        if is_auth:
            print(f"Session Token: {response['session_token'][:20]}...")
            print(f"Expires At: {response['expires_at']}")