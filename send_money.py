
import os
import sys
import json
import base64
import hashlib
import hmac
import datetime
import logging
from typing import Dict, Optional, Tuple, Union, List
from dataclasses import dataclass
from enum import Enum

# Third-party imports
import requests
from requests.exceptions import RequestException, Timeout, ConnectionError
from pydantic import BaseModel, Field, validator
from cryptography.fernet import Fernet

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('mpesa_c2b.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# ============================================
# ENUMS AND CONSTANTS
# ============================================

class MPesaEnvironment(Enum):
    """M-Pesa API Environment"""
    SANDBOX = "sandbox"
    PRODUCTION = "production"
    
class TransactionType(Enum):
    """M-Pesa Transaction Types"""
    CUSTOMER_PAY_BILL_ONLINE = "CustomerPayBillOnline"
    CUSTOMER_BUY_GOODS_ONLINE = "CustomerBuyGoodsOnline"

class ResponseCode(Enum):
    """M-Pesa Response Codes"""
    SUCCESS = "0"
    INSUFFICIENT_BALANCE = "1"
    LESS_THAN_MINIMUM = "2"
    MORE_THAN_MAXIMUM = "3"
    SUSPENDED = "4"
    CANCELLED = "17"
    TIMEOUT = "1032"
    PROCESSING = "1037"

# ============================================
# MODELS AND DATA CLASSES
# ============================================

@dataclass
class MPesaCredentials:
    """Encapsulates M-Pesa API credentials"""
    consumer_key: str
    consumer_secret: str
    shortcode: str
    passkey: str
    initiator_name: Optional[str] = None
    security_credential: Optional[str] = None
    
class PaymentRequest(BaseModel):
    """Payment request model for validation"""
    customer_phone: str = Field(..., min_length=10, max_length=12)
    amount: float = Field(..., gt=0, le=150000)  # Max 150,000 KES
    account_reference: str = Field(..., min_length=1, max_length=12)
    transaction_desc: str = "Payment for goods/services"
    transaction_type: TransactionType = TransactionType.CUSTOMER_PAY_BILL_ONLINE
    
    @validator('customer_phone')
    def validate_phone_format(cls, v):
        """Validate and format phone number"""
        # Remove any non-digit characters
        v = ''.join(filter(str.isdigit, v))
        
        # Convert to 254 format if needed
        if v.startswith('0') and len(v) == 10:
            v = '254' + v[1:]
        elif v.startswith('7') and len(v) == 9:
            v = '254' + v
        
        if not (v.startswith('254') and len(v) == 12):
            raise ValueError('Invalid phone number format. Use 07xxxxxxxx or 2547xxxxxxxx')
        
        return v

class STKPushRequest(BaseModel):
    """STK Push request payload model"""
    BusinessShortCode: str
    Password: str
    Timestamp: str
    TransactionType: str
    Amount: str
    PartyA: str
    PartyB: str
    PhoneNumber: str
    CallBackURL: str
    AccountReference: str
    TransactionDesc: str

class STKPushResponse(BaseModel):
    """STK Push response model"""
    MerchantRequestID: str
    CheckoutRequestID: str
    ResponseCode: str
    ResponseDescription: str
    CustomerMessage: str

class CallbackMetadataItem(BaseModel):
    """Callback metadata item"""
    Name: str
    Value: Union[str, int, float]

class STKCallback(BaseModel):
    """STK Callback model"""
    ResultCode: int
    ResultDesc: str
    MerchantRequestID: Optional[str] = None
    CheckoutRequestID: Optional[str] = None
    CallbackMetadata: Optional[Dict[str, List[CallbackMetadataItem]]] = None

class MPesaCallback(BaseModel):
    """Complete M-Pesa callback model"""
    Body: Dict[str, STKCallback]

# ============================================
# CONFIGURATION MANAGEMENT
# ============================================

class MPesaConfig:
    """Configuration manager for M-Pesa API"""
    
    def __init__(self, env: MPesaEnvironment = MPesaEnvironment.SANDBOX):
        self.environment = env
        self._load_config()
        
    def _load_config(self):
        """Load configuration from environment variables"""
        self.consumer_key = os.getenv('MPESA_CONSUMER_KEY', '')
        self.consumer_secret = os.getenv('MPESA_CONSUMER_SECRET', '')
        
        if self.environment == MPesaEnvironment.SANDBOX:
            self.base_url = 'https://sandbox.safaricom.co.ke'
            self.shortcode = os.getenv('MPESA_SANDBOX_SHORTCODE', '174379')
            self.passkey = os.getenv('MPESA_SANDBOX_PASSKEY', 
                'bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919')
        else:
            self.base_url = 'https://api.safaricom.co.ke'
            self.shortcode = os.getenv('MPESA_PRODUCTION_SHORTCODE', '')
            self.passkey = os.getenv('MPESA_PRODUCTION_PASSKEY', '')
        
        self.callback_url = os.getenv('MPESA_CALLBACK_URL', '')
        self.timeout = int(os.getenv('MPESA_TIMEOUT', '30'))
        self.max_retries = int(os.getenv('MPESA_MAX_RETRIES', '3'))
        
    def validate(self) -> Tuple[bool, List[str]]:
        """Validate configuration"""
        errors = []
        
        if not self.consumer_key:
            errors.append("MPESA_CONSUMER_KEY is required")
        if not self.consumer_secret:
            errors.append("MPESA_CONSUMER_SECRET is required")
        if not self.shortcode:
            errors.append("M-Pesa shortcode is required")
        if not self.passkey:
            errors.append("M-Pesa passkey is required")
        if self.environment == MPesaEnvironment.PRODUCTION and not self.callback_url:
            errors.append("Callback URL is required for production")
            
        return len(errors) == 0, errors

# ============================================
# SECURITY UTILITIES
# ============================================

class SecurityManager:
    """Handles security-related operations"""
    
    def __init__(self, encryption_key: Optional[str] = None):
        self.encryption_key = encryption_key or os.getenv('ENCRYPTION_KEY')
        if self.encryption_key:
            self.cipher = Fernet(self.encryption_key.encode())
    
    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        if not self.cipher:
            return data
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        if not self.cipher:
            return encrypted_data
        return self.cipher.decrypt(encrypted_data.encode()).decode()
    
    def generate_signature(self, data: Dict, secret: str) -> str:
        """Generate HMAC signature for data integrity"""
        message = json.dumps(data, sort_keys=True).encode()
        signature = hmac.new(
            secret.encode(),
            message,
            hashlib.sha256
        ).hexdigest()
        return signature
    
    def validate_signature(self, data: Dict, signature: str, secret: str) -> bool:
        """Validate HMAC signature"""
        expected_signature = self.generate_signature(data, secret)
        return hmac.compare_digest(expected_signature, signature)

# ============================================
# CORE MPESA SERVICE
# ============================================

class MPesaService:
    """Main service class for M-Pesa C2B operations"""
    
    def __init__(self, config: MPesaConfig):
        self.config = config
        self.security_manager = SecurityManager()
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        # Validate configuration
        is_valid, errors = config.validate()
        if not is_valid:
            raise ValueError(f"Invalid configuration: {', '.join(errors)}")
        
        logger.info(f"M-Pesa Service initialized for {config.environment.value} environment")
    
    def _get_access_token(self) -> Optional[str]:
        """
        Retrieve access token from M-Pesa OAuth API
        Returns: Access token or None if failed
        """
        try:
            # Create authentication string
            auth_string = f"{self.config.consumer_key}:{self.config.consumer_secret}"
            auth_bytes = auth_string.encode('ascii')
            base64_auth = base64.b64encode(auth_bytes).decode('ascii')
            
            # Prepare request
            url = f"{self.config.base_url}/oauth/v1/generate"
            headers = {
                'Authorization': f'Basic {base64_auth}',
                'Cache-Control': 'no-cache'
            }
            params = {'grant_type': 'client_credentials'}
            
            logger.debug(f"Requesting access token from {url}")
            
            # Make request
            response = self.session.get(
                url,
                headers=headers,
                params=params,
                timeout=self.config.timeout
            )
            
            response.raise_for_status()
            
            data = response.json()
            access_token = data.get('access_token')
            
            if access_token:
                logger.info("Access token retrieved successfully")
                return access_token
            else:
                logger.error("No access token in response")
                return None
                
        except RequestException as e:
            logger.error(f"Failed to get access token: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response status: {e.response.status_code}")
                logger.error(f"Response body: {e.response.text}")
            return None
    
    def _generate_password(self, shortcode: str, passkey: str) -> Tuple[str, str]:
        """
        Generate Lipa Na M-Pesa Online password
        Returns: (password, timestamp) tuple
        """
        # Generate timestamp in format YYYYMMDDHHMMSS
        timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        
        # Concatenate shortcode, passkey, and timestamp
        data_string = f"{shortcode}{passkey}{timestamp}"
        
        # Encode to base64
        password_bytes = base64.b64encode(data_string.encode('utf-8'))
        password = password_bytes.decode('utf-8')
        
        logger.debug(f"Generated password with timestamp: {timestamp}")
        
        return password, timestamp
    
    def initiate_stk_push(self, payment_request: PaymentRequest) -> Dict:
        """
        Initiate STK Push to customer's phone
        Args:
            payment_request: Validated payment request
        Returns:
            Dictionary with response data
        """
        logger.info(f"Initiating STK Push for {payment_request.customer_phone}, "
                   f"Amount: {payment_request.amount}")
        
        # Get access token
        access_token = self._get_access_token()
        if not access_token:
            return {
                'success': False,
                'error': 'Failed to authenticate with M-Pesa',
                'error_code': 'AUTH_FAILED'
            }
        
        try:
            # Generate password and timestamp
            password, timestamp = self._generate_password(
                self.config.shortcode,
                self.config.passkey
            )
            
            # Prepare STK Push request payload
            stk_request = STKPushRequest(
                BusinessShortCode=self.config.shortcode,
                Password=password,
                Timestamp=timestamp,
                TransactionType=payment_request.transaction_type.value,
                Amount=str(int(payment_request.amount)),
                PartyA=payment_request.customer_phone,
                PartyB=self.config.shortcode,
                PhoneNumber=payment_request.customer_phone,
                CallBackURL=self.config.callback_url,
                AccountReference=payment_request.account_reference,
                TransactionDesc=payment_request.transaction_desc
            )
            
            # Convert to dictionary
            payload = stk_request.dict()
            
            logger.debug(f"STK Push payload: {json.dumps(payload, indent=2)}")
            
            # Prepare request headers
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            # Send STK Push request
            url = f"{self.config.base_url}/mpesa/stkpush/v1/processrequest"
            
            response = self.session.post(
                url,
                headers=headers,
                json=payload,
                timeout=self.config.timeout
            )
            
            response.raise_for_status()
            
            # Parse response
            response_data = response.json()
            stk_response = STKPushResponse(**response_data)
            
            logger.info(f"STK Push initiated successfully. "
                       f"CheckoutRequestID: {stk_response.CheckoutRequestID}")
            
            return {
                'success': True,
                'message': 'STK Push initiated successfully',
                'data': {
                    'merchant_request_id': stk_response.MerchantRequestID,
                    'checkout_request_id': stk_response.CheckoutRequestID,
                    'response_code': stk_response.ResponseCode,
                    'response_description': stk_response.ResponseDescription,
                    'customer_message': stk_response.CustomerMessage,
                    'customer_phone': payment_request.customer_phone,
                    'amount': payment_request.amount,
                    'account_reference': payment_request.account_reference,
                    'timestamp': timestamp,
                    'environment': self.config.environment.value
                }
            }
            
        except RequestException as e:
            logger.error(f"STK Push request failed: {str(e)}")
            
            error_data = {
                'success': False,
                'error': 'STK Push request failed',
                'error_type': 'REQUEST_ERROR'
            }
            
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_response = e.response.json()
                    error_data.update({
                        'error_detail': error_response.get('errorMessage', str(e)),
                        'error_code': error_response.get('errorCode', 'UNKNOWN'),
                        'request_id': error_response.get('requestId'),
                        'status_code': e.response.status_code
                    })
                except:
                    error_data['error_detail'] = e.response.text
            
            return error_data
            
        except Exception as e:
            logger.error(f"Unexpected error during STK Push: {str(e)}")
            return {
                'success': False,
                'error': 'Internal server error',
                'error_type': 'INTERNAL_ERROR',
                'error_detail': str(e)
            }
    
    def process_callback(self, callback_data: Dict) -> Dict:
        """
        Process M-Pesa callback
        Args:
            callback_data: Callback data from M-Pesa
        Returns:
            Processed callback result
        """
        try:
            # Validate callback data
            mpesa_callback = MPesaCallback(**callback_data)
            stk_callback = mpesa_callback.Body.get('stkCallback', {})
            
            logger.info(f"Processing callback with ResultCode: {stk_callback.ResultCode}")
            
            # Extract transaction details
            transaction_details = {}
            if stk_callback.CallbackMetadata and 'Item' in stk_callback.CallbackMetadata:
                for item in stk_callback.CallbackMetadata['Item']:
                    transaction_details[item.Name] = item.Value
            
            # Process based on result code
            if stk_callback.ResultCode == 0:
                # Successful transaction
                logger.info(f"Payment successful. M-Pesa Receipt: "
                          f"{transaction_details.get('MpesaReceiptNumber', 'N/A')}")
                
                return {
                    'success': True,
                    'transaction_status': 'COMPLETED',
                    'result_code': stk_callback.ResultCode,
                    'result_description': stk_callback.ResultDesc,
                    'transaction_details': transaction_details,
                    'merchant_request_id': stk_callback.MerchantRequestID,
                    'checkout_request_id': stk_callback.CheckoutRequestID,
                    'processed_at': datetime.datetime.now().isoformat()
                }
            else:
                # Failed transaction
                logger.warning(f"Payment failed. ResultCode: {stk_callback.ResultCode}, "
                             f"Description: {stk_callback.ResultDesc}")
                
                return {
                    'success': False,
                    'transaction_status': 'FAILED',
                    'result_code': stk_callback.ResultCode,
                    'result_description': stk_callback.ResultDesc,
                    'error_message': stk_callback.ResultDesc,
                    'merchant_request_id': stk_callback.MerchantRequestID,
                    'checkout_request_id': stk_callback.CheckoutRequestID,
                    'processed_at': datetime.datetime.now().isoformat()
                }
                
        except Exception as e:
            logger.error(f"Error processing callback: {str(e)}")
            return {
                'success': False,
                'error': 'Failed to process callback',
                'error_detail': str(e),
                'raw_callback': callback_data
            }
    
    def query_transaction_status(self, checkout_request_id: str) -> Dict:
        """
        Query transaction status
        Args:
            checkout_request_id: The checkout request ID from STK Push
        Returns:
            Transaction status information
        """
        logger.info(f"Querying transaction status for: {checkout_request_id}")
        
        access_token = self._get_access_token()
        if not access_token:
            return {
                'success': False,
                'error': 'Authentication failed'
            }
        
        try:
            # Generate password and timestamp
            password, timestamp = self._generate_password(
                self.config.shortcode,
                self.config.passkey
            )
            
            # Prepare query payload
            payload = {
                'BusinessShortCode': self.config.shortcode,
                'Password': password,
                'Timestamp': timestamp,
                'CheckoutRequestID': checkout_request_id
            }
            
            # Send query request
            url = f"{self.config.base_url}/mpesa/stkpushquery/v1/query"
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            response = self.session.post(
                url,
                headers=headers,
                json=payload,
                timeout=self.config.timeout
            )
            
            response.raise_for_status()
            
            query_result = response.json()
            
            logger.info(f"Transaction query result: {query_result.get('ResultDesc')}")
            
            return {
                'success': True,
                'data': query_result,
                'checkout_request_id': checkout_request_id,
                'queried_at': datetime.datetime.now().isoformat()
            }
            
        except RequestException as e:
            logger.error(f"Transaction query failed: {str(e)}")
            return {
                'success': False,
                'error': 'Transaction query failed',
                'error_detail': str(e),
                'checkout_request_id': checkout_request_id
            }
    
    def register_c2b_urls(self, confirmation_url: str, validation_url: str) -> Dict:
        """
        Register C2B URLs with M-Pesa
        Args:
            confirmation_url: URL for payment confirmations
            validation_url: URL for payment validation
        Returns:
            Registration result
        """
        logger.info(f"Registering C2B URLs: Confirmation={confirmation_url}, "
                   f"Validation={validation_url}")
        
        access_token = self._get_access_token()
        if not access_token:
            return {
                'success': False,
                'error': 'Authentication failed'
            }
        
        try:
            payload = {
                'ShortCode': self.config.shortcode,
                'ResponseType': 'Completed',
                'ConfirmationURL': confirmation_url,
                'ValidationURL': validation_url
            }
            
            url = f"{self.config.base_url}/mpesa/c2b/v1/registerurl"
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            response = self.session.post(
                url,
                headers=headers,
                json=payload,
                timeout=self.config.timeout
            )
            
            response.raise_for_status()
            
            result = response.json()
            
            logger.info(f"C2B URLs registered successfully: {result}")
            
            return {
                'success': True,
                'data': result,
                'registered_at': datetime.datetime.now().isoformat()
            }
            
        except RequestException as e:
            logger.error(f"C2B URL registration failed: {str(e)}")
            return {
                'success': False,
                'error': 'C2B URL registration failed',
                'error_detail': str(e)
            }

# ============================================
# DATABASE MODELS (SQLAlchemy Example)
# ============================================

try:
    from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Enum, Text, Boolean
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.sql import func
    
    Base = declarative_base()
    
    class Transaction(Base):
        """Database model for M-Pesa transactions"""
        __tablename__ = 'mpesa_transactions'
        
        id = Column(Integer, primary_key=True, autoincrement=True)
        merchant_request_id = Column(String(50), nullable=False, index=True)
        checkout_request_id = Column(String(50), nullable=False, unique=True, index=True)
        customer_phone = Column(String(15), nullable=False, index=True)
        amount = Column(Float, nullable=False)
        account_reference = Column(String(50), nullable=False, index=True)
        transaction_type = Column(String(50), default='CustomerPayBillOnline')
        
        # M-Pesa response fields
        mpesa_receipt_number = Column(String(50), nullable=True, index=True)
        result_code = Column(Integer, nullable=True)
        result_description = Column(Text, nullable=True)
        response_description = Column(Text, nullable=True)
        
        # Transaction metadata
        transaction_timestamp = Column(String(20), nullable=True)
        transaction_date = Column(DateTime, nullable=True)
        
        # Status tracking
        status = Column(
            Enum('PENDING', 'COMPLETED', 'FAILED', 'CANCELLED', 'TIMEOUT', 
                 name='transaction_status'),
            default='PENDING'
        )
        callback_received = Column(Boolean, default=False)
        callback_processed = Column(Boolean, default=False)
        
        # Timestamps
        created_at = Column(DateTime, server_default=func.now())
        updated_at = Column(DateTime, onupdate=func.now())
        completed_at = Column(DateTime, nullable=True)
        
        def to_dict(self):
            """Convert to dictionary"""
            return {
                'id': self.id,
                'merchant_request_id': self.merchant_request_id,
                'checkout_request_id': self.checkout_request_id,
                'customer_phone': self.customer_phone,
                'amount': self.amount,
                'account_reference': self.account_reference,
                'status': self.status,
                'mpesa_receipt_number': self.mpesa_receipt_number,
                'created_at': self.created_at.isoformat() if self.created_at else None,
                'completed_at': self.completed_at.isoformat() if self.completed_at else None
            }
    
    class DatabaseManager:
        """Manages database operations"""
        
        def __init__(self, connection_string: str):
            self.engine = create_engine(connection_string)
            self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
            
            # Create tables
            Base.metadata.create_all(bind=self.engine)
        
        def save_transaction(self, transaction_data: Dict) -> Transaction:
            """Save transaction to database"""
            session = self.SessionLocal()
            try:
                transaction = Transaction(**transaction_data)
                session.add(transaction)
                session.commit()
                session.refresh(transaction)
                return transaction
            except Exception as e:
                session.rollback()
                logger.error(f"Failed to save transaction: {str(e)}")
                raise
            finally:
                session.close()
        
        def update_transaction(self, checkout_request_id: str, update_data: Dict) -> bool:
            """Update transaction status"""
            session = self.SessionLocal()
            try:
                transaction = session.query(Transaction)\
                    .filter(Transaction.checkout_request_id == checkout_request_id)\
                    .first()
                
                if transaction:
                    for key, value in update_data.items():
                        setattr(transaction, key, value)
                    session.commit()
                    return True
                return False
            except Exception as e:
                session.rollback()
                logger.error(f"Failed to update transaction: {str(e)}")
                return False
            finally:
                session.close()
        
        def get_transaction(self, checkout_request_id: str) -> Optional[Transaction]:
            """Retrieve transaction by checkout request ID"""
            session = self.SessionLocal()
            try:
                return session.query(Transaction)\
                    .filter(Transaction.checkout_request_id == checkout_request_id)\
                    .first()
            finally:
                session.close()
        
        def get_transactions_by_phone(self, phone: str, limit: int = 100) -> List[Transaction]:
            """Get transactions for a specific phone number"""
            session = self.SessionLocal()
            try:
                return session.query(Transaction)\
                    .filter(Transaction.customer_phone == phone)\
                    .order_by(Transaction.created_at.desc())\
                    .limit(limit)\
                    .all()
            finally:
                session.close()

except ImportError:
    logger.warning("SQLAlchemy not installed. Database features disabled.")
    
    class DatabaseManager:
        """Dummy database manager when SQLAlchemy is not available"""
        def __init__(self, *args, **kwargs):
            logger.warning("Database operations disabled. Install SQLAlchemy to enable.")
        
        def save_transaction(self, *args, **kwargs):
            return None
        
        def update_transaction(self, *args, **kwargs):
            return False
        
        def get_transaction(self, *args, **kwargs):
            return None

# ============================================
# FASTAPI INTEGRATION
# ============================================

try:
    from fastapi import FastAPI, HTTPException, Depends, status, Header, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, HTMLResponse
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    import uvicorn
    
    # Create FastAPI app
    app = FastAPI(
        title="M-Pesa C2B Integration API",
        description="Complete M-Pesa Customer-to-Business Payment Integration",
        version="3.0.0",
        docs_url="/docs",
        redoc_url="/redoc"
    )
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Security
    security = HTTPBearer()
    
    # Dependency injection
    def get_mpesa_service():
        """Get M-Pesa service instance"""
        config = MPesaConfig(MPesaEnvironment.SANDBOX)
        return MPesaService(config)
    
    def get_db_manager():
        """Get database manager instance"""
        db_url = os.getenv('DATABASE_URL', 'sqlite:///mpesa.db')
        return DatabaseManager(db_url)
    
    # Routes
    @app.get("/", response_class=HTMLResponse)
    async def root():
        """Root endpoint with API documentation"""
        return """
        <html>
            <head>
                <title>M-Pesa C2B API</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; }
                    .container { max-width: 800px; margin: 0 auto; }
                    .endpoint { background: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 5px; }
                    code { background: #e0e0e0; padding: 2px 5px; border-radius: 3px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>M-Pesa C2B Integration API</h1>
                    <p>Complete Customer-to-Business payment integration</p>
                    
                    <div class="endpoint">
                        <h3>POST /api/v1/payments/request</h3>
                        <p>Initiate STK Push payment request</p>
                        <code>Content-Type: application/json</code>
                    </div>
                    
                    <div class="endpoint">
                        <h3>POST /api/v1/payments/callback</h3>
                        <p>M-Pesa callback endpoint</p>
                    </div>
                    
                    <div class="endpoint">
                        <h3>GET /api/v1/payments/status/{checkout_id}</h3>
                        <p>Check payment status</p>
                    </div>
                    
                    <p>Visit <a href="/docs">/docs</a> for interactive API documentation</p>
                </div>
            </body>
        </html>
        """
    
    @app.post("/api/v1/payments/request")
    async def request_payment(
        payment_request: PaymentRequest,
        mpesa_service: MPesaService = Depends(get_mpesa_service),
        db_manager: DatabaseManager = Depends(get_db_manager),
        authorization: HTTPAuthorizationCredentials = Depends(security)
    ):
        """
        Initiate STK Push payment request
        
        - **customer_phone**: Customer's phone number (format: 2547XXXXXXXX)
        - **amount**: Amount to pay (KES)
        - **account_reference**: Payment reference (max 12 characters)
        - **transaction_desc**: Transaction description (optional)
        """
        # Validate authorization token (basic example)
        if not authorization.credentials == os.getenv('API_TOKEN', 'default-token'):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API token"
            )
        
        # Initiate payment
        result = mpesa_service.initiate_stk_push(payment_request)
        
        if result['success']:
            # Save to database
            transaction_data = {
                'merchant_request_id': result['data']['merchant_request_id'],
                'checkout_request_id': result['data']['checkout_request_id'],
                'customer_phone': payment_request.customer_phone,
                'amount': payment_request.amount,
                'account_reference': payment_request.account_reference,
                'transaction_type': payment_request.transaction_type.value,
                'response_description': result['data']['response_description']
            }
            
            try:
                db_manager.save_transaction(transaction_data)
            except Exception as e:
                logger.error(f"Failed to save transaction to database: {str(e)}")
            
            return {
                "success": True,
                "message": result['message'],
                "data": result['data'],
                "timestamp": datetime.datetime.now().isoformat()
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get('error', 'Payment request failed'),
                headers={"X-Error-Code": result.get('error_code', 'UNKNOWN')}
            )
    
    @app.post("/api/v1/payments/callback")
    async def payment_callback(
        request: Request,
        mpesa_service: MPesaService = Depends(get_mpesa_service),
        db_manager: DatabaseManager = Depends(get_db_manager)
    ):
        """
        M-Pesa payment callback endpoint
        
        This endpoint receives payment confirmations from M-Pesa
        """
        try:
            callback_data = await request.json()
            
            # Log callback
            logger.info(f"Received callback: {json.dumps(callback_data, indent=2)}")
            
            # Process callback
            result = mpesa_service.process_callback(callback_data)
            
            if result['success']:
                # Update database
                update_data = {
                    'status': 'COMPLETED',
                    'callback_received': True,
                    'callback_processed': True,
                    'result_code': result['result_code'],
                    'result_description': result['result_description'],
                    'mpesa_receipt_number': result['transaction_details'].get('MpesaReceiptNumber'),
                    'transaction_date': datetime.datetime.now(),
                    'completed_at': datetime.datetime.now()
                }
                
                checkout_id = result.get('checkout_request_id')
                if checkout_id:
                    db_manager.update_transaction(checkout_id, update_data)
                
                # Here you can trigger business logic:
                # - Update order status
                # - Send confirmation email
                # - Update inventory
                # - Notify customer
                
                logger.info(f"Callback processed successfully for {checkout_id}")
                
            else:
                # Update failed transaction
                checkout_id = result.get('checkout_request_id')
                if checkout_id:
                    update_data = {
                        'status': 'FAILED',
                        'callback_received': True,
                        'callback_processed': True,
                        'result_code': result['result_code'],
                        'result_description': result['result_description']
                    }
                    db_manager.update_transaction(checkout_id, update_data)
            
            # Always return success to M-Pesa
            return JSONResponse(
                content={
                    "ResultCode": 0,
                    "ResultDesc": "Success"
                },
                status_code=status.HTTP_200_OK
            )
            
        except Exception as e:
            logger.error(f"Error processing callback: {str(e)}")
            return JSONResponse(
                content={
                    "ResultCode": 1,
                    "ResultDesc": f"Error: {str(e)}"
                },
                status_code=status.HTTP_200_OK
            )
    
    @app.get("/api/v1/payments/status/{checkout_request_id}")
    async def get_payment_status(
        checkout_request_id: str,
        mpesa_service: MPesaService = Depends(get_mpesa_service),
        db_manager: DatabaseManager = Depends(get_db_manager),
        authorization: HTTPAuthorizationCredentials = Depends(security)
    ):
        """
        Check payment status by checkout request ID
        """
        if not authorization.credentials == os.getenv('API_TOKEN', 'default-token'):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API token"
            )
        
        # Check database first
        transaction = db_manager.get_transaction(checkout_request_id)
        
        if not transaction:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Transaction not found"
            )
        
        # Query M-Pesa for latest status
        query_result = mpesa_service.query_transaction_status(checkout_request_id)
        
        response = {
            "transaction": transaction.to_dict() if hasattr(transaction, 'to_dict') else {},
            "mpesa_query": query_result,
            "checked_at": datetime.datetime.now().isoformat()
        }
        
        return response
    
    @app.post("/api/v1/payments/register-urls")
    async def register_urls(
        confirmation_url: str,
        validation_url: str,
        mpesa_service: MPesaService = Depends(get_mpesa_service),
        authorization: HTTPAuthorizationCredentials = Depends(security)
    ):
        """
        Register C2B URLs with M-Pesa
        """
        if not authorization.credentials == os.getenv('API_TOKEN', 'default-token'):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API token"
            )
        
        result = mpesa_service.register_c2b_urls(confirmation_url, validation_url)
        
        if result['success']:
            return result
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get('error', 'URL registration failed')
            )
    
    @app.get("/api/v1/health")
    async def health_check(
        mpesa_service:
