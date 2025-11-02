from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, Header
from fastapi.responses import StreamingResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
from passlib.context import CryptContext
import jwt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64
import hashlib
import random
import io

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "your-secret-key-for-jwt-token-generation-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI()
api_router = APIRouter(prefix="/api")

logger = logging.getLogger(__name__)

# ========== MODELS ==========

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    role: str = "user"  # "admin" or "user"

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class OTPVerify(BaseModel):
    email: EmailStr
    otp: str

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    full_name: str
    role: str
    password_hash: str
    public_key: str
    private_key: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class FileMetadata(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    filename: str
    original_hash: str
    encrypted_data: str  # Base64 encoded
    encrypted_key: str  # AES key encrypted with RSA
    owner_id: str
    owner_email: str
    size: int
    shared_with: List[str] = []  # List of user emails
    uploaded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AccessLog(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_email: str
    action: str
    file_id: Optional[str] = None
    filename: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# ========== SECURITY UTILITIES ==========

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def generate_rsa_keypair():
    """Generate RSA key pair for each user"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_pem, public_pem

def encrypt_file_aes(file_data: bytes) -> tuple:
    """Encrypt file with AES-256 and return encrypted data + key"""
    aes_key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)  # Initialization vector
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad data to be multiple of 16 bytes
    padding_length = 16 - (len(file_data) % 16)
    padded_data = file_data + bytes([padding_length]) * padding_length
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Combine IV and encrypted data
    combined = iv + encrypted_data
    
    return base64.b64encode(combined).decode('utf-8'), base64.b64encode(aes_key).decode('utf-8')

def decrypt_file_aes(encrypted_data_b64: str, aes_key_b64: str) -> bytes:
    """Decrypt AES encrypted file"""
    combined = base64.b64decode(encrypted_data_b64)
    iv = combined[:16]
    encrypted_data = combined[16:]
    aes_key = base64.b64decode(aes_key_b64)
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Remove padding
    padding_length = padded_data[-1]
    return padded_data[:-padding_length]

def encrypt_key_rsa(aes_key: str, public_key_pem: str) -> str:
    """Encrypt AES key with RSA public key"""
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=default_backend()
    )
    
    encrypted_key = public_key.encrypt(
        base64.b64decode(aes_key),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return base64.b64encode(encrypted_key).decode('utf-8')

def decrypt_key_rsa(encrypted_key: str, private_key_pem: str) -> str:
    """Decrypt AES key with RSA private key"""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    decrypted_key = private_key.decrypt(
        base64.b64decode(encrypted_key),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return base64.b64encode(decrypted_key).decode('utf-8')

def compute_file_hash(file_data: bytes) -> str:
    """Compute SHA-256 hash for file integrity"""
    return hashlib.sha256(file_data).hexdigest()

def generate_otp() -> str:
    """Generate 6-digit OTP"""
    return str(random.randint(100000, 999999))

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = await db.users.find_one({"email": email}, {"_id": 0})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

async def log_action(user_email: str, action: str, file_id: str = None, filename: str = None):
    log_entry = AccessLog(
        user_email=user_email,
        action=action,
        file_id=file_id,
        filename=filename
    )
    doc = log_entry.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    await db.access_logs.insert_one(doc)

# ========== AUTH ENDPOINTS ==========

@api_router.post("/auth/register")
async def register(user_data: UserRegister):
    # Check if user exists
    existing = await db.users.find_one({"email": user_data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Generate RSA keys
    private_key, public_key = generate_rsa_keypair()
    
    # Create user
    user = User(
        email=user_data.email,
        full_name=user_data.full_name,
        role=user_data.role,
        password_hash=hash_password(user_data.password),
        public_key=public_key,
        private_key=private_key
    )
    
    doc = user.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.users.insert_one(doc)
    
    await log_action(user.email, "User registered")
    
    return {"message": "User registered successfully", "email": user.email, "role": user.role}

@api_router.post("/auth/login")
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email}, {"_id": 0})
    if not user or not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Generate OTP
    otp = generate_otp()
    
    # Store OTP in database (expires in 5 minutes)
    await db.otp_codes.delete_many({"email": credentials.email})  # Clear old OTPs
    await db.otp_codes.insert_one({
        "email": credentials.email,
        "otp": otp,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    })
    
    # In production, send email here. For demo, log it
    logger.info(f"OTP for {credentials.email}: {otp}")
    
    await log_action(user["email"], "Login attempt - OTP sent")
    
    return {
        "message": "OTP sent to your email",
        "email": credentials.email,
        "otp_for_demo": otp  # Remove in production
    }

@api_router.post("/auth/verify-otp")
async def verify_otp(verification: OTPVerify):
    otp_record = await db.otp_codes.find_one({"email": verification.email})
    
    if not otp_record:
        raise HTTPException(status_code=400, detail="No OTP found. Please login again.")
    
    # Check expiration
    expires_at = datetime.fromisoformat(otp_record["expires_at"])
    if datetime.now(timezone.utc) > expires_at:
        await db.otp_codes.delete_one({"email": verification.email})
        raise HTTPException(status_code=400, detail="OTP expired. Please login again.")
    
    # Verify OTP
    if otp_record["otp"] != verification.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    # Delete OTP after successful verification
    await db.otp_codes.delete_one({"email": verification.email})
    
    # Get user
    user = await db.users.find_one({"email": verification.email}, {"_id": 0})
    
    # Create JWT token
    token = create_access_token({"sub": user["email"], "role": user["role"]})
    
    await log_action(user["email"], "Login successful")
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"]
        }
    }

@api_router.post("/auth/resend-otp")
async def resend_otp(data: dict):
    email = data.get("email")
    user = await db.users.find_one({"email": email}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Generate new OTP
    otp = generate_otp()
    
    await db.otp_codes.delete_many({"email": email})
    await db.otp_codes.insert_one({
        "email": email,
        "otp": otp,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    })
    
    logger.info(f"OTP for {email}: {otp}")
    
    return {"message": "OTP resent", "otp_for_demo": otp}

# ========== FILE ENDPOINTS ==========

@api_router.post("/files/upload")
async def upload_file(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    # Read file
    file_data = await file.read()
    
    # Compute hash for integrity
    file_hash = compute_file_hash(file_data)
    
    # Encrypt file with AES-256
    encrypted_data, aes_key = encrypt_file_aes(file_data)
    
    # Encrypt AES key with user's RSA public key
    encrypted_key = encrypt_key_rsa(aes_key, current_user["public_key"])
    
    # Store in database
    file_metadata = FileMetadata(
        filename=file.filename,
        original_hash=file_hash,
        encrypted_data=encrypted_data,
        encrypted_key=encrypted_key,
        owner_id=current_user["id"],
        owner_email=current_user["email"],
        size=len(file_data)
    )
    
    doc = file_metadata.model_dump()
    doc['uploaded_at'] = doc['uploaded_at'].isoformat()
    await db.files.insert_one(doc)
    
    await log_action(current_user["email"], "File uploaded", file_metadata.id, file.filename)
    
    return {
        "message": "File uploaded and encrypted successfully",
        "file_id": file_metadata.id,
        "filename": file.filename,
        "hash": file_hash
    }

@api_router.get("/files/list")
async def list_files(current_user: dict = Depends(get_current_user)):
    # Get files owned by user or shared with user
    files = await db.files.find(
        {
            "$or": [
                {"owner_email": current_user["email"]},
                {"shared_with": current_user["email"]}
            ]
        },
        {"_id": 0, "encrypted_data": 0, "encrypted_key": 0, "private_key": 0}
    ).to_list(1000)
    
    return {"files": files}

@api_router.get("/files/download/{file_id}")
async def download_file(file_id: str, current_user: dict = Depends(get_current_user)):
    # Get file
    file_doc = await db.files.find_one({"id": file_id}, {"_id": 0})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")
    
    # Check access
    if file_doc["owner_email"] != current_user["email"] and current_user["email"] not in file_doc.get("shared_with", []):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Decrypt AES key with user's RSA private key
    aes_key = decrypt_key_rsa(file_doc["encrypted_key"], current_user["private_key"])
    
    # Decrypt file
    decrypted_data = decrypt_file_aes(file_doc["encrypted_data"], aes_key)
    
    # Verify integrity
    current_hash = compute_file_hash(decrypted_data)
    if current_hash != file_doc["original_hash"]:
        raise HTTPException(status_code=500, detail="File integrity check failed")
    
    await log_action(current_user["email"], "File downloaded", file_id, file_doc["filename"])
    
    return StreamingResponse(
        io.BytesIO(decrypted_data),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={file_doc['filename']}"}
    )

@api_router.delete("/files/delete/{file_id}")
async def delete_file(file_id: str, current_user: dict = Depends(get_current_user)):
    file_doc = await db.files.find_one({"id": file_id}, {"_id": 0})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")
    
    # Only owner or admin can delete
    if file_doc["owner_email"] != current_user["email"] and current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    await db.files.delete_one({"id": file_id})
    await log_action(current_user["email"], "File deleted", file_id, file_doc["filename"])
    
    return {"message": "File deleted successfully"}

@api_router.post("/files/share/{file_id}")
async def share_file(
    file_id: str,
    data: dict,
    current_user: dict = Depends(get_current_user)
):
    share_with_email = data.get("email")
    
    file_doc = await db.files.find_one({"id": file_id}, {"_id": 0})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")
    
    # Only owner can share
    if file_doc["owner_email"] != current_user["email"]:
        raise HTTPException(status_code=403, detail="Only owner can share files")
    
    # Check if target user exists
    target_user = await db.users.find_one({"email": share_with_email})
    if not target_user:
        raise HTTPException(status_code=404, detail="Target user not found")
    
    # Add to shared list
    if share_with_email not in file_doc.get("shared_with", []):
        await db.files.update_one(
            {"id": file_id},
            {"$push": {"shared_with": share_with_email}}
        )
    
    await log_action(current_user["email"], f"File shared with {share_with_email}", file_id, file_doc["filename"])
    
    return {"message": f"File shared with {share_with_email}"}

# ========== ADMIN ENDPOINTS ==========

@api_router.get("/admin/users")
async def get_all_users(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    users = await db.users.find(
        {},
        {"_id": 0, "password_hash": 0, "private_key": 0, "public_key": 0}
    ).to_list(1000)
    
    return {"users": users}

@api_router.get("/admin/logs")
async def get_access_logs(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    logs = await db.access_logs.find({}, {"_id": 0}).sort("timestamp", -1).to_list(1000)
    
    return {"logs": logs}

@api_router.get("/admin/stats")
async def get_stats(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    total_users = await db.users.count_documents({})
    total_files = await db.files.count_documents({})
    total_logs = await db.access_logs.count_documents({})
    
    return {
        "total_users": total_users,
        "total_files": total_files,
        "total_logs": total_logs
    }

# ========== ROOT ==========

@api_router.get("/")
async def root():
    return {"message": "SecureShare API - File Sharing with AES-256 & RSA Encryption"}

# Include router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()