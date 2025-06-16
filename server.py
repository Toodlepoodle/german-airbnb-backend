from fastapi import FastAPI, APIRouter, HTTPException, Depends
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional
import uuid
from datetime import datetime, date
from passlib.context import CryptContext
import jwt
from contextlib import asynccontextmanager
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import FastAPI
import uvicorn


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    yield
    # Shutdown
    client.close()

# Create the main app without a prefix
app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
    "http://localhost:3000", 
    "https://german-airbnb-frontend.vercel.app",
    "https://*.vercel.app"
],  # React app origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# JWT Configuration
JWT_SECRET = "wunderwohn-secret-key-2025"
JWT_ALGORITHM = "HS256"
security = HTTPBearer()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Define Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str
    first_name: str
    last_name: str
    password_hash: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

class UserCreate(BaseModel):
    email: str
    first_name: str
    last_name: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class Property(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    property_type: str  # apartment, house, villa, etc.
    city: str
    state: str  # German state
    address: str
    price_per_night: float
    max_guests: int
    bedrooms: int
    bathrooms: int
    amenities: List[str]
    images: List[str]
    available: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)

class PropertyCreate(BaseModel):
    title: str
    description: str
    property_type: str
    city: str
    state: str
    address: str
    price_per_night: float
    max_guests: int
    bedrooms: int
    bathrooms: int
    amenities: List[str]
    images: List[str]

class Booking(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    property_id: str
    check_in: date
    check_out: date
    guests: int
    total_price: float
    status: str = "confirmed"  # confirmed, cancelled
    created_at: datetime = Field(default_factory=datetime.utcnow)

class BookingCreate(BaseModel):
    property_id: str
    check_in: date
    check_out: date
    guests: int

class SearchFilters(BaseModel):
    city: Optional[str] = None
    min_price: Optional[float] = None
    max_price: Optional[float] = None
    min_guests: Optional[int] = None
    property_type: Optional[str] = None
    amenities: Optional[List[str]] = None

# Auth helper functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def create_jwt_token(user_id: str) -> str:
    payload = {"user_id": user_id, "exp": datetime.utcnow().timestamp() + 86400}  # 24 hours
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = await db.users.find_one({"id": user_id})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        return User(**user)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Auth Routes
@api_router.post("/auth/register")
async def register(user_data: UserCreate):
    # Check if user exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user = User(
        email=user_data.email,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        password_hash=hash_password(user_data.password)
    )
    
    await db.users.insert_one(user.dict())
    token = create_jwt_token(user.id)
    
    return {"token": token, "user": {"id": user.id, "email": user.email, "first_name": user.first_name, "last_name": user.last_name}}

@api_router.post("/auth/login")
async def login(login_data: UserLogin):
    user = await db.users.find_one({"email": login_data.email})
    if not user or not verify_password(login_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_jwt_token(user["id"])
    return {"token": token, "user": {"id": user["id"], "email": user["email"], "first_name": user["first_name"], "last_name": user["last_name"]}}

@api_router.get("/auth/me")
async def get_me(current_user: User = Depends(get_current_user)):
    return {"id": current_user.id, "email": current_user.email, "first_name": current_user.first_name, "last_name": current_user.last_name}

# Property Routes
@api_router.get("/properties", response_model=List[Property])
async def get_properties(
    city: Optional[str] = None,
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    min_guests: Optional[int] = None,
    property_type: Optional[str] = None
):
    filter_dict = {"available": True}
    
    if city:
        filter_dict["city"] = {"$regex": city, "$options": "i"}
    if min_price:
        filter_dict["price_per_night"] = {"$gte": min_price}
    if max_price:
        if "price_per_night" in filter_dict:
            filter_dict["price_per_night"]["$lte"] = max_price
        else:
            filter_dict["price_per_night"] = {"$lte": max_price}
    if min_guests:
        filter_dict["max_guests"] = {"$gte": min_guests}
    if property_type:
        filter_dict["property_type"] = {"$regex": property_type, "$options": "i"}
    
    properties = await db.properties.find(filter_dict).to_list(100)
    return [Property(**prop) for prop in properties]

@api_router.get("/properties/{property_id}", response_model=Property)
async def get_property(property_id: str):
    property_doc = await db.properties.find_one({"id": property_id})
    if not property_doc:
        raise HTTPException(status_code=404, detail="Property not found")
    return Property(**property_doc)

@api_router.post("/properties", response_model=Property)
async def create_property(property_data: PropertyCreate):
    property_obj = Property(**property_data.dict())
    await db.properties.insert_one(property_obj.dict())
    return property_obj

# Booking Routes
@api_router.post("/bookings")
async def create_booking(booking_data: BookingCreate, current_user: User = Depends(get_current_user)):
    # Get property details
    property_doc = await db.properties.find_one({"id": booking_data.property_id})
    if not property_doc:
        raise HTTPException(status_code=404, detail="Property not found")
    
    # Calculate total price
    days = (booking_data.check_out - booking_data.check_in).days
    if days <= 0:
        raise HTTPException(status_code=400, detail="Invalid date range")
    
    total_price = days * property_doc["price_per_night"]
    
    # Create booking
    booking = Booking(
        user_id=current_user.id,
        property_id=booking_data.property_id,
        check_in=booking_data.check_in,
        check_out=booking_data.check_out,
        guests=booking_data.guests,
        total_price=total_price
    )
    
    # Convert date objects to strings for MongoDB storage
    booking_dict = booking.dict()
    booking_dict["check_in"] = booking_dict["check_in"].isoformat()
    booking_dict["check_out"] = booking_dict["check_out"].isoformat()
    
    await db.bookings.insert_one(booking_dict)
    return {"success": True, "booking_id": booking.id, "total_price": total_price}

@api_router.get("/bookings")
async def get_user_bookings(current_user: User = Depends(get_current_user)):
    # For admin users, return all bookings
    if current_user.email == "admin@wunderwohn.com":
        bookings = await db.bookings.find().to_list(1000)
    else:
        # For regular users, return only their bookings
        bookings = await db.bookings.find({"user_id": current_user.id}).to_list(100)
    
    print(f"Found {len(bookings)} bookings for user {current_user.email}")
    
    # Get property details for each booking
    result = []
    for booking in bookings:
        # Remove MongoDB _id field which is not JSON serializable
        if "_id" in booking:
            del booking["_id"]
        
        print(f"Processing booking {booking.get('id')} for property {booking.get('property_id')}")
        
        property_doc = await db.properties.find_one({"id": booking["property_id"]})
        if property_doc:
            if "_id" in property_doc:
                del property_doc["_id"]
            print(f"Found property: {property_doc.get('title')} in {property_doc.get('city')}")
        else:
            print(f"WARNING: Property not found for property_id: {booking['property_id']}")
            
        booking_with_property = {
            **booking,
            "property": property_doc
        }
        result.append(booking_with_property)
    
    return result

@api_router.delete("/bookings/{booking_id}")
async def delete_booking(booking_id: str, current_user: User = Depends(get_current_user)):
    # Find the booking
    booking = await db.bookings.find_one({"id": booking_id})
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    
    # Check if user owns the booking or is admin
    if booking["user_id"] != current_user.id and current_user.email != "admin@wunderwohn.com":
        raise HTTPException(status_code=403, detail="Not authorized to delete this booking")
    
    # Delete the booking
    result = await db.bookings.delete_one({"id": booking_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Booking not found")
    
    return {"success": True, "message": "Booking deleted successfully"}

# Initialize sample data with 12 properties
@api_router.post("/init-data")
async def initialize_sample_data():
    # Check if data already exists
    existing_properties = await db.properties.count_documents({})
    if existing_properties > 0:
        return {"message": "Sample data already exists"}
    
    # German cities and sample properties (expanded to 12)
    sample_properties = [
        {
            "title": "Charming Apartment in Berlin Mitte",
            "description": "Beautiful 2-bedroom apartment in the heart of Berlin with modern amenities and great transport links. Perfect for exploring the city's rich history and vibrant culture.",
            "property_type": "apartment",
            "city": "Berlin",
            "state": "Berlin",
            "address": "Alexanderplatz 1, 10178 Berlin",
            "price_per_night": 120.0,
            "max_guests": 4,
            "bedrooms": 2,
            "bathrooms": 1,
            "amenities": ["WiFi", "Kitchen", "Washing Machine", "TV", "Air Conditioning"],
            "images": [
                "https://images.unsplash.com/photo-1703698800457-da754d6f454f",
                "https://images.unsplash.com/photo-1583847268964-b28dc8f51f92",
                "https://images.pexels.com/photos/1454806/pexels-photo-1454806.jpeg"
            ]
        },
        {
            "title": "Historic House in Munich Old Town",
            "description": "Traditional Bavarian house with authentic architecture, perfect for experiencing Munich's culture. Located near Marienplatz with easy access to beer gardens and museums.",
            "property_type": "house",
            "city": "Munich",
            "state": "Bavaria",
            "address": "Marienplatz 5, 80331 Munich",
            "price_per_night": 200.0,
            "max_guests": 6,
            "bedrooms": 3,
            "bathrooms": 2,
            "amenities": ["WiFi", "Kitchen", "Garden", "Parking", "Fireplace"],
            "images": [
                "https://images.unsplash.com/photo-1670145867818-1fbbbd12e800",
                "https://images.unsplash.com/photo-1556911220-bff31c812dba",
                "https://images.unsplash.com/photo-1615874959474-d609969a20ed"
            ]
        },
        {
            "title": "Modern Riverside Apartment in Hamburg",
            "description": "Contemporary apartment with stunning views of Hamburg's canals and modern amenities. Close to the historic Speicherstadt and HafenCity district.",
            "property_type": "apartment",
            "city": "Hamburg",
            "state": "Hamburg",
            "address": "HafenCity 10, 20457 Hamburg",
            "price_per_night": 150.0,
            "max_guests": 3,
            "bedrooms": 1,
            "bathrooms": 1,
            "amenities": ["WiFi", "Kitchen", "River View", "TV", "Balcony"],
            "images": [
                "https://images.pexels.com/photos/31838667/pexels-photo-31838667.png",
                "https://images.pexels.com/photos/1080721/pexels-photo-1080721.jpeg",
                "https://images.unsplash.com/photo-1665249934445-1de680641f50"
            ]
        },
        {
            "title": "Cozy Canal House in Cologne",
            "description": "Beautiful traditional house along Cologne's historic canals with authentic German charm. Walking distance to the famous Cologne Cathedral.",
            "property_type": "house",
            "city": "Cologne",
            "state": "North Rhine-Westphalia",
            "address": "Rheinauhafen 15, 50678 Cologne",
            "price_per_night": 180.0,
            "max_guests": 5,
            "bedrooms": 2,
            "bathrooms": 2,
            "amenities": ["WiFi", "Kitchen", "Canal View", "Parking", "Pet Friendly"],
            "images": [
                "https://images.pexels.com/photos/2773415/pexels-photo-2773415.jpeg",
                "https://images.unsplash.com/photo-1632057254608-5f9b14e37444",
                "https://images.pexels.com/photos/1454806/pexels-photo-1454806.jpeg"
            ]
        },
        {
            "title": "Luxury Apartment in Frankfurt Financial District",
            "description": "High-end apartment in Frankfurt's business district with panoramic city views and premium amenities. Perfect for business travelers and luxury seekers.",
            "property_type": "apartment",
            "city": "Frankfurt",
            "state": "Hesse",
            "address": "Zeil 50, 60313 Frankfurt am Main",
            "price_per_night": 250.0,
            "max_guests": 4,
            "bedrooms": 2,
            "bathrooms": 2,
            "amenities": ["WiFi", "Kitchen", "City View", "Gym Access", "Concierge", "Air Conditioning"],
            "images": [
                "https://images.unsplash.com/photo-1649006613961-26e0c7aa581a",
                "https://images.unsplash.com/photo-1583847268964-b28dc8f51f92",
                "https://images.unsplash.com/photo-1556911220-bff31c812dba"
            ]
        },
        {
            "title": "Charming Villa in Stuttgart Hills",
            "description": "Elegant villa in Stuttgart's hills with beautiful garden and city views, perfect for a luxurious stay. Close to Mercedes-Benz and Porsche museums.",
            "property_type": "villa",
            "city": "Stuttgart",
            "state": "Baden-Württemberg",
            "address": "Königstraße 25, 70173 Stuttgart",
            "price_per_night": 300.0,
            "max_guests": 8,
            "bedrooms": 4,
            "bathrooms": 3,
            "amenities": ["WiFi", "Kitchen", "Garden", "Pool", "Parking", "City View"],
            "images": [
                "https://images.unsplash.com/photo-1726334487986-6f90bfa9e87a",
                "https://images.unsplash.com/photo-1615874959474-d609969a20ed",
                "https://images.pexels.com/photos/1080721/pexels-photo-1080721.jpeg"
            ]
        },
        {
            "title": "Elegant Loft in Dresden Historic Center",
            "description": "Stylish loft apartment in Dresden's beautifully restored historic center. Experience the baroque architecture and cultural heritage of this magnificent city.",
            "property_type": "loft",
            "city": "Dresden",
            "state": "Saxony",
            "address": "Neumarkt 8, 01067 Dresden",
            "price_per_night": 140.0,
            "max_guests": 3,
            "bedrooms": 1,
            "bathrooms": 1,
            "amenities": ["WiFi", "Kitchen", "Historic View", "TV", "Heating"],
            "images": [
                "https://images.pexels.com/photos/11114194/pexels-photo-11114194.jpeg",
                "https://images.unsplash.com/photo-1583847268964-b28dc8f51f92",
                "https://images.unsplash.com/photo-1665249934445-1de680641f50"
            ]
        },
        {
            "title": "Seaside Apartment in Kiel Baltic Coast",
            "description": "Bright apartment overlooking the Baltic Sea in Kiel. Perfect for sailing enthusiasts and those seeking coastal tranquility in northern Germany.",
            "property_type": "apartment",
            "city": "Kiel",
            "state": "Schleswig-Holstein",
            "address": "Kiellinie 20, 24105 Kiel",
            "price_per_night": 110.0,
            "max_guests": 4,
            "bedrooms": 2,
            "bathrooms": 1,
            "amenities": ["WiFi", "Kitchen", "Sea View", "Balcony", "Beach Access"],
            "images": [
                "https://images.unsplash.com/photo-1632057254608-5f9b14e37444",
                "https://images.pexels.com/photos/1080721/pexels-photo-1080721.jpeg",
                "https://images.unsplash.com/photo-1615874959474-d609969a20ed"
            ]
        },
        {
            "title": "Mountain Chalet in Garmisch-Partenkirchen",
            "description": "Authentic Alpine chalet with breathtaking mountain views near the Zugspitze. Perfect for hiking, skiing, and experiencing Bavarian mountain culture.",
            "property_type": "chalet",
            "city": "Garmisch-Partenkirchen",
            "state": "Bavaria",
            "address": "Alpspitzstraße 12, 82467 Garmisch-Partenkirchen",
            "price_per_night": 220.0,
            "max_guests": 6,
            "bedrooms": 3,
            "bathrooms": 2,
            "amenities": ["WiFi", "Kitchen", "Mountain View", "Fireplace", "Ski Storage", "Garden"],
            "images": [
                "https://images.unsplash.com/photo-1726334487986-6f90bfa9e87a",
                "https://images.unsplash.com/photo-1703698800457-da754d6f454f",
                "https://images.unsplash.com/photo-1556911220-bff31c812dba"
            ]
        },
        {
            "title": "Industrial Loft in Düsseldorf Art Quarter",
            "description": "Contemporary converted warehouse loft in Düsseldorf's trendy art district. Modern design meets industrial heritage in this unique space.",
            "property_type": "loft",
            "city": "Düsseldorf",
            "state": "North Rhine-Westphalia",
            "address": "Königsallee 100, 40212 Düsseldorf",
            "price_per_night": 170.0,
            "max_guests": 4,
            "bedrooms": 2,
            "bathrooms": 1,
            "amenities": ["WiFi", "Kitchen", "Art Gallery Access", "TV", "Air Conditioning", "Workspace"],
            "images": [
                "https://images.unsplash.com/photo-1649006613961-26e0c7aa581a",
                "https://images.unsplash.com/photo-1665249934445-1de680641f50",
                "https://images.pexels.com/photos/1454806/pexels-photo-1454806.jpeg"
            ]
        },
        {
            "title": "Historic Townhouse in Heidelberg Old Town",
            "description": "Beautifully preserved 16th-century townhouse in romantic Heidelberg. Experience medieval charm with modern comforts near the famous castle.",
            "property_type": "townhouse",
            "city": "Heidelberg",
            "state": "Baden-Württemberg",
            "address": "Hauptstraße 45, 69117 Heidelberg",
            "price_per_night": 190.0,
            "max_guests": 5,
            "bedrooms": 3,
            "bathrooms": 2,
            "amenities": ["WiFi", "Kitchen", "Historic Charm", "Castle View", "Garden", "Parking"],
            "images": [
                "https://images.unsplash.com/photo-1670145867818-1fbbbd12e800",
                "https://images.pexels.com/photos/2773415/pexels-photo-2773415.jpeg",
                "https://images.unsplash.com/photo-1632057254608-5f9b14e37444"
            ]
        },
        {
            "title": "Modern Penthouse in Leipzig City Center",
            "description": "Stunning penthouse apartment in Leipzig's vibrant city center. Enjoy panoramic views and easy access to the city's famous music venues and cultural sites.",
            "property_type": "penthouse",
            "city": "Leipzig",
            "state": "Saxony",
            "address": "Augustusplatz 15, 04109 Leipzig",
            "price_per_night": 280.0,
            "max_guests": 6,
            "bedrooms": 3,
            "bathrooms": 2,
            "amenities": ["WiFi", "Kitchen", "Panoramic View", "Rooftop Terrace", "Elevator", "Premium Appliances"],
            "images": [
                "https://images.pexels.com/photos/11114194/pexels-photo-11114194.jpeg",
                "https://images.unsplash.com/photo-1583847268964-b28dc8f51f92",
                "https://images.pexels.com/photos/1080721/pexels-photo-1080721.jpeg"
            ]
        }
    ]
    
    # Create properties
    for prop_data in sample_properties:
        property_obj = Property(**prop_data)
        await db.properties.insert_one(property_obj.dict())
    
    # Create admin user
    admin_user = User(
        email="admin@wunderwohn.com",
        first_name="Admin",
        last_name="User",
        password_hash=hash_password("admin123")
    )
    
    # Check if admin already exists
    existing_admin = await db.users.find_one({"email": "admin@wunderwohn.com"})
    if not existing_admin:
        await db.users.insert_one(admin_user.dict())
    
    return {"message": f"Initialized {len(sample_properties)} sample properties and admin user"}

# Force refresh data endpoint
@api_router.post("/refresh-data")
async def refresh_sample_data(current_user: User = Depends(get_current_user)):
    # Only allow admin to refresh data
    if current_user.email != "admin@wunderwohn.com":
        raise HTTPException(status_code=403, detail="Only admin can refresh data")
    
    # Get existing bookings
    existing_bookings = await db.bookings.find({}).to_list(length=None)
    booked_property_ids = set(booking["property_id"] for booking in existing_bookings)
    
    # Get existing properties that have bookings
    existing_properties = await db.properties.find({"id": {"$in": list(booked_property_ids)}}).to_list(length=None)
    existing_property_ids = set(prop["id"] for prop in existing_properties)
    
    # Delete only properties that don't have bookings
    await db.properties.delete_many({"id": {"$nin": list(existing_property_ids)}})
    
    # German cities and sample properties (12 properties)
    sample_properties = [
        {
            "title": "Charming Apartment in Berlin Mitte",
            "description": "Beautiful 2-bedroom apartment in the heart of Berlin with modern amenities and great transport links. Perfect for exploring the city's rich history and vibrant culture.",
            "property_type": "apartment",
            "city": "Berlin",
            "state": "Berlin",
            "address": "Alexanderplatz 1, 10178 Berlin",
            "price_per_night": 120.0,
            "max_guests": 4,
            "bedrooms": 2,
            "bathrooms": 1,
            "amenities": ["WiFi", "Kitchen", "Washing Machine", "TV", "Air Conditioning"],
            "images": [
                "https://images.unsplash.com/photo-1703698800457-da754d6f454f",
                "https://images.unsplash.com/photo-1583847268964-b28dc8f51f92",
                "https://images.pexels.com/photos/1454806/pexels-photo-1454806.jpeg"
            ]
        },
        {
            "title": "Historic House in Munich Old Town",
            "description": "Traditional Bavarian house with authentic architecture, perfect for experiencing Munich's culture. Located near Marienplatz with easy access to beer gardens and museums.",
            "property_type": "house",
            "city": "Munich",
            "state": "Bavaria",
            "address": "Marienplatz 5, 80331 Munich",
            "price_per_night": 200.0,
            "max_guests": 6,
            "bedrooms": 3,
            "bathrooms": 2,
            "amenities": ["WiFi", "Kitchen", "Garden", "Parking", "Fireplace"],
            "images": [
                "https://images.unsplash.com/photo-1670145867818-1fbbbd12e800",
                "https://images.unsplash.com/photo-1556911220-bff31c812dba",
                "https://images.unsplash.com/photo-1615874959474-d609969a20ed"
            ]
        },
        {
            "title": "Modern Riverside Apartment in Hamburg",
            "description": "Contemporary apartment with stunning views of Hamburg's canals and modern amenities. Close to the historic Speicherstadt and HafenCity district.",
            "property_type": "apartment",
            "city": "Hamburg",
            "state": "Hamburg",
            "address": "HafenCity 10, 20457 Hamburg",
            "price_per_night": 150.0,
            "max_guests": 3,
            "bedrooms": 1,
            "bathrooms": 1,
            "amenities": ["WiFi", "Kitchen", "River View", "TV", "Balcony"],
            "images": [
                "https://images.pexels.com/photos/31838667/pexels-photo-31838667.png",
                "https://images.pexels.com/photos/1080721/pexels-photo-1080721.jpeg",
                "https://images.unsplash.com/photo-1665249934445-1de680641f50"
            ]
        },
        {
            "title": "Cozy Canal House in Cologne",
            "description": "Beautiful traditional house along Cologne's historic canals with authentic German charm. Walking distance to the famous Cologne Cathedral.",
            "property_type": "house",
            "city": "Cologne",
            "state": "North Rhine-Westphalia",
            "address": "Rheinauhafen 15, 50678 Cologne",
            "price_per_night": 180.0,
            "max_guests": 5,
            "bedrooms": 2,
            "bathrooms": 2,
            "amenities": ["WiFi", "Kitchen", "Canal View", "Parking", "Pet Friendly"],
            "images": [
                "https://images.pexels.com/photos/2773415/pexels-photo-2773415.jpeg",
                "https://images.unsplash.com/photo-1632057254608-5f9b14e37444",
                "https://images.pexels.com/photos/1454806/pexels-photo-1454806.jpeg"
            ]
        },
        {
            "title": "Luxury Apartment in Frankfurt Financial District",
            "description": "High-end apartment in Frankfurt's business district with panoramic city views and premium amenities. Perfect for business travelers and luxury seekers.",
            "property_type": "apartment",
            "city": "Frankfurt",
            "state": "Hesse",
            "address": "Zeil 50, 60313 Frankfurt am Main",
            "price_per_night": 250.0,
            "max_guests": 4,
            "bedrooms": 2,
            "bathrooms": 2,
            "amenities": ["WiFi", "Kitchen", "City View", "Gym Access", "Concierge", "Air Conditioning"],
            "images": [
                "https://images.unsplash.com/photo-1649006613961-26e0c7aa581a",
                "https://images.unsplash.com/photo-1583847268964-b28dc8f51f92",
                "https://images.unsplash.com/photo-1556911220-bff31c812dba"
            ]
        },
        {
            "title": "Charming Villa in Stuttgart Hills",
            "description": "Elegant villa in Stuttgart's hills with beautiful garden and city views, perfect for a luxurious stay. Close to Mercedes-Benz and Porsche museums.",
            "property_type": "villa",
            "city": "Stuttgart",
            "state": "Baden-Württemberg",
            "address": "Königstraße 25, 70173 Stuttgart",
            "price_per_night": 300.0,
            "max_guests": 8,
            "bedrooms": 4,
            "bathrooms": 3,
            "amenities": ["WiFi", "Kitchen", "Garden", "Pool", "Parking", "City View"],
            "images": [
                "https://images.unsplash.com/photo-1726334487986-6f90bfa9e87a",
                "https://images.unsplash.com/photo-1615874959474-d609969a20ed",
                "https://images.pexels.com/photos/1080721/pexels-photo-1080721.jpeg"
            ]
        },
        {
            "title": "Elegant Loft in Dresden Historic Center",
            "description": "Stylish loft apartment in Dresden's beautifully restored historic center. Experience the baroque architecture and cultural heritage of this magnificent city.",
            "property_type": "loft",
            "city": "Dresden",
            "state": "Saxony",
            "address": "Neumarkt 8, 01067 Dresden",
            "price_per_night": 140.0,
            "max_guests": 3,
            "bedrooms": 1,
            "bathrooms": 1,
            "amenities": ["WiFi", "Kitchen", "Historic View", "TV", "Heating"],
            "images": [
                "https://images.pexels.com/photos/11114194/pexels-photo-11114194.jpeg",
                "https://images.unsplash.com/photo-1583847268964-b28dc8f51f92",
                "https://images.unsplash.com/photo-1665249934445-1de680641f50"
            ]
        },
        {
            "title": "Seaside Apartment in Kiel Baltic Coast",
            "description": "Bright apartment overlooking the Baltic Sea in Kiel. Perfect for sailing enthusiasts and those seeking coastal tranquility in northern Germany.",
            "property_type": "apartment",
            "city": "Kiel",
            "state": "Schleswig-Holstein",
            "address": "Kiellinie 20, 24105 Kiel",
            "price_per_night": 110.0,
            "max_guests": 4,
            "bedrooms": 2,
            "bathrooms": 1,
            "amenities": ["WiFi", "Kitchen", "Sea View", "Balcony", "Beach Access"],
            "images": [
                "https://images.unsplash.com/photo-1632057254608-5f9b14e37444",
                "https://images.pexels.com/photos/1080721/pexels-photo-1080721.jpeg",
                "https://images.unsplash.com/photo-1615874959474-d609969a20ed"
            ]
        },
        {
            "title": "Mountain Chalet in Garmisch-Partenkirchen",
            "description": "Authentic Alpine chalet with breathtaking mountain views near the Zugspitze. Perfect for hiking, skiing, and experiencing Bavarian mountain culture.",
            "property_type": "chalet",
            "city": "Garmisch-Partenkirchen",
            "state": "Bavaria",
            "address": "Alpspitzstraße 12, 82467 Garmisch-Partenkirchen",
            "price_per_night": 220.0,
            "max_guests": 6,
            "bedrooms": 3,
            "bathrooms": 2,
            "amenities": ["WiFi", "Kitchen", "Mountain View", "Fireplace", "Ski Storage", "Garden"],
            "images": [
                "https://images.unsplash.com/photo-1726334487986-6f90bfa9e87a",
                "https://images.unsplash.com/photo-1703698800457-da754d6f454f",
                "https://images.unsplash.com/photo-1556911220-bff31c812dba"
            ]
        },
        {
            "title": "Industrial Loft in Düsseldorf Art Quarter",
            "description": "Contemporary converted warehouse loft in Düsseldorf's trendy art district. Modern design meets industrial heritage in this unique space.",
            "property_type": "loft",
            "city": "Düsseldorf",
            "state": "North Rhine-Westphalia",
            "address": "Königsallee 100, 40212 Düsseldorf",
            "price_per_night": 170.0,
            "max_guests": 4,
            "bedrooms": 2,
            "bathrooms": 1,
            "amenities": ["WiFi", "Kitchen", "Art Gallery Access", "TV", "Air Conditioning", "Workspace"],
            "images": [
                "https://images.unsplash.com/photo-1649006613961-26e0c7aa581a",
                "https://images.unsplash.com/photo-1665249934445-1de680641f50",
                "https://images.pexels.com/photos/1454806/pexels-photo-1454806.jpeg"
            ]
        },
        {
            "title": "Historic Townhouse in Heidelberg Old Town",
            "description": "Beautifully preserved 16th-century townhouse in romantic Heidelberg. Experience medieval charm with modern comforts near the famous castle.",
            "property_type": "townhouse",
            "city": "Heidelberg",
            "state": "Baden-Württemberg",
            "address": "Hauptstraße 45, 69117 Heidelberg",
            "price_per_night": 190.0,
            "max_guests": 5,
            "bedrooms": 3,
            "bathrooms": 2,
            "amenities": ["WiFi", "Kitchen", "Historic Charm", "Castle View", "Garden", "Parking"],
            "images": [
                "https://images.unsplash.com/photo-1670145867818-1fbbbd12e800",
                "https://images.pexels.com/photos/2773415/pexels-photo-2773415.jpeg",
                "https://images.unsplash.com/photo-1632057254608-5f9b14e37444"
            ]
        },
        {
            "title": "Modern Penthouse in Leipzig City Center",
            "description": "Stunning penthouse apartment in Leipzig's vibrant city center. Enjoy panoramic views and easy access to the city's famous music venues and cultural sites.",
            "property_type": "penthouse",
            "city": "Leipzig",
            "state": "Saxony",
            "address": "Augustusplatz 15, 04109 Leipzig",
            "price_per_night": 280.0,
            "max_guests": 6,
            "bedrooms": 3,
            "bathrooms": 2,
            "amenities": ["WiFi", "Kitchen", "Panoramic View", "Rooftop Terrace", "Elevator", "Premium Appliances"],
            "images": [
                "https://images.pexels.com/photos/11114194/pexels-photo-11114194.jpeg",
                "https://images.unsplash.com/photo-1583847268964-b28dc8f51f92",
                "https://images.pexels.com/photos/1080721/pexels-photo-1080721.jpeg"
            ]
        }
    ]
    
    # Create all properties
    for prop_data in sample_properties:
        property_obj = Property(**prop_data)
        await db.properties.insert_one(property_obj.dict())
    
    # Create admin user if not exists
    admin_user = User(
        email="admin@wunderwohn.com",
        first_name="Admin",
        last_name="User",
        password_hash=hash_password("admin123")
    )
    
    existing_admin = await db.users.find_one({"email": "admin@wunderwohn.com"})
    if not existing_admin:
        await db.users.insert_one(admin_user.dict())
    
    return {"message": f"Successfully refreshed data with {len(sample_properties)} properties and admin user"}

# General routes
@api_router.get("/")
async def root():
    return {"message": "WunderWohn API"}

# Include the router in the main app
app.include_router(api_router)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)

# Add this at the very end of server.py
from fastapi import Request

# Handler for Vercel
def handler(request: Request):
    return app(request.scope, request.receive, request.send)

# Export for Vercel
app_handler = handler

