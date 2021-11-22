from datetime import datetime, timedelta
from typing import Optional
import json

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

SECRET_KEY = "95be5a51fa29a6cf400f4e60684b0594bb77260916151c09a7fd39613316cc4b"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

dummy_user = {
    "zarfanpr": {
        "username": "zarfanpr",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    },
    "asdf": {
        "username": "asdf",
        "hashed_password": "$2b$12$ozaFLkFGK59YlwU/wOQU..0dpBQGCb5tceg1PJEEXMnQxnOCmZz6q",
        "disabled": False,
    }
}

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

with open("booking.json","r") as read_file:
	data=json.load(read_file)
app = FastAPI()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(dummy_user, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

@app.get("/", tags=["Initiate"])
async def Nama_NIM():
    return("Nama: Zarfa Naida P, NIM: 18219014, Silahkan buka: http://zarfanpr-tst2.herokuapp.com/docs")

@app.post("/token", response_model=Token, tags=["Initiate"])
async def login_untuk_akes_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(dummy_user, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model=User, tags=["Initiate"])
async def Data_User(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.get('/booking', tags=["Booking"])
async def read_all_booking(current_user: User = Depends(get_current_active_user)):
    return data

@app.get('/booking/{nama_reviewer}', tags=["Booking"])
async def read_booking_by_reviewer(nama_reviewer:str, current_user: User = Depends(get_current_active_user)):
	for menu_item in data['booking']:
		if menu_item['nama_reviewer']==nama_reviewer:
			return menu_item
	raise HTTPException(
		status_code=404,detail=f'Item not found'
	)

@app.put('/booking/{id_booking}', tags=["Booking"])
async def choose_booking(id_booking:int,nama_reviewer:str,current_user: User = Depends(get_current_active_user)):
    listmenu=[]
    for menu_item in data['booking']:
        if menu_item['id_booking']==id_booking:
            menu_item['nama_reviewer']=nama_reviewer
        listmenu.append(menu_item)
    data['booking']=listmenu
    with open('booking.json', 'w') as tambahdata:
        json.dump(data, tambahdata)
    return data


