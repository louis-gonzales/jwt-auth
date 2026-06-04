from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from models import UserCreate, UserLogin, UserOut
from auth import (
    fake_users_db,
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
)

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

@app.post("/signup", response_model=UserOut)
def signup(user: UserCreate):
    if user.username in fake_users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    fake_users_db[user.username] = hash_password(user.password)
    return UserOut(username=user.username)

@app.post("/login")
def login(user: UserLogin):
    stored = fake_users_db.get(user.username)
    if not stored or not verify_password(user.password, stored):
        raise HTTPException(status_code=401, detail="Invalid Credentials")
    
    access_token = create_access_token(subject=user.username)
    return {"access_token": access_token, "token_type": "bearer"}

def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    username = decode_access_token(token)
    if not username or username not in fake_users_db:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return username

@app.get("/me", response_model=UserOut)
def read_me(current_user: str = Depends(get_current_user)):
    return UserOut(username=current_user)

