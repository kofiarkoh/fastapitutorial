from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from ..models import User, UserInDB
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel
from typing import Union
from datetime import timedelta, datetime

router = APIRouter()

SECRET_KEY = '7e55f48cc06684df06fea949a71ed14fc1acd14198d0fa93b1a396321524750c'
ALGORITHYM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "fakehashedsecret",
        "disabled": False,
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "fakehashedsecret2",
        "disabled": True,
    },
}

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=5)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHYM)

    return encoded_jwt


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False

    if not verify_password(password, user.hashed_password):
        return False

    return user


# tokenUrl is the url the client will use to submit username and password
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')


def fake_hash_password(password: str):
    return "fakehashed" + password


def fake_decode_token(token):
    return User(
        username=token + "fakedecoded", email="john@example.com", full_name="John Doe"
    )

# creates a get user dependency


async def get_current_user(token: str = Depends(oauth2_scheme)):

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate credentials',
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHYM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)

    except JWTError:
        raise credentials_exception

    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if(current_user.disabled):
        raise HTTPException(400, "Your accounnt is inactive")
    return current_user


@router.get('/items', tags=['items'])
async def read_items(token: str = Depends(oauth2_scheme)):
    return {'token': token}


@router.get('/users/me')
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@router.post('/token')
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=404, detail="User not found")

    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(
            status_code=400, detail='Your password is incorrect')

    return {"access_token": user.username, "tokenn_type": "bearer"}
