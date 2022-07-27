from fastapi import FastAPI, HTTPException, Depends, status
from mongita import MongitaClientDisk
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from typing import Union
from datetime import datetime, timedelta
from passlib.context import CryptContext

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "bc56d27a4022b93b7d1c09e49f4308a7dc5c7a36a7cb6d45565f080c5e00af11"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# comunicate types to mongita nad fast API
class Card(BaseModel):
    name: str
    no_of_mana: int
    id: int

# deck = [
#     {"card_name": "Guf", "no_of_mana": 5, "id": 1},
#     {"card_name": "Bran", "no_of_mana": 5, "id": 2},
#     {"card_name": "Onyxia", "no_of_mana": 9, "id": 3},
# ]

# Hashing passwords mechanism
pwd_context = CryptContext(schemes=['bcrypt'], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "$2b$12$FSjTE5SWCl/5PkonuYI2HuIRYINxqQWdCNIU3upuJ4xoW2qk5avNe",
        "disabled": False,
    },
}

# will be used in the token endpoint for the response
class Token(BaseModel):
    access_token: str
    token_type: str


app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def authenticate_user(fake_users_db, username: str, password: str):
    user = get_user(fake_users_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

client = MongitaClientDisk()
db = client.db
deck = db.deck

# def fake_hash_password(password: str):
#     return "fakehashed" + password



class User(BaseModel):
    username: str
    email: Union[str, None] = None
    full_name: Union[str, None] = None
    disabled: Union[bool, None] = None


class UserInDB(User):
    hashed_password: str


def fake_decode_token(token):
    # This doesn't provide any security at all
    # Check the next version
    user = get_user(fake_users_db, token)
    return user


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


class TokenData(BaseModel):
    username: str | None = None


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={'WWW-Authenticate': "Bearer"}
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub") # sub -> subject of the token (here is the user but can be antyhinh)
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)): # Dependency injection
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


# create real JWT access token adn return it
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes = ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


# @app.post("/token")
# async def login(form_data: OAuth2PasswordRequestForm = Depends()):
#     user_dict = fake_users_db.get(form_data.username)
#     if not user_dict:
#         raise HTTPException(status_code=400, detail="Incorrect username or password")
#     user = UserInDB(**user_dict)
#     hashed_password = fake_hash_password(form_data.password)
#     if not hashed_password == user.hashed_password:
#         raise HTTPException(status_code=400, detail="Incorrect username or password")
#
#     return {"access_token": user.username, "token_type": "bearer"}


@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.get("/items/")
async def read_items(token: str = Depends(oauth2_scheme)):
    return {"token": token}

@app.get("/")
async def root():
    return {"message": "Hello world"}

@app.get("/deck")
async def get_deck(current_user: User = Depends(get_current_active_user)):
    current_deck = deck.find({})
    return [
        {key: card[key] for key in card if key != "_id"} for card in current_deck
    ]

@app.get("/deck/{card_id}")
async def get_card_by_id(card_id: int):
    if deck.count_documents({"id": card_id}) > 0: # check number of documents
        card = deck.find_one({"id": card_id})
        return {key:deck[key] for key in deck if key != "_id"} # klucza _id dokumentu w mongo db nie da sie latwo json serializowac
    raise HTTPException(status_code=404, detail=f"No card with id {card_id}")


@app.post('/deck')
async def post_card(card: Card, current_user: User = Depends(get_current_active_user)):
    deck.insert_one(card.dict())
    return card


@app.put("/deck/{card_id}")
async def update_card(card_id: int, card: Card, current_user: User = Depends(get_current_active_user)):
    if deck.count_documents({"id": card_id}) > 0: # count doc -> zwraca liczbę dokumentów spełniających kryteria "id"
        deck.replace_one({"id": card_id}, card.dict())
        return card
    raise HTTPException(status_code=404, detail=f"No card with id {card_id} found")


@app.put("/deck/upsert/{card_id}")
async def update_card(card_id: int, card: Card):
        deck.replace_one({"id": card_id}, card.dict(), upsert = True)
        return card


@app.delete("/deck/{card_id}")
async def delete_card(card_id: int):
    delte_result = deck.delete_one({"id": card_id})
    if delte_result.deleted_count == 0:
        raise HTTPException(status_code=404, detail=f"No card with id {card_id} exists")
    return {"Ok"}



