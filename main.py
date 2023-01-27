from fastapi import FastAPI
from pydantic import BaseModel
from app.routers import users
from app.routers import auth


app = FastAPI()
app.include_router(users.router)
app.include_router(auth.router)


class User(BaseModel):
    name: str
    age: int
    country: str


class Item(BaseModel):
    name: str
    description: str
    price: int


@app.post("/userinfo")
def adduser(user: User, item: Item):

    return {"userdata": user}
