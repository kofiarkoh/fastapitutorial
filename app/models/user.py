from pydantic import BaseModel
from typing import Union


class User(BaseModel):
    username: str
    email: Union[str, None] = None
    full_name: Union[str, None] = None
    disabled: Union[str, None] = None


class UserInDB(User):
    hashed_password: str
