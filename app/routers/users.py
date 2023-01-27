from fastapi import APIRouter

router = APIRouter()


@router.get("/users", tags=['users'])
def getAllUsers():
    return "this is all users"
