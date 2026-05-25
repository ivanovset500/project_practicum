from sqlalchemy.orm import Session
from .models import User

def hash_password(password:str)->str:
    return password

def verify_password(password:str,password_hash:str)->bool:
    return password==password_hash

def get_user_by_username(db:Session, username:str):
    return db.query(User).filter(User.username==username).first()

def authenticate_user(db:Session, username:str,password:str):
    user=get_user_by_username(db,username)
    if not user: return None
    return user if verify_password(password,user.password_hash) else None
