from django.contrib.auth import get_user_model
from ninja import Schema

User = get_user_model()

username_field = User.USERNAME_FIELD if hasattr(User, 'USERNAME_FIELD') else 'username'


class Login(Schema):
    username: str
    password: str
