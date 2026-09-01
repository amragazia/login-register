from pydantic import BaseModel, Field


class User(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9@_.-]+$")
    password: str = Field(min_length=8, max_length=128)


class UserUpdate(BaseModel):
    username: str | None = Field(
        default=None, min_length=3, max_length=50, pattern=r"^[A-Za-z0-9@_.-]+$"
    )
    password: str | None = Field(default=None, min_length=8, max_length=128)
