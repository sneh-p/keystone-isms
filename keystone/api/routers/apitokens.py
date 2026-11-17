"""Personal API tokens. Managed with a browser session only (tokens can't manage tokens)."""

from fastapi import APIRouter, Depends
from pydantic import Field
from sqlalchemy.orm import Session

from keystone.apitokens import service as tk

from ..deps import get_db, perm
from ..serialize import ser
from .common import In

router = APIRouter(prefix="/tokens", tags=["api-tokens"])
TOKEN = ("id", "user_id", "name", "scope", "created_at", "expires_at", "revoked_at", "last_used_at", "last_used_ip")


@router.get("")
def tokens(all: bool = False, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return [ser(t, TOKEN) for t in tk.tokens(db, user, everyone=all)]


class TokenIn(In):
    name: str = Field(min_length=1, max_length=100)
    scope: str = Field(default="read", pattern="^(read|write)$")
    days: int = Field(default=90, ge=1, le=365)


@router.post("")
def create(body: TokenIn, user=Depends(perm("read")), db: Session = Depends(get_db)):
    t, raw = tk.create(db, user, body.name, body.scope, body.days)
    return {**ser(t, TOKEN), "token": raw}  # shown once


@router.post("/{tid}/revoke")
def revoke(tid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return ser(tk.revoke(db, user, tid), TOKEN)
