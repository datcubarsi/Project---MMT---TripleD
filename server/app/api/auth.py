"""Xác thực phụ huynh: đăng ký, đăng nhập, đăng xuất, đổi mật khẩu.

Cơ chế:
- Mật khẩu băm Argon2id (passlib), tối thiểu 10 ký tự.
- Khóa tài khoản 15 phút sau 5 lần sai; giới hạn tần suất theo IP.
- Phiên lưu phía máy chủ (cookie chỉ giữ token ngẫu nhiên): HttpOnly, Secure, SameSite=Lax, hạn 12 giờ.
- CSRF: token gắn với phiên, client gửi lại qua header X-CSRF-Token cho mọi thao tác ghi.
- Mọi sự kiện quan trọng đều ghi audit (không ghi mật khẩu).
"""
import secrets
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db, utcnow
from app.models.user import AuthSession, Role, User
from app.security.deps import (
    client_ip,
    get_current_session,
    get_current_user,
    hash_token,
    require_csrf,
)
from app.security.passwords import burn_time, hash_password, needs_rehash, verify_password
from app.security.rate_limit import rate_limit
from app.services.audit import write_audit

router = APIRouter(prefix="/auth", tags=["auth"])


# ---------- Schemas ----------

def _check_password_strength(password: str, email: str | None = None) -> str:
    if len(password) < settings.min_password_length:
        raise ValueError(f"Mật khẩu phải có ít nhất {settings.min_password_length} ký tự.")
    if len(password) > settings.max_password_length:
        raise ValueError("Mật khẩu quá dài.")
    if email and email.split("@")[0].lower() in password.lower():
        raise ValueError("Mật khẩu không được chứa phần tên của email.")
    if password.isdigit() or len(set(password)) < 4:
        raise ValueError("Mật khẩu quá đơn giản.")
    return password


class RegisterIn(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=100)
    password: str

    @field_validator("password")
    @classmethod
    def _pw(cls, v, info):
        return _check_password_strength(v, str(info.data.get("email", "")))


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(max_length=settings.max_password_length)


class ChangePasswordIn(BaseModel):
    current_password: str = Field(max_length=settings.max_password_length)
    new_password: str

    @field_validator("new_password")
    @classmethod
    def _pw(cls, v):
        return _check_password_strength(v)


class UserOut(BaseModel):
    id: str
    email: str
    full_name: str
    role: str

    model_config = {"from_attributes": True}


class LoginOut(BaseModel):
    user: UserOut
    csrf_token: str


# ---------- Helpers ----------

def _open_session(db: Session, user: User, response: Response) -> AuthSession:
    """Mỗi lần đăng nhập tạo token mới (chống session fixation) và dọn phiên đã hết hạn của user."""
    now = utcnow()
    db.execute(delete(AuthSession).where(AuthSession.user_id == user.id, AuthSession.expires_at <= now))

    token = secrets.token_urlsafe(32)
    sess = AuthSession(
        token_hash=hash_token(token),
        csrf_token=secrets.token_urlsafe(32),
        user_id=user.id,
        expires_at=now + timedelta(hours=settings.session_ttl_hours),
    )
    db.add(sess)
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        max_age=settings.session_ttl_hours * 3600,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )
    return sess


def _login_failed() -> HTTPException:
    # Thông báo chung cho mọi nguyên nhân (sai email, sai mật khẩu, đang bị khóa) để không lộ tài khoản có tồn tại hay không.
    return HTTPException(status.HTTP_401_UNAUTHORIZED, "Email hoặc mật khẩu không đúng, hoặc tài khoản đang tạm khóa.")


# ---------- Endpoints ----------

@router.post(
    "/register",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("register", settings.register_rate))],
)
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    email = body.email.lower()
    user = User(
        email=email,
        full_name=body.full_name.strip(),
        password_hash=hash_password(body.password),
        role=Role.parent.value,  # đăng ký công khai luôn là parent; không cho client tự chọn vai trò
    )
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Email này đã được đăng ký.")
    write_audit(db, action="auth.register", ip=client_ip(request), actor_id=user.id, target=user.id)
    db.commit()
    return user


@router.post(
    "/login",
    response_model=LoginOut,
    dependencies=[Depends(rate_limit("login", settings.login_rate))],
)
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    ip = client_ip(request)
    now = utcnow()
    user = db.scalar(select(User).where(User.email == body.email.lower()))

    if user is None:
        burn_time(body.password)
        write_audit(db, action="auth.login_failed", ip=ip, new={"reason": "unknown_email"})
        db.commit()
        raise _login_failed()

    if user.locked_until and user.locked_until > now:
        burn_time(body.password)
        write_audit(db, action="auth.login_blocked_locked", ip=ip, actor_id=user.id)
        db.commit()
        raise _login_failed()

    if not verify_password(body.password, user.password_hash):
        user.failed_attempts += 1
        write_audit(db, action="auth.login_failed", ip=ip, actor_id=user.id, new={"reason": "bad_password"})
        if user.failed_attempts >= settings.max_failed_logins:
            user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
            user.failed_attempts = 0
            write_audit(
                db, action="auth.account_locked", ip=ip, actor_id=user.id,
                new={"locked_until": user.locked_until.isoformat()},
            )
        db.commit()
        raise _login_failed()

    # Thành công
    user.failed_attempts = 0
    user.locked_until = None
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
    sess = _open_session(db, user, response)
    write_audit(db, action="auth.login", ip=ip, actor_id=user.id)
    db.commit()
    return LoginOut(user=UserOut.model_validate(user), csrf_token=sess.csrf_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    sess: AuthSession = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    # Hủy phiên phía máy chủ: cookie cũ có bị đánh cắp cũng vô dụng
    write_audit(db, action="auth.logout", ip=client_ip(request), actor_id=sess.user_id)
    db.delete(db.merge(sess))
    db.commit()
    response.delete_cookie(settings.session_cookie_name, path="/")
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


@router.get("/csrf")
def csrf(sess: AuthSession = Depends(get_current_session)):
    """Dashboard gọi khi tải lại trang để lấy lại CSRF token của phiên hiện tại."""
    return {"csrf_token": sess.csrf_token}


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    body: ChangePasswordIn,
    request: Request,
    sess: AuthSession = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    user = db.get(User, sess.user_id)
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Mật khẩu hiện tại không đúng.")
    if verify_password(body.new_password, user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Mật khẩu mới phải khác mật khẩu cũ.")

    user.password_hash = hash_password(body.new_password)
    # Thu hồi mọi phiên khác; chỉ giữ phiên hiện tại
    db.execute(delete(AuthSession).where(AuthSession.user_id == user.id, AuthSession.id != sess.id))
    # Chỉ ghi sự kiện, tuyệt đối không ghi giá trị mật khẩu hay hash
    write_audit(db, action="auth.password_changed", ip=client_ip(request), actor_id=user.id, target=user.id)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)