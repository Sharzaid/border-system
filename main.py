# -*- coding: utf-8 -*-
"""
نظام التواصل في المنفذ
الجوازات | الجمارك | سلاح الحدود
"""

from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional
import os
import secrets

# ==================== إعدادات ====================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data", "border.db")
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
SESSION_EXPIRE_HOURS = 12  # مدة الجلسة بالساعات

os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)

# ==================== قاعدة البيانات ====================
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    full_name = Column(String(100), nullable=False)
    hashed_password = Column(String(200), nullable=False)
    department = Column(String(50), default="")  # الجوازات / الجمارك / سلاح الحدود
    is_admin = Column(Boolean, default=False)
    can_create = Column(Boolean, default=False)       # يسجل حالات جديدة
    can_edit_status = Column(Boolean, default=False)  # يعدل الحالة فقط
    can_edit_all = Column(Boolean, default=False)     # يعدل كل الحقول
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Case(Base):
    __tablename__ = "cases"
    id = Column(Integer, primary_key=True, index=True)
    case_number = Column(String(30), unique=True, index=True)
    person_name = Column(String(150), nullable=False)
    passport_id = Column(String(50), nullable=False)
    nationality = Column(String(50), default="")
    movement_type = Column(String(20), nullable=False)  # قدوم / مغادرة
    registered_by_dept = Column(String(50), nullable=False)
    registered_by_user = Column(String(50), nullable=False)
    reason = Column(String(300), default="")
    status = Column(String(50), default="قيد الإجراء")  # تم الإعادة / قيد الإجراء / لم تتم / محول / أخرى
    notes_jawazat = Column(Text, default="")
    notes_gamarik = Column(Text, default="")
    notes_border = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = Column(String(50), default="")

Base.metadata.create_all(bind=engine)

# ==================== التطبيق ====================
app = FastAPI(title="نظام المنفذ")
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

# تخزين الجلسات في الذاكرة (بسيط وكافي للعدد المتوسط)
sessions = {}  # token -> {user_id, expires}

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    sessions[token] = {
        "user_id": user_id,
        "expires": datetime.utcnow() + timedelta(hours=SESSION_EXPIRE_HOURS)
    }
    return token

def get_current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    token = request.cookies.get("session_token")
    if not token or token not in sessions:
        return None
    sess = sessions[token]
    if datetime.utcnow() > sess["expires"]:
        del sessions[token]
        return None
    user = db.query(User).filter(User.id == sess["user_id"], User.is_active == True).first()
    return user

def require_login(user: Optional[User]):
    if not user:
        raise HTTPException(status_code=303, headers={"Location": "/login"})

def require_admin(user: Optional[User]):
    require_login(user)
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="غير مصرح")

# ==================== إنشاء المدير الافتراضي ====================
def init_admin():
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            admin = User(
                username="admin",
                full_name="مدير النظام",
                hashed_password=hash_password("Admin@123"),
                department="الإدارة",
                is_admin=True,
                can_create=True,
                can_edit_status=True,
                can_edit_all=True,
                is_active=True
            )
            db.add(admin)
            db.commit()
            print("✅ تم إنشاء حساب المدير: admin / Admin@123")
    finally:
        db.close()

init_admin()

# ==================== الصفحات ====================

@app.get("/", response_class=HTMLResponse)
async def home(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return RedirectResponse("/cases", status_code=303)

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if user:
        return RedirectResponse("/cases", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "اسم المستخدم أو كلمة المرور غير صحيحة"
        })
    token = create_session(user.id)
    response = RedirectResponse("/cases", status_code=303)
    response.set_cookie(
        key="session_token",
        value=token,
        httponly=True,
        max_age=SESSION_EXPIRE_HOURS * 3600,
        samesite="lax"
    )
    return response

@app.get("/logout")
async def logout(request: Request):
    token = request.cookies.get("session_token")
    if token and token in sessions:
        del sessions[token]
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("session_token")
    return response

# ---------- الحالات ----------
@app.get("/cases", response_class=HTMLResponse)
async def cases_list(request: Request, db: Session = Depends(get_db), q: str = "", status_filter: str = ""):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    query = db.query(Case).order_by(Case.created_at.desc())
    if q:
        query = query.filter(
            (Case.person_name.contains(q)) |
            (Case.passport_id.contains(q)) |
            (Case.case_number.contains(q))
        )
    if status_filter:
        query = query.filter(Case.status == status_filter)

    cases = query.limit(200).all()
    return templates.TemplateResponse("cases.html", {
        "request": request,
        "user": user,
        "cases": cases,
        "q": q,
        "status_filter": status_filter
    })

@app.get("/cases/new", response_class=HTMLResponse)
async def case_new_form(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not (user.can_create or user.is_admin):
        return templates.TemplateResponse("error.html", {
            "request": request, "user": user, "message": "ليس لديك صلاحية تسجيل حالات جديدة"
        })
    return templates.TemplateResponse("case_form.html", {
        "request": request,
        "user": user,
        "case": None,
        "mode": "create"
    })

@app.post("/cases/new")
async def case_create(
    request: Request,
    person_name: str = Form(...),
    passport_id: str = Form(...),
    nationality: str = Form(""),
    movement_type: str = Form(...),
    reason: str = Form(""),
    status: str = Form("قيد الإجراء"),
    notes: str = Form(""),
    db: Session = Depends(get_db)
):
    user = get_current_user(request, db)
    if not user or not (user.can_create or user.is_admin):
        raise HTTPException(status_code=403)

    # رقم حالة تلقائي
    today = datetime.now().strftime("%Y%m%d")
    last = db.query(Case).filter(Case.case_number.like(f"{today}%")).count()
    case_number = f"{today}-{last + 1:03d}"

    notes_j = notes if user.department == "الجوازات" else ""
    notes_g = notes if user.department == "الجمارك" else ""
    notes_b = notes if user.department == "سلاح الحدود" else ""

    new_case = Case(
        case_number=case_number,
        person_name=person_name.strip(),
        passport_id=passport_id.strip(),
        nationality=nationality.strip(),
        movement_type=movement_type,
        registered_by_dept=user.department or "غير محدد",
        registered_by_user=user.full_name,
        reason=reason.strip(),
        status=status,
        notes_jawazat=notes_j,
        notes_gamarik=notes_g,
        notes_border=notes_b,
        updated_by=user.full_name
    )
    db.add(new_case)
    db.commit()
    return RedirectResponse("/cases", status_code=303)

@app.get("/cases/{case_id}", response_class=HTMLResponse)
async def case_detail(request: Request, case_id: int, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        return templates.TemplateResponse("error.html", {
            "request": request, "user": user, "message": "الحالة غير موجودة"
        })
    return templates.TemplateResponse("case_detail.html", {
        "request": request,
        "user": user,
        "case": case
    })

@app.get("/cases/{case_id}/edit", response_class=HTMLResponse)
async def case_edit_form(request: Request, case_id: int, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        return templates.TemplateResponse("error.html", {
            "request": request, "user": user, "message": "الحالة غير موجودة"
        })

    can_edit = user.is_admin or user.can_edit_all or user.can_edit_status
    if not can_edit:
        return templates.TemplateResponse("error.html", {
            "request": request, "user": user, "message": "ليس لديك صلاحية التعديل"
        })

    return templates.TemplateResponse("case_form.html", {
        "request": request,
        "user": user,
        "case": case,
        "mode": "edit"
    })

@app.post("/cases/{case_id}/edit")
async def case_update(
    request: Request,
    case_id: int,
    person_name: str = Form(None),
    passport_id: str = Form(None),
    nationality: str = Form(None),
    movement_type: str = Form(None),
    reason: str = Form(None),
    status: str = Form(...),
    notes_jawazat: str = Form(""),
    notes_gamarik: str = Form(""),
    notes_border: str = Form(""),
    db: Session = Depends(get_db)
):
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=403)

    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404)

    # صلاحية تعديل الحالة فقط
    if user.can_edit_status and not (user.can_edit_all or user.is_admin):
        case.status = status
        # يسمح بإضافة ملاحظة حسب القسم
        if user.department == "الجوازات":
            case.notes_jawazat = notes_jawazat
        elif user.department == "الجمارك":
            case.notes_gamarik = notes_gamarik
        elif user.department == "سلاح الحدود":
            case.notes_border = notes_border
    elif user.is_admin or user.can_edit_all:
        if person_name is not None:
            case.person_name = person_name.strip()
        if passport_id is not None:
            case.passport_id = passport_id.strip()
        if nationality is not None:
            case.nationality = nationality.strip()
        if movement_type is not None:
            case.movement_type = movement_type
        if reason is not None:
            case.reason = reason.strip()
        case.status = status
        case.notes_jawazat = notes_jawazat
        case.notes_gamarik = notes_gamarik
        case.notes_border = notes_border
    else:
        raise HTTPException(status_code=403)

    case.updated_at = datetime.utcnow()
    case.updated_by = user.full_name
    db.commit()
    return RedirectResponse(f"/cases/{case_id}", status_code=303)

# ---------- إدارة المستخدمين (المدير فقط) ----------
@app.get("/admin/users", response_class=HTMLResponse)
async def admin_users(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or not user.is_admin:
        return templates.TemplateResponse("error.html", {
            "request": request, "user": user, "message": "هذه الصفحة للمدير فقط"
        })
    users = db.query(User).order_by(User.id).all()
    return templates.TemplateResponse("admin_users.html", {
        "request": request,
        "user": user,
        "users": users
    })

@app.get("/admin/users/new", response_class=HTMLResponse)
async def admin_user_new(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or not user.is_admin:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse("admin_user_form.html", {
        "request": request,
        "user": user,
        "edit_user": None
    })

@app.post("/admin/users/new")
async def admin_user_create(
    request: Request,
    username: str = Form(...),
    full_name: str = Form(...),
    password: str = Form(...),
    department: str = Form(""),
    is_admin: bool = Form(False),
    can_create: bool = Form(False),
    can_edit_status: bool = Form(False),
    can_edit_all: bool = Form(False),
    is_active: bool = Form(True),
    db: Session = Depends(get_db)
):
    user = get_current_user(request, db)
    if not user or not user.is_admin:
        raise HTTPException(status_code=403)

    if db.query(User).filter(User.username == username).first():
        return templates.TemplateResponse("admin_user_form.html", {
            "request": request,
            "user": user,
            "edit_user": None,
            "error": "اسم المستخدم موجود مسبقاً"
        })

    new_user = User(
        username=username.strip(),
        full_name=full_name.strip(),
        hashed_password=hash_password(password),
        department=department,
        is_admin=is_admin,
        can_create=can_create,
        can_edit_status=can_edit_status,
        can_edit_all=can_edit_all,
        is_active=is_active
    )
    db.add(new_user)
    db.commit()
    return RedirectResponse("/admin/users", status_code=303)

@app.get("/admin/users/{user_id}/edit", response_class=HTMLResponse)
async def admin_user_edit_form(request: Request, user_id: int, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or not user.is_admin:
        return RedirectResponse("/login", status_code=303)
    edit_user = db.query(User).filter(User.id == user_id).first()
    if not edit_user:
        return RedirectResponse("/admin/users", status_code=303)
    return templates.TemplateResponse("admin_user_form.html", {
        "request": request,
        "user": user,
        "edit_user": edit_user
    })

@app.post("/admin/users/{user_id}/edit")
async def admin_user_update(
    request: Request,
    user_id: int,
    full_name: str = Form(...),
    password: str = Form(""),
    department: str = Form(""),
    is_admin: bool = Form(False),
    can_create: bool = Form(False),
    can_edit_status: bool = Form(False),
    can_edit_all: bool = Form(False),
    is_active: bool = Form(True),
    db: Session = Depends(get_db)
):
    user = get_current_user(request, db)
    if not user or not user.is_admin:
        raise HTTPException(status_code=403)

    edit_user = db.query(User).filter(User.id == user_id).first()
    if not edit_user:
        raise HTTPException(status_code=404)

    edit_user.full_name = full_name.strip()
    edit_user.department = department
    edit_user.is_admin = is_admin
    edit_user.can_create = can_create
    edit_user.can_edit_status = can_edit_status
    edit_user.can_edit_all = can_edit_all
    edit_user.is_active = is_active
    if password.strip():
        edit_user.hashed_password = hash_password(password.strip())

    db.commit()
    return RedirectResponse("/admin/users", status_code=303)

# ---------- إحصائيات ----------
@app.get("/stats", response_class=HTMLResponse)
async def stats_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    total = db.query(Case).count()
    by_status = {}
    for s in ["تم الإعادة", "قيد الإجراء", "لم تتم", "محول", "أخرى"]:
        by_status[s] = db.query(Case).filter(Case.status == s).count()

    by_dept = {}
    for d in ["الجوازات", "الجمارك", "سلاح الحدود"]:
        by_dept[d] = db.query(Case).filter(Case.registered_by_dept == d).count()

    by_movement = {
        "قدوم": db.query(Case).filter(Case.movement_type == "قدوم").count(),
        "مغادرة": db.query(Case).filter(Case.movement_type == "مغادرة").count()
    }

    return templates.TemplateResponse("stats.html", {
        "request": request,
        "user": user,
        "total": total,
        "by_status": by_status,
        "by_dept": by_dept,
        "by_movement": by_movement
    })

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
