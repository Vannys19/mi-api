import os
import datetime
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException, Security, status, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from pydantic import BaseModel
import jwt
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# ------------------------------------------------------------------------------
# CONFIGURACIONES DE SEGURIDAD
# ------------------------------------------------------------------------------

# 1. Configuración de API Key
API_KEY_NAME = "X-API-Key"
VALID_API_KEY = "segura-api-key-987654321"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

# 2. Configuración de JWT
JWT_SECRET_KEY = "clave-super-secreta-para-firmar-jwt-2026"
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 60
bearer_scheme = HTTPBearer(auto_error=False)

# 3. Configuración de Rate Limiter (SlowAPI)
limiter = Limiter(key_func=get_remote_address)

# Inicialización de la aplicación FastAPI
app = FastAPI(
    title="API Segura - Demostración de Buenas Prácticas",
    description="""
    API mejorada con 4 capas esenciales de seguridad:
    1. **API Key**: Validación de servicios externos y microservicios mediante cabecera `X-API-Key`.
    2. **JWT**: Autenticación segura y generación de tokens de sesión con expiración.
    3. **Protección BOLA/IDOR y Roles (RBAC)**: Validación estricta de propiedad de objetos y control por roles (`user` vs `admin`).
    4. **Rate Limiting**: Mitigación de DoS y fuerza bruta limitando peticiones por minuto.
    """,
    version="2.0.0"
)

# Asociar el limitador de tasa y su manejador de excepción (HTTP 429)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Montar carpeta estática para la interfaz gráfica
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ------------------------------------------------------------------------------
# BASE DE DATOS EN MEMORIA (USUARIOS Y TAREAS)
# ------------------------------------------------------------------------------

USUARIOS_DB = {
    "usuario1": {
        "id": 1,
        "username": "usuario1",
        "password": "password123",
        "role": "user",
        "nombre": "Carlos Pérez"
    },
    "usuario2": {
        "id": 2,
        "username": "usuario2",
        "password": "password456",
        "role": "user",
        "nombre": "Ana Gómez"
    },
    "admin": {
        "id": 99,
        "username": "admin",
        "password": "adminpassword",
        "role": "admin",
        "nombre": "Administrador Principal"
    }
}

# Tareas con campo 'owner_id' para trazabilidad y validación de propiedad (Mitigación BOLA/IDOR)
tareas = [
    {"id": 1, "titulo": "Aprender Docker", "hecha": False, "owner_id": 1},
    {"id": 2, "titulo": "Crear mi API", "hecha": True, "owner_id": 1},
    {"id": 3, "titulo": "Configurar Servidor en la Nube", "hecha": False, "owner_id": 2},
    {"id": 4, "titulo": "Auditar seguridad y cumplimiento", "hecha": False, "owner_id": 99},
]


# ------------------------------------------------------------------------------
# MODELOS PYDANTIC
# ------------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str

class TareaCreate(BaseModel):
    titulo: str

class TareaUpdate(BaseModel):
    titulo: Optional[str] = None
    hecha: Optional[bool] = None


# ------------------------------------------------------------------------------
# DEPENDENCIAS Y FUNCIONES DE SEGURIDAD
# ------------------------------------------------------------------------------

# --- A) Validación de API Key ---
def verify_api_key(api_key: Optional[str] = Security(api_key_header)):
    """
    Verifica que la petición contenga la cabecera 'X-API-Key' válida.
    Comúnmente usada para comunicación servidor a servidor o integraciones.
    """
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Falta la cabecera 'X-API-Key'."
        )
    if api_key != VALID_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API Key inválida o sin privilegios suficientes."
        )
    return api_key


# --- B) Utilidades y Dependencia de JWT ---
def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None) -> str:
    """Genera un token JWT firmado con expiración."""
    to_encode = data.copy()
    expire = datetime.datetime.now(datetime.timezone.utc) + (
        expires_delta or datetime.timedelta(minutes=JWT_EXPIRATION_MINUTES)
    )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme)):
    """
    Extrae y valida el token JWT de la cabecera Authorization (Bearer).
    Devuelve los datos del usuario autenticado.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de autorización Bearer ausente.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        if username is None or username not in USUARIOS_DB:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token no contiene un usuario válido.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = USUARIOS_DB[username]
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="El token JWT ha expirado. Por favor inicia sesión nuevamente.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token JWT inválido o manipulado.",
            headers={"WWW-Authenticate": "Bearer"},
        )


# --- C) Control de Acceso Basado en Roles (RBAC) ---
def require_admin(current_user: dict = Depends(get_current_user)):
    """Exige que el usuario autenticado posea el rol de 'admin'."""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso denegado: Se requiere rol de 'admin' para realizar esta acción."
        )
    return current_user


# ------------------------------------------------------------------------------
# ENDPOINTS
# ------------------------------------------------------------------------------

# 1. Interfaz Gráfica Interactiva del Centro de Seguridad
@app.get("/", response_class=HTMLResponse)
@limiter.limit("60/minute")
def inicio(request: Request):
    """
    Sirve el Centro de Pruebas de Seguridad (Web Dashboard interactivo).
    Permite probar visualmente API Key, JWT, BOLA/IDOR y Rate Limiting.
    """
    index_file = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return HTMLResponse("<h2>API Segura Activa</h2><p>Documentación en <a href='/docs'>/docs</a></p>")


@app.get("/api/info")
def info_api():
    return {
        "mensaje": "¡Bienvenido a la API con seguridad implementada!",
        "versión": "2.0.0",
        "documentacion": "/docs",
        "seguridad_activa": ["API Key", "JWT", "Protección BOLA/IDOR", "Roles RBAC", "Rate Limiting"]
    }


# 2. Endpoint Público con Rate Limiter estricto (Demostración de DoS Mitigation)
@app.get("/publico/ping")
@limiter.limit("5/minute")
def ping_con_rate_limit(request: Request):
    """
    Demostración de Rate Limiter: Máximo 5 peticiones por minuto por IP.
    Al superar este límite, se responderá automáticamente con HTTP 429 Too Many Requests.
    """
    return {"mensaje": "pong", "limite": "5 peticiones por minuto"}


# 3. Endpoint de Autenticación (Login) -> Emite JWT con Rate Limiting anti Fuerza Bruta
@app.post("/auth/login")
@limiter.limit("5/minute")
def login(request: Request, credenciales: LoginRequest):
    """
    Autenticación mediante usuario y contraseña con protección contra fuerza bruta (5 intentos/min).
    Usuarios demo disponibles:
    - usuario1 / password123 (rol: user)
    - usuario2 / password456 (rol: user)
    - admin / adminpassword (rol: admin)
    """
    user = USUARIOS_DB.get(credenciales.username)
    if not user or user["password"] != credenciales.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas (usuario o contraseña no válidos)."
        )
    
    token_data = {
        "sub": user["username"],
        "user_id": user["id"],
        "role": user["role"]
    }
    access_token = create_access_token(data=token_data)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "usuario": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "nombre": user["nombre"]
        }
    }


# 4. Endpoint Protegido con API Key
@app.get("/sistema/estado")
def estado_sistema(api_key: str = Depends(verify_api_key)):
    """
    Endpoint protegido exclusivamente con API Key (cabecera 'X-API-Key: segura-api-key-987654321').
    Ideal para integraciones entre microservicios, tareas programadas o monitoreo.
    """
    return {
        "estado": "operativo",
        "servidor": "produccion-01",
        "memoria_uso": "42%",
        "tareas_totales": len(tareas),
        "autenticado_por": "API Key válida"
    }


# ------------------------------------------------------------------------------
# DEMOSTRACIÓN DIDÁCTICA: ANÁLISIS BOLA / IDOR (Broken Object Level Authorization)
# ------------------------------------------------------------------------------

# A) ENDPOINT VULNERABLE A BOLA/IDOR (Para propósitos educativos y comparativos)
@app.get("/vulnerable/tareas/{tarea_id}")
def obtener_tarea_vulnerable(tarea_id: int):
    """
    ⚠️ ENDPOINT VULNERABLE A IDOR/BOLA (Para ejemplificar el riesgo):
    Cualquier persona puede ver cualquier tarea cambiando el ID en la URL,
    sin autenticación ni verificación de si la tarea le pertenece.
    """
    for t in tareas:
        if t["id"] == tarea_id:
            return {
                "ADVERTENCIA": "Este endpoint es intencionalmente vulnerable a BOLA/IDOR",
                "tarea": t
            }
    raise HTTPException(status_code=404, detail="Tarea no encontrada")


# B) ENDPOINTS PROTEGIDOS CONTRA BOLA / IDOR Y CON ROLES

@app.get("/tareas")
@limiter.limit("30/minute")
def obtener_mis_tareas(request: Request, current_user: dict = Depends(get_current_user)):
    """
    Listar tareas seguro:
    - Un usuario regular solo ve sus propias tareas (donde owner_id == current_user['id']).
    - Un usuario 'admin' tiene visibilidad completa de todas las tareas.
    """
    if current_user["role"] == "admin":
        return {"filtro": "todos los registros (rol admin)", "tareas": tareas}
    
    mis_tareas = [t for t in tareas if t["owner_id"] == current_user["id"]]
    return {"filtro": f"únicamente tareas de {current_user['username']}", "tareas": mis_tareas}


@app.post("/tareas", status_code=status.HTTP_201_CREATED)
def crear_tarea(tarea_in: TareaCreate, current_user: dict = Depends(get_current_user)):
    """
    Crea una tarea asociando de forma automática el 'owner_id' al usuario autenticado vía JWT.
    Evita que un usuario cree tareas en nombre de otro.
    """
    nueva_tarea = {
        "id": len(tareas) + 1,
        "titulo": tarea_in.titulo,
        "hecha": False,
        "owner_id": current_user["id"]
    }
    tareas.append(nueva_tarea)
    return {"mensaje": "Tarea creada exitosamente", "tarea": nueva_tarea}


@app.get("/tareas/{tarea_id}")
def obtener_tarea_por_id(tarea_id: int, current_user: dict = Depends(get_current_user)):
    """
    🛡️ ENDPOINT PROTEGIDO CONTRA BOLA / IDOR:
    Verifica que el usuario solicitante sea el propietario del objeto (owner_id)
    o cuente con rol 'admin'. Si un usuario intenta acceder a la tarea de otro,
    se bloquea con HTTP 403 Forbidden.
    """
    tarea = next((t for t in tareas if t["id"] == tarea_id), None)
    if not tarea:
        raise HTTPException(status_code=404, detail="Tarea no encontrada.")
    
    # CONTROL DE ACCESO A NIVEL DE OBJETO (Mitigación BOLA)
    if tarea["owner_id"] != current_user["id"] and current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"[BOLA/IDOR DETECTADO] Acceso denegado: No eres el propietario de la tarea {tarea_id}."
        )
    
    return tarea


@app.put("/tareas/{tarea_id}")
def actualizar_tarea(
    tarea_id: int,
    cambios: TareaUpdate,
    current_user: dict = Depends(get_current_user)
):
    """
    🛡️ Modificación protegida contra BOLA:
    Solo el propietario o un administrador pueden editar la tarea.
    """
    tarea = next((t for t in tareas if t["id"] == tarea_id), None)
    if not tarea:
        raise HTTPException(status_code=404, detail="Tarea no encontrada.")
    
    # Verificación de propiedad (BOLA / IDOR)
    if tarea["owner_id"] != current_user["id"] and current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"[BOLA/IDOR DETECTADO] No puedes modificar una tarea que no te pertenece."
        )
    
    if cambios.titulo is not None:
        tarea["titulo"] = cambios.titulo
    if cambios.hecha is not None:
        tarea["hecha"] = cambios.hecha
        
    return {"mensaje": "Tarea actualizada correctamente", "tarea": tarea}


@app.delete("/tareas/{tarea_id}")
def eliminar_tarea(tarea_id: int, current_user: dict = Depends(get_current_user)):
    """
    🛡️ Eliminación protegida contra BOLA:
    Previene que un atacante borre recursos de otros manipulando el ID en la URL.
    """
    tarea = next((t for t in tareas if t["id"] == tarea_id), None)
    if not tarea:
        raise HTTPException(status_code=404, detail="Tarea no encontrada.")
    
    # Verificación de propiedad (BOLA / IDOR)
    if tarea["owner_id"] != current_user["id"] and current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"[BOLA/IDOR DETECTADO] No tienes permiso para eliminar la tarea de otro usuario."
        )
    
    tareas.remove(tarea)
    return {"mensaje": f"Tarea {tarea_id} eliminada exitosamente."}


# ------------------------------------------------------------------------------
# ENDPOINTS EXCLUSIVOS PARA ROL ADMIN (RBAC)
# ------------------------------------------------------------------------------

@app.get("/admin/auditoria")
def panel_auditoria_admin(admin_user: dict = Depends(require_admin)):
    """
    Endpoint exclusivo para rol 'admin'.
    Demuestra control de acceso basado en roles (RBAC).
    """
    return {
        "mensaje": "Bienvenido al panel de auditoría",
        "usuario_autorizado": admin_user["username"],
        "rol": admin_user["role"],
        "total_usuarios": len(USUARIOS_DB),
        "total_tareas": len(tareas),
        "resumen_propietarios": [
            {"tarea_id": t["id"], "owner_id": t["owner_id"], "titulo": t["titulo"]} for t in tareas
        ]
    }


# Ejecución directa con python main.py
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)