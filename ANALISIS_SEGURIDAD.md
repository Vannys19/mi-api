# 🛡️ Informe de Seguridad y Análisis BOLA / IDOR - API Segura

Este documento detalla la reconfiguración y fortificación de la API original (la cual carecía de mecanismos de seguridad), incorporando cuatro pilares esenciales de protección conforme a los estándares de **OWASP API Security Top 10**.

---

## 1. Estado Inicial vs. Estado Fortificado

| Dimensión | Estado Inicial (Vulnerable) | Estado Actual (Fortificado) |
| :--- | :--- | :--- |
| **Autenticación** | Nula (Endpoints públicos sin credenciales) | **JWT (JSON Web Tokens)** con firma HS256 y expiración automática |
| **Acceso Servidor a Servidor** | Inexistente | **API Key** mediante cabecera HTTP `X-API-Key` |
| **Control de Acceso a Objetos** | Vulnerable a **BOLA / IDOR** (sin validación de dueño) | Validación estricta de propiedad de objeto (`owner_id`) y **Roles (RBAC)** |
| **Protección contra Abusos** | Nula (susceptible a DoS y fuerza bruta) | **Rate Limiter** dinámico por IP mediante SlowAPI / Limits |

---

## 2. Análisis Profundo de BOLA / IDOR y Protección por Roles

### ¿Qué es BOLA / IDOR?
- **BOLA** (*Broken Object Level Authorization*) ocupa la posición **#1 en el OWASP API Security Top 10 (API1:2023)**.
- Históricamente conocido como **IDOR** (*Insecure Direct Object Reference*).
- **Causa Raíz:** Ocurre cuando un endpoint recibe el identificador de un recurso (por ejemplo, `/tareas/{tarea_id}`) y accede directamente a él en la base de datos o memoria sin comprobar si el usuario que realiza la petición tiene autorización legítima sobre ese recurso específico.

### Demostración del Riesgo (Antes)
En el código original, si se consultaba o modificaba una tarea:
```python
# CÓDIGO VULNERABLE:
@app.get("/vulnerable/tareas/{tarea_id}")
def obtener_tarea(tarea_id: int):
    # Cualquiera puede cambiar 'tarea_id' en la URL y ver/modificar recursos ajenos
    return next((t for t in tareas if t["id"] == tarea_id), None)
```
- **Vector de Ataque:** Un usuario malicioso autenticado con `id=1` puede iterar secuencialmente IDs (`/tareas/1`, `/tareas/2`, `/tareas/3`, ...) y exfiltrar o alterar información confidencial de otros clientes de la plataforma.

### Solución Implementada (Mitigación Completa)
1. **Asociación de Propiedad (`owner_id`):** Cada recurso almacena el ID del usuario creador.
2. **Validación a Nivel de Objeto:**
   ```python
   # CÓDIGO MITIGADO:
   @app.get("/tareas/{tarea_id}")
   def obtener_tarea_segura(tarea_id: int, current_user: dict = Depends(get_current_user)):
       tarea = next((t for t in tareas if t["id"] == tarea_id), None)
       if not tarea:
           raise HTTPException(status_code=404, detail="Tarea no encontrada")
       
       # Validación BOLA: Propietario o rol con privilegios elevados
       if tarea["owner_id"] != current_user["id"] and current_user["role"] != "admin":
           raise HTTPException(
               status_code=403, 
               detail="[BOLA/IDOR DETECTADO] Acceso denegado: No eres el propietario de este recurso."
           )
       return tarea
   ```
3. **Control de Acceso Basado en Roles (RBAC):**
   - **Rol `user`:** Restringido exclusivamente a interactuar con sus propios recursos (`owner_id == user["id"]`).
   - **Rol `admin`:** Posee autorización de lectura global para auditoría y endpoints privilegiados como `/admin/auditoria`.

---

## 3. Detalle de las Configuraciones de Seguridad Implementadas

### A) API Key
- **Cabecera Requerida:** `X-API-Key`
- **Valor Configurado:** `segura-api-key-987654321`
- **Endpoints de Ejemplo:** `GET /sistema/estado`
- **Comportamiento:**
  - Sin cabecera $\rightarrow$ `401 Unauthorized`
  - Clave incorrecta $\rightarrow$ `403 Forbidden`
  - Clave válida $\rightarrow$ `200 OK`
- **Caso de Uso:** Comunicación de backend a backend, ingestión de métricas, webhooks o trabajos programados (*cron jobs*).

### B) Autenticación JWT (JSON Web Tokens)
- **Algoritmo:** HMAC-SHA256 (`HS256`)
- **Tiempo de Expiración:** 60 minutos
- **Endpoint de Emisión:** `POST /auth/login`
- **Usuarios de Prueba Preconfigurados:**
  - `usuario1` / `password123` (Rol: `user`, ID: `1`)
  - `usuario2` / `password456` (Rol: `user`, ID: `2`)
  - `admin` / `adminpassword` (Rol: `admin`, ID: `99`)
- **Cabecera de Consumo:** `Authorization: Bearer <TOKEN_JWT>`
- **Manejo de Errores:** Rechazo explícito de tokens expirados (`ExpiredSignatureError`) y manipulados (`PyJWTError`).

### C) Rate Limiter (Limitación de Tasa)
- **Mecanismo:** Biblioteca `SlowAPI` con estrategia de seguimiento por IP del cliente (`get_remote_address`).
- **Endpoints y Reglas:**
  - `POST /auth/login`: **5 peticiones / minuto** $\rightarrow$ Previene ataques de fuerza bruta y adivinación de credenciales.
  - `GET /publico/ping`: **5 peticiones / minuto** $\rightarrow$ Demostración rápida de mitigación de saturación DoS.
  - `GET /tareas`: **30 peticiones / minuto** $\rightarrow$ Control de scraping y abuso de recursos.
- **Respuesta ante Exceso:** Código de estado `HTTP 429 Too Many Requests` con mensaje descriptivo y cabeceras de tiempo de espera (`Retry-After`).

---

## 4. Matriz de Endpoints

| Método | Endpoint | Seguridad Aplicada | Regla de Acceso |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | Interfaz Web Interactiva (Dashboard) | Público (Centro de Control) |
| `GET` | `/api/info` | Rate Limit (30/min) | Información de la API en JSON |
| `GET` | `/publico/ping` | Rate Limit (5/min) | Público (Prueba de DoS) |
| `POST` | `/auth/login` | Rate Limit (5/min) + JWT Issuer | Credenciales válidas |
| `GET` | `/sistema/estado` | API Key (`X-API-Key`) | Microservicios / Clientes de confianza |
| `GET` | `/vulnerable/tareas/{id}` | Ninguna (Intencional) | ⚠️ Endpoint de contraste didáctico BOLA |
| `GET` | `/tareas` | JWT + Rate Limit (30/min) | Filtra solo tareas del usuario autenticado |
| `POST` | `/tareas` | JWT | Asigna automáticamente `owner_id` |
| `GET` | `/tareas/{id}` | JWT + Protección BOLA | Solo dueño o rol `admin` |
| `PUT` | `/tareas/{id}` | JWT + Protección BOLA | Solo dueño o rol `admin` |
| `DELETE` | `/tareas/{id}` | JWT + Protección BOLA | Solo dueño o rol `admin` |
| `GET` | `/admin/auditoria` | JWT + Rol `admin` (RBAC) | Solo rol administrativo |

---

## 5. Guía de Ejecución y Pruebas

### Paso 1: Instalar dependencias
```bash
pip install -r requirements.txt
```

### Paso 2: Ejecutar la API
```bash
python main.py
```
O con uvicorn:
```bash
uvicorn main:app --reload --port 8000
```
La documentación interactiva OpenAPI (Swagger) estará disponible en:
👉 `http://localhost:8000/docs`

---

### Paso 3: Ejecutar la Suite de Pruebas Automatizadas
Se ha provisto el script `test_security.py` que comprueba de forma autónoma cada uno de los 4 aspectos de seguridad:
```bash
python test_security.py
```

---

### Paso 4: Pruebas Manuales con `curl` / HTTP

#### 1. Probar API Key
```bash
# Sin API Key (Falla con 401):
curl -i http://localhost:8000/sistema/estado

# Con API Key Correcta (Éxito 200):
curl -i -H "X-API-Key: segura-api-key-987654321" http://localhost:8000/sistema/estado
```

#### 2. Obtener Token JWT (Login)
```bash
# Login como usuario1:
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"usuario1\", \"password\": \"password123\"}"
```
*(Copia el `access_token` retornado)*.

#### 3. Probar Protección BOLA / IDOR
```bash
# Usuario 1 accede a su propia tarea (Tarea 1) -> 200 OK
curl -H "Authorization: Bearer <TOKEN_USUARIO_1>" http://localhost:8000/tareas/1

# Usuario 1 intenta acceder a la tarea de Usuario 2 (Tarea 3) -> 403 Forbidden (BLOQUEADO)
curl -i -H "Authorization: Bearer <TOKEN_USUARIO_1>" http://localhost:8000/tareas/3
```

#### 4. Probar Rate Limiter
Ejecuta 6 peticiones seguidas al endpoint de ping:
```bash
curl http://localhost:8000/publico/ping
# A la 6ta petición dentro del mismo minuto, responderá con HTTP 429 Too Many Requests
```
