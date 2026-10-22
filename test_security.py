"""
Script de pruebas automatizadas para verificar las 4 configuraciones de seguridad:
1. API Key
2. JWT (Autenticación y generación de tokens)
3. BOLA / IDOR y Roles (RBAC)
4. Rate Limiting
"""

from fastapi.testclient import TestClient
from main import app, VALID_API_KEY

client = TestClient(app)

def run_tests():
    print("=" * 70)
    print("INICIANDO PRUEBAS DE SEGURIDAD EN LA API")
    print("=" * 70)

    # --------------------------------------------------------------------------
    # 1. PRUEBAS DE API KEY
    # --------------------------------------------------------------------------
    print("\n[1] Verificando Seguridad con API Key...")

    # Petición sin cabecera X-API-Key
    r_sin_key = client.get("/sistema/estado")
    assert r_sin_key.status_code == 401, f"Esperado 401, recibido {r_sin_key.status_code}"
    print("  [OK] Acceso sin API Key rechazado con HTTP 401 Unauthorized.")

    # Petición con API Key incorrecta
    r_bad_key = client.get("/sistema/estado", headers={"X-API-Key": "clave_falsa_999"})
    assert r_bad_key.status_code == 403, f"Esperado 403, recibido {r_bad_key.status_code}"
    print("  [OK] Acceso con API Key inválida rechazado con HTTP 403 Forbidden.")

    # Petición con API Key correcta
    r_ok_key = client.get("/sistema/estado", headers={"X-API-Key": VALID_API_KEY})
    assert r_ok_key.status_code == 200, f"Esperado 200, recibido {r_ok_key.status_code}"
    print(f"  [OK] Acceso con API Key válida concedido (HTTP 200): {r_ok_key.json()['estado']}")

    # --------------------------------------------------------------------------
    # 2. PRUEBAS DE JWT (LOGIN Y ACCESO)
    # --------------------------------------------------------------------------
    print("\n[2] Verificando Autenticación con JWT...")

    # Intento de acceso a endpoint protegido sin token
    r_no_jwt = client.get("/tareas")
    assert r_no_jwt.status_code == 401, f"Esperado 401, recibido {r_no_jwt.status_code}"
    print("  [OK] Endpoint protegido sin JWT rechazado con HTTP 401.")

    # Login con credenciales incorrectas
    r_bad_login = client.post("/auth/login", json={"username": "usuario1", "password": "password_incorrecto"})
    assert r_bad_login.status_code == 401
    print("  [OK] Login con clave errónea denegado con HTTP 401.")

    # Login exitoso usuario 1
    r_login_u1 = client.post("/auth/login", json={"username": "usuario1", "password": "password123"})
    assert r_login_u1.status_code == 200
    token_u1 = r_login_u1.json()["access_token"]
    print("  [OK] Login exitoso para 'usuario1'. Token JWT emitido.")

    # Login exitoso usuario 2
    r_login_u2 = client.post("/auth/login", json={"username": "usuario2", "password": "password456"})
    assert r_login_u2.status_code == 200
    token_u2 = r_login_u2.json()["access_token"]
    print("  [OK] Login exitoso para 'usuario2'. Token JWT emitido.")

    # Login exitoso admin
    r_login_admin = client.post("/auth/login", json={"username": "admin", "password": "adminpassword"})
    assert r_login_admin.status_code == 200
    token_admin = r_login_admin.json()["access_token"]
    print("  [OK] Login exitoso para 'admin'. Token JWT emitido.")

    # Acceso con JWT válido
    r_tareas_u1 = client.get("/tareas", headers={"Authorization": f"Bearer {token_u1}"})
    assert r_tareas_u1.status_code == 200
    print(f"  [OK] Acceso con JWT válido concedido. Tareas listadas: {len(r_tareas_u1.json()['tareas'])}.")

    # --------------------------------------------------------------------------
    # 3. PRUEBAS DE ANÁLISIS BOLA / IDOR Y ROLES
    # --------------------------------------------------------------------------
    print("\n[3] Verificando Protección BOLA / IDOR y Roles (RBAC)...")

    # Demostración del riesgo en endpoint vulnerable
    r_vuln = client.get("/vulnerable/tareas/3")
    print(f"  [ALERTA DIDÁCTICA] Endpoint vulnerable expone tarea 3 sin auth ni validación: {r_vuln.status_code}")

    # Usuario 1 accede a su propia tarea (id=1, owner_id=1) -> Debe permitir
    r_own = client.get("/tareas/1", headers={"Authorization": f"Bearer {token_u1}"})
    assert r_own.status_code == 200
    print("  [OK - BOLA Mitigado] Propietario accede exitosamente a su recurso (/tareas/1).")

    # Usuario 1 intenta acceder a la tarea 3 (que pertenece a Usuario 2) -> DEBE BLOQUEAR BOLA/IDOR
    r_bola = client.get("/tareas/3", headers={"Authorization": f"Bearer {token_u1}"})
    assert r_bola.status_code == 403, f"Esperado 403, recibido {r_bola.status_code}"
    print(f"  [OK - BOLA Mitigado] Intento de IDOR/BOLA bloqueado con HTTP 403: {r_bola.json()['detail']}")

    # Usuario 1 intenta modificar la tarea 3 (de Usuario 2) -> DEBE BLOQUEAR
    r_bola_put = client.put("/tareas/3", json={"titulo": "Hacked Title"}, headers={"Authorization": f"Bearer {token_u1}"})
    assert r_bola_put.status_code == 403
    print("  [OK - BOLA Mitigado] Modificación ilegítima bloqueada con HTTP 403.")

    # Usuario 1 intenta borrar la tarea 3 (de Usuario 2) -> DEBE BLOQUEAR
    r_bola_del = client.delete("/tareas/3", headers={"Authorization": f"Bearer {token_u1}"})
    assert r_bola_del.status_code == 403
    print("  [OK - BOLA Mitigado] Borrado ilegítimo bloqueado con HTTP 403.")

    # Rol Admin accede a la tarea 3 para auditoría -> Debe permitir por privilegios elevados
    r_admin_task = client.get("/tareas/3", headers={"Authorization": f"Bearer {token_admin}"})
    assert r_admin_task.status_code == 200
    print("  [OK - Roles RBAC] Administrador puede auditar la tarea 3 de cualquier usuario.")

    # Rol User intenta acceder a endpoint exclusivo de Admin -> DEBE BLOQUEAR (RBAC)
    r_rbac_fail = client.get("/admin/auditoria", headers={"Authorization": f"Bearer {token_u1}"})
    assert r_rbac_fail.status_code == 403
    print("  [OK - Roles RBAC] Usuario regular bloqueado al acceder a /admin/auditoria (HTTP 403).")

    # Rol Admin accede a /admin/auditoria -> DEBE PERMITIR
    r_rbac_ok = client.get("/admin/auditoria", headers={"Authorization": f"Bearer {token_admin}"})
    assert r_rbac_ok.status_code == 200
    print("  [OK - Roles RBAC] Administrador accede exitosamente a /admin/auditoria.")

    # --------------------------------------------------------------------------
    # 4. PRUEBAS DE RATE LIMITER
    # --------------------------------------------------------------------------
    print("\n[4] Verificando Rate Limiter (Protección DoS / Fuerza Bruta)...")
    
    # Endpoint /publico/ping tiene límite de 5/minuto
    exceeded = False
    for i in range(1, 8):
        resp = client.get("/publico/ping")
        if resp.status_code == 429:
            exceeded = True
            print(f"  [OK - Rate Limit Activo] Petición #{i} superó la tasa permitida: HTTP 429 Too Many Requests ({resp.json().get('error', 'Rate limit exceeded')})")
            break
        else:
            print(f"  Petición #{i}: HTTP {resp.status_code}")

    assert exceeded, "El Rate Limiter debía haber respondido con 429 al superar el umbral."

    print("\n" + "=" * 70)
    print("¡TODAS LAS PRUEBAS DE SEGURIDAD PASARON CON ÉXITO! (100% OK)")
    print("=" * 70)

if __name__ == "__main__":
    run_tests()
