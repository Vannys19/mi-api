from fastapi import FastAPI

app = FastAPI()

tareas = [
    {"id": 1, "titulo": "Aprender Docker", "hecha": False},
    {"id": 2, "titulo": "Crear mi API", "hecha": True},
]

@app.get("/")
def inicio():
    return {"mensaje": "¡Mi API funciona!"}

@app.get("/tareas")
def obtener_tareas():
    return tareas

@app.post("/tareas")
def crear_tarea(titulo: str):
    nueva = {"id": len(tareas) + 1, "titulo": titulo, "hecha": False}
    tareas.append(nueva)
    return nueva