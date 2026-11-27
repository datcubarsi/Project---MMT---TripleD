from fastapi import FastAPI
import uvicorn

app = FastAPI()

@app.get("/")
def home():
    return {"message": "FastAPI is working!"}

@app.get("/hello")
def hello():
    return {"message": "Hello from Visual Studio 2022"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)