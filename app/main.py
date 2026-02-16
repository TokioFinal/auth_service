from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI()

@app.get('/heatlhz')
def healthz():
    return JSONResponse( status_code=200 ,content = {"message": "Everything okay"})