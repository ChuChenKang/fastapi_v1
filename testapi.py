from fastapi import FastAPI, HTTPException
from typing import Optional
from pydantic import BaseModel
from datetime import timedelta
from twilio.rest import Client
import requests
import json
import redis
import os
import crypto_utils
import math, random


class Item(BaseModel):
    country: str
    remark: Optional[str] = None

class Secret(BaseModel):
    message: str
    passphrase: str
    expire_seconds: Optional[int] = 3600

class Passphrase(BaseModel):
    passphrase: str

class Login(BaseModel):
    username: str
    password: str

class OTP(BaseModel) :
    phone_no: int

client = Client("AC640aaf98ffad1bb2981ef084c555fc61","0b12b6dba6bb6a9b1995513a99b8b839")

app = FastAPI()

r = redis.Redis(
    host=os.getenv("DB_HOST", "localhost"),
    port=os.getenv("DB_PORT", 6379),
    password=os.getenv("DB_PASSWORD", None),
    ssl=os.getenv("REDIS_SSL", "True") == "True",
)

@app.post("/covidCase/")
async def covid_new_case(item:Item):
    url = "https://covid-193.p.rapidapi.com/statistics"
    querystring = {"country": item.country}
    headers = {
        'x-rapidapi-host': "covid-193.p.rapidapi.com",
        'x-rapidapi-key': "482a8f8516msh16204eb9d1f4f68p1a9146jsnf33914c7300e"
    }
    response = requests.request("GET", url, headers=headers, params=querystring)
    js = json.loads(response.text)
    result = js.get('response')[0]
    country = result['country']
    population = result['population']
    new_cases = result['cases']['new']
    active_case = result['cases']['active']
    total_case = result['cases']['total']
    new_death = result['deaths']['new']
    total_death = result['deaths']['total']
    return {'country': country, 'population': population, 'new_case': new_cases, 'active_case': active_case, 'total_case':total_case, 'new_death': new_death, 'total_death': total_death}

@app.get("/item/{item_id}")
def read_item(item_id: int, q: Optional[str] = None):
    return {"item_id": item_id, "q" : q}

@app.post("/secrets")
def create_secret(secret: Secret):
    id = crypto_utils.get_uuid()
    sha = crypto_utils.get_sha(secret.passphrase)
    ciphertext = crypto_utils.encrypt(secret.passphrase, secret.message)
    r.setex(id, timedelta(seconds=secret.expire_seconds), f"{sha}\n{ciphertext}")
    return {"success": "True", "id": id}

@app.post("/secrets/{secret_id}")
def read_secret(secret_id: str, passphrase: Passphrase):
    data = r.get(secret_id)
    passphrase = passphrase.passphrase
    if data is None:
        return HTTPException(
            404, detail="This secret wither never existed or it was already read"
        )

    data = data.decode("utf-8")

    stored_sha, ciphertext = data.split("\n")
    sha = crypto_utils.get_sha(passphrase)

    if stored_sha != sha:
        return HTTPException(
            404, detail="This secret wither never existed or it was already read"
        )

    r.delete(secret_id)
    plaintext = crypto_utils.decrypt(passphrase, ciphertext)
    return {"success": "True", "message": plaintext}


@app.post("/login/")
async def loginpage(login:Login):

    username = login.username
    password = login.password
    result = {}

    if username == "" or password == "":
        result = {"message" : "Please enter correct username or password"}
        return result
    else:
        result = {"message" : "Please proceed"}
        return result

@app.post("/otp/")
async def otp_twillio(otp:OTP):

    digits = "0123456789"
    otp_no = ""
    phone_no = otp.phone_no

    for i in range(6) :
        otp_no += digits[math.floor(random.random() * 10)]

    client.messages.create(to= "+60" + str(phone_no),
        from_= "+12012994622",
        body="This is your exabytes bot OTP number : "+ otp_no
    )
    return {"otp_no": otp_no}
    