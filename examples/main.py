"""Minimal FastAPI application showcasing ipregistry-fastapi.

Run with:
    export IPREGISTRY_API_KEY=YOUR_API_KEY
    uvicorn examples.main:app --reload
"""

from fastapi import APIRouter, Depends, FastAPI

from ipregistry_fastapi import (
    ClientIpDep,
    IpInfoDep,
    IpregistryDep,
    IpregistryMiddleware,
    block_threats,
    ipregistry_lifespan,
    is_eu,
)

app = FastAPI(title="ipregistry-fastapi example", lifespan=ipregistry_lifespan)

# Optional: enrich every request and skip bots/static assets to save credits.
app.add_middleware(IpregistryMiddleware, skip_bots=True)


@app.get("/whoami")
async def whoami(info: IpInfoDep, ip: ClientIpDep):
    if info is None:
        return {"ip": ip, "detail": "No IP intelligence available (private IP or lookup failure)"}
    return {
        "ip": info.ip,
        "country": info.location.country.name if info.location and info.location.country else None,
        "city": info.location.city if info.location else None,
        "in_eu": is_eu(info),
        "threat": info.security.is_threat if info.security else None,
    }


@app.get("/consent")
async def consent(info: IpInfoDep):
    return {"show_cookie_banner": is_eu(info, assume_eu=True)}


@app.get("/lookup/{ip}")
async def lookup(ip: str, ipregistry: IpregistryDep):
    info = await ipregistry.lookup(ip, fields="location,security")
    return info.model_dump(exclude_none=True)


protected = APIRouter(
    prefix="/protected",
    dependencies=[Depends(block_threats(tor=True, proxy=True))],
)


@protected.get("/")
async def protected_index():
    return {"detail": "Only reachable from IPs that are not flagged as threats"}


app.include_router(protected)
