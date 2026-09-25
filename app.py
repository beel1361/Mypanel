
import os, json, uuid, sqlite3, secrets, subprocess, re, base64, time, socket, ipaddress, yaml, urllib.request, shutil
from pathlib import Path
from urllib.parse import quote, urlencode
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, Request, Form, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

DATA=Path(os.getenv("DATA_DIR","/data")); DATA.mkdir(parents=True, exist_ok=True)
DB=DATA/"panel.db"; XRAY_DIR=DATA/"xray"; XRAY_DIR.mkdir(exist_ok=True)
CFG=XRAY_DIR/"config.json"; ACCESS=XRAY_DIR/"access.log"; ERROR=XRAY_DIR/"error.log"
PORT=int(os.getenv("PORT","8080")); ADMIN_USER=os.getenv("ADMIN_USER","admin")
ADMIN_PASSWORD=os.getenv("ADMIN_PASSWORD","")
if not ADMIN_PASSWORD: ADMIN_PASSWORD=secrets.token_urlsafe(18)
XRAY="/usr/local/bin/xray"
app=FastAPI(title="Railway VPN Panel")
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET",secrets.token_urlsafe(32)), max_age=86400)
templates=Jinja2Templates(directory=str(Path(__file__).parent/"templates"))

PROTOCOLS={"vless","vmess","trojan"}
TRANSPORTS={"tcp","ws","grpc","xhttp","httpupgrade"}
SECURITIES={"none","tls","reality"}

def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
def init():
    c=db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, group_name TEXT DEFAULT '',
      note TEXT DEFAULT '', enabled INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS inbounds(
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, user_id INTEGER, protocol TEXT NOT NULL,
      transport TEXT NOT NULL, security TEXT DEFAULT 'none', port INTEGER NOT NULL, uuid TEXT NOT NULL,
      flow TEXT DEFAULT '', path TEXT DEFAULT '/ws', service_name TEXT DEFAULT 'grpc',
      xhttp_mode TEXT DEFAULT 'auto', domain TEXT DEFAULT '', sni TEXT DEFAULT '', fingerprint TEXT DEFAULT 'chrome',
      short_id TEXT DEFAULT '', external_host TEXT DEFAULT '', external_port INTEGER DEFAULT 0,
      enabled INTEGER DEFAULT 1, expiry TEXT DEFAULT '', quota_gb REAL DEFAULT 0, ip_limit INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id));
    CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS traffic(inbound_id INTEGER PRIMARY KEY, uplink INTEGER DEFAULT 0, downlink INTEGER DEFAULT 0, updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
    """); c.commit(); c.close()
def q(sql,args=(),one=False):
    c=db(); r=c.execute(sql,args); out=r.fetchone() if one else r.fetchall(); c.close(); return out
def execdb(sql,args=()):
    c=db(); c.execute(sql,args); c.commit(); c.close()
def logged(req): return bool(req.session.get("user"))
def guard(req):
    if not logged(req): raise HTTPException(303,headers={"Location":"/login"})
def run(cmd,timeout=15):
    try: return subprocess.run(cmd,capture_output=True,text=True,timeout=timeout)
    except Exception as e: return None
def setting(k,d=""):
    r=q("select v from settings where k=?",(k,),True); return r["v"] if r else d
def set_setting(k,v): execdb("INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",(k,str(v)))
def public_domain():
    return os.getenv("RAILWAY_PUBLIC_DOMAIN") or setting("public_domain","")

NGINX=Path("/etc/nginx/conf.d/railway-vpn.conf")
def ensure_nginx():
    rows=q("select * from inbounds where enabled=1")
    lines=[
      "map $http_upgrade $connection_upgrade { default upgrade; '' close; }",
      "server { listen 8080; server_name _; client_max_body_size 10m;",
      "location / { proxy_pass http://127.0.0.1:8081; proxy_set_header Host $host; proxy_set_header X-Real-IP $remote_addr; proxy_set_header X-Forwarded-Proto https; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; }"
    ]
    for r in rows:
        if r["transport"] in ("ws","xhttp","httpupgrade"):
            path=normalize_path(r["path"],"/"+r["transport"])
            lines += [f"location = {path} {{ proxy_pass http://127.0.0.1:{r['port']}; proxy_http_version 1.1; proxy_set_header Host $host; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection $connection_upgrade; proxy_read_timeout 3600s; proxy_send_timeout 3600s; }}"]
        elif r["transport"]=="grpc":
            path="/"+(r["service_name"] or "grpc")
            lines += [f"location ^~ {path} {{ grpc_pass grpc://127.0.0.1:{r['port']}; grpc_read_timeout 3600s; grpc_send_timeout 3600s; }}"]
    lines.append("}")
    NGINX.write_text("\n".join(lines)+"\n")
    t=run(["nginx","-t"])
    if t and t.returncode==0: run(["nginx","-s","reload"])
def admin_password():
    return setting("admin_password",ADMIN_PASSWORD)

def reality_setup():
    if setting("reality_private") and setting("reality_public"): return
    p=run([XRAY,"x25519"])
    priv=pub=""
    if p and p.returncode==0:
        for line in p.stdout.splitlines():
            if ":" in line:
                k,v=line.split(":",1); k=k.lower().strip(); v=v.strip()
                if "private" in k: priv=v
                if "public" in k: pub=v
    if not priv: priv=secrets.token_urlsafe(32)
    set_setting("reality_private",priv); set_setting("reality_public",pub)
def gen_short(): return secrets.token_hex(4)
def gen_uuid(): return str(uuid.uuid4())
def port_for_new():
    used={r["port"] for r in q("select port from inbounds")}
    p=10000
    while p in used: p+=1
    return p
def normalize_path(p,default="/ws"):
    p=p or default
    if not p.startswith("/"): p="/"+p
    return p
def build_stream(r):
    network=r["transport"]; sec=r["security"] or "none"
    s={"network":network,"security":sec}
    if sec=="tls":
        s["tlsSettings"]={"serverName":r["sni"] or r["domain"] or public_domain(),"alpn":["h2","http/1.1"]}
    if sec=="reality":
        s["realitySettings"]={"show":False,"dest":(r["domain"] or "www.cloudflare.com")+":443",
          "xver":0,"serverNames":[r["sni"] or r["domain"] or "www.cloudflare.com"],
          "privateKey":setting("reality_private"),"shortIds":[r["short_id"] or gen_short()]}
    if network=="tcp":
        s["tcpSettings"]={"acceptProxyProtocol":False}
    elif network=="ws":
        s["wsSettings"]={"path":normalize_path(r["path"]), "headers":{}}
    elif network=="grpc":
        s["grpcSettings"]={"serviceName":r["service_name"] or "grpc","multiMode":False}
    elif network=="httpupgrade":
        s["httpupgradeSettings"]={"path":normalize_path(r["path"],"/httpupgrade"),"host":r["domain"] or public_domain()}
    elif network=="xhttp":
        # Xray XHTTP settings vary slightly by version; test mode catches unsupported combinations.
        s["xhttpSettings"]={"path":normalize_path(r["path"],"/xhttp"),"mode":r["xhttp_mode"] or "auto","host":r["domain"] or public_domain()}
    return s
def build_config():
    rows=q("""select i.*,u.username,u.enabled as user_enabled from inbounds i
              left join users u on u.id=i.user_id where i.enabled=1""")
    ins=[]
    for r in rows:
        if r["user_id"] and not r["user_enabled"]: continue
        if r["expiry"]:
            try:
                if datetime.fromisoformat(r["expiry"]).replace(tzinfo=timezone.utc) < datetime.now(timezone.utc): continue
            except: pass
        email=(r["username"] or r["name"]).strip()
        if r["protocol"]=="vless":
            cl={"id":r["uuid"],"email":email}
            if r["flow"]: cl["flow"]=r["flow"]
        elif r["protocol"]=="vmess":
            cl={"id":r["uuid"],"alterId":0,"email":email}
        else:
            cl={"password":r["uuid"],"email":email}
        st={"tag":f"in-{r['id']}","listen":"0.0.0.0","port":r["port"],"protocol":r["protocol"],
            "settings":{"clients":[cl]},"streamSettings":build_stream(r)}
        ins.append(st)
    cfg={"log":{"access":str(ACCESS),"error":str(ERROR),"loglevel":"warning"},
         "api":{"tag":"api","services":["HandlerService","LoggerService","StatsService"]},
         "stats":{},"policy":{"levels":{"0":{"statsUserUplink":True,"statsUserDownlink":True}}},
         "inbounds":[{"listen":"127.0.0.1","port":10085,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1"},"tag":"api","sniffing":{"enabled":False}}]+ins,
         "outbounds":[{"protocol":"freedom","tag":"direct"},{"protocol":"blackhole","tag":"blocked"}],
         "routing":{"rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api"}]}}
    # Xray's API outbound is required by some versions; api inbound is enough for statsquery in most releases.
    CFG.write_text(json.dumps(cfg,indent=2))
    return cfg
def xray_test():
    return run([XRAY,"run","-test","-config",str(CFG)],20)
def restart_xray():
    build_config(); ensure_nginx()
    t=xray_test()
    if t and t.returncode!=0: return False, (t.stderr or t.stdout)[-5000:]
    # entrypoint owns xray; HUP is supported by Xray for reload on current versions.
    p=run(["pkill","-HUP","-x","xray"])
    return True,""
def link_for(r, host=None, port=None):
    host=host or r["external_host"] or public_domain() or "YOUR-DOMAIN"
    port=port or r["external_port"] or (443 if r["security"] in ("tls","reality") or r["transport"] in ("ws","grpc","xhttp","httpupgrade") else r["port"])
    name=quote(r["name"])
    q={"encryption":"none","type":r["transport"]}
    if r["security"]=="tls":
        q.update({"security":"tls","sni":r["sni"] or r["domain"] or host,"fp":r["fingerprint"] or "chrome"})
    elif r["security"]=="reality":
        q.update({"security":"reality","sni":r["sni"] or r["domain"] or "www.cloudflare.com","fp":r["fingerprint"] or "chrome",
                  "pbk":setting("reality_public"),"sid":r["short_id"] or gen_short()})
        if r["protocol"]=="vless" and r["flow"]: q["flow"]=r["flow"]
    else: q["security"]="none"
    if r["transport"]=="ws": q["path"]=normalize_path(r["path"])
    elif r["transport"]=="grpc": q["serviceName"]=r["service_name"] or "grpc"
    elif r["transport"]=="xhttp":
        q["path"]=normalize_path(r["path"],"/xhttp"); q["mode"]=r["xhttp_mode"] or "auto"
    elif r["transport"]=="httpupgrade": q["path"]=normalize_path(r["path"],"/httpupgrade")
    if r["transport"]=="httpupgrade" and r["domain"]: q["host"]=r["domain"]
    if r["transport"]=="xhttp" and r["domain"]: q["host"]=r["domain"]
    if r["protocol"]=="vless":
        return "vless://"+r["uuid"]+"@"+host+":"+str(port)+"?"+urlencode(q,quote_via=quote)+"#"+name
    if r["protocol"]=="trojan":
        q.pop("encryption",None)
        return "trojan://"+r["uuid"]+"@"+host+":"+str(port)+"?"+urlencode(q,quote_via=quote)+"#"+name
    # VMess base64 JSON
    obj={"v":"2","ps":r["name"],"add":host,"port":str(port),"id":r["uuid"],"aid":"0","scy":"auto","net":r["transport"],
         "type":"none","tls":"tls" if r["security"]=="tls" else ("reality" if r["security"]=="reality" else ""),
         "sni":r["sni"] or r["domain"] or host,"fp":r["fingerprint"] or "chrome",
         "path":r["path"] if r["transport"] in ("ws","xhttp","httpupgrade") else "",
         "host":r["domain"] or host,"grpc-service-name":r["service_name"] if r["transport"]=="grpc" else ""}
    return "vmess://"+base64.b64encode(json.dumps(obj,separators=(",",":")).encode()).decode()
def singbox(r):
    link=link_for(r)
    host=r["external_host"] or public_domain(); port=r["external_port"] or (443 if r["security"]!="none" else r["port"])
    o={"type":r["protocol"],"tag":r["name"],"server":host,"server_port":port}
    if r["protocol"] in ("vless","vmess"): o["uuid"]=r["uuid"]
    if r["protocol"]=="trojan": o["password"]=r["uuid"]
    if r["security"] in ("tls","reality"):
        o["tls"]={"enabled":True,"server_name":r["sni"] or r["domain"] or host,"utls":{"enabled":True,"fingerprint":r["fingerprint"] or "chrome"}}
    if r["security"]=="reality":
        o["tls"]["reality"]={"enabled":True,"public_key":setting("reality_public"),"short_id":r["short_id"] or gen_short()}
    if r["transport"]=="ws": o["transport"]={"type":"ws","path":normalize_path(r["path"])}
    elif r["transport"]=="grpc": o["transport"]={"type":"grpc","service_name":r["service_name"] or "grpc"}
    elif r["transport"]=="xhttp": o["transport"]={"type":"http","path":normalize_path(r["path"],"/xhttp")}
    elif r["transport"]=="httpupgrade": o["transport"]={"type":"httpupgrade","path":normalize_path(r["path"],"/httpupgrade")}
    return o
def clash(r):
    host=r["external_host"] or public_domain(); port=r["external_port"] or (443 if r["security"]!="none" else r["port"])
    p={"name":r["name"],"type":r["protocol"],"server":host,"port":port,"uuid":r["uuid"] if r["protocol"]!="trojan" else None,
       "cipher":"none" if r["protocol"]=="vless" else "auto"}
    if r["protocol"]=="trojan": p["password"]=r["uuid"]
    if r["security"] in ("tls","reality"):
        p["tls"]=True; p["servername"]=r["sni"] or r["domain"] or host
    if r["security"]=="reality":
        p["client-fingerprint"]=r["fingerprint"] or "chrome"; p["reality-opts"]={"public-key":setting("reality_public"),"short-id":r["short_id"] or gen_short()}
    if r["transport"]=="ws": p["network"]="ws"; p["ws-opts"]={"path":normalize_path(r["path"]),"headers":{"Host":r["domain"] or host}}
    elif r["transport"]=="grpc": p["network"]="grpc"; p["grpc-opts"]={"grpc-service-name":r["service_name"] or "grpc"}
    elif r["transport"]=="xhttp": p["network"]="xhttp"; p["xhttp-opts"]={"path":normalize_path(r["path"],"/xhttp")}
    elif r["transport"]=="httpupgrade": p["network"]="httpupgrade"; p["httpupgrade-opts"]={"path":normalize_path(r["path"],"/httpupgrade")}
    return {k:v for k,v in p.items() if v is not None}

def stats_for(r):
    # Xray CLI statsquery is version dependent; return persisted values plus best-effort live query.
    email=(r["username"] or r["name"])
    up=down=0
    for direction in ("uplink","downlink"):
        p=run([XRAY,"api","statsquery","-server","127.0.0.1:10085","-name",f"user>>>{email}>>>traffic>>>{direction}"],8)
        if p and p.returncode==0:
            m=re.search(r"value:\s*(\d+)',?|\bvalue:\s*(\d+)',?",p.stdout)
            if m:
                val=int(next(x for x in m.groups() if x)); up=val if direction=="uplink" else up; down=val if direction=="downlink" else down
    return up,down

@app.on_event("startup")
def startup():
    init(); reality_setup(); build_config(); ensure_nginx()

@app.get("/login",response_class=HTMLResponse)
def login(req:Request): return templates.TemplateResponse("login.html",{"request":req,"error":""})
@app.post("/login",response_class=HTMLResponse)
def login_post(req:Request,user:str=Form(...),password:str=Form(...)):
    if secrets.compare_digest(user,ADMIN_USER) and secrets.compare_digest(password,admin_password()):
        req.session["user"]=user; return RedirectResponse("/",303)
    return templates.TemplateResponse("login.html",{"request":req,"error":"نام کاربری یا رمز عبور نادرست است."})
@app.get("/logout")
def logout(req:Request): req.session.clear(); return RedirectResponse("/login",303)

@app.get("/",response_class=HTMLResponse)
def index(req:Request):
    guard(req); rows=q("""select i.*,u.username,u.group_name from inbounds i left join users u on u.id=i.user_id order by i.id desc""")
    users=q("select * from users order by id desc")
    return templates.TemplateResponse("index.html",{"request":req,"rows":rows,"users":users,"domain":public_domain(),"reality_pub":setting("reality_public"),"xray":bool(shutil.which(XRAY))})

@app.get("/new",response_class=HTMLResponse)
def new(req:Request):
    guard(req); return templates.TemplateResponse("new.html",{"request":req,"users":q("select * from users where enabled=1"),"domain":public_domain()})

@app.post("/new")
def create(req:Request,name:str=Form(...),user_id:int=Form(0),protocol:str=Form(...),transport:str=Form(...),security:str=Form("none"),
           domain:str=Form(""),sni:str=Form(""),fingerprint:str=Form("chrome"),flow:str=Form(""),path:str=Form(""),
           service_name:str=Form("grpc"),xhttp_mode:str=Form("auto"),external_host:str=Form(""),external_port:int=Form(0),
           expiry:str=Form(""),quota_gb:float=Form(0),ip_limit:int=Form(0)):
    guard(req)
    if protocol not in PROTOCOLS or transport not in TRANSPORTS or security not in SECURITIES: raise HTTPException(400,"پارامتر نامعتبر")
    if security=="reality" and transport not in ("tcp","xhttp","httpupgrade","ws","grpc"):
        raise HTTPException(400,"Transport انتخاب‌شده برای Reality توسط این نسخه آزمایش نشده است.")
    if transport in ("ws","grpc","xhttp","httpupgrade") and not path and transport!="grpc": path="/"+transport
    if transport=="grpc": path=""
    if security=="reality" and not sni: sni=domain or "www.cloudflare.com"
    uid=gen_uuid(); sid=gen_short() if security=="reality" else ""
    if protocol=="vless" and not flow and security=="reality" and transport=="tcp": flow="xtls-rprx-vision"
    port=port_for_new()
    execdb("""insert into inbounds(name,user_id,protocol,transport,security,port,uuid,flow,path,service_name,xhttp_mode,domain,sni,fingerprint,short_id,external_host,external_port,expiry,quota_gb,ip_limit)
              values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
           (name,user_id or None,protocol,transport,security,port,uid,flow,path or "",service_name,xhttp_mode,domain,sni,fingerprint,sid,external_host,external_port,expiry,quota_gb,ip_limit))
    ok,err=restart_xray()
    if not ok: execdb("delete from inbounds where uuid=?",(uid,)); raise HTTPException(400,"Xray config test failed: "+err)
    return RedirectResponse("/",303)

@app.post("/toggle/{id}")
def toggle(req:Request,id:int):
    guard(req); execdb("update inbounds set enabled=1-enabled where id=?",(id,)); restart_xray(); return RedirectResponse("/",303)
@app.post("/delete/{id}")
def delete(req:Request,id:int):
    guard(req); execdb("delete from inbounds where id=?",(id,)); restart_xray(); return RedirectResponse("/",303)

@app.get("/edit/{id}",response_class=HTMLResponse)
def edit(req:Request,id:int):
    guard(req); r=q("select * from inbounds where id=?",(id,),True)
    if not r: raise HTTPException(404)
    return templates.TemplateResponse("edit.html",{"request":req,"r":r,"users":q("select * from users where enabled=1")})

@app.post("/edit/{id}")
def edit_post(req:Request,id:int,name:str=Form(...),user_id:int=Form(0),security:str=Form("none"),domain:str=Form(""),sni:str=Form(""),
              fingerprint:str=Form("chrome"),flow:str=Form(""),path:str=Form(""),service_name:str=Form("grpc"),xhttp_mode:str=Form("auto"),
              external_host:str=Form(""),external_port:int=Form(0),expiry:str=Form(""),quota_gb:float=Form(0),ip_limit:int=Form(0)):
    guard(req)
    r=q("select * from inbounds where id=?",(id,),True)
    if not r: raise HTTPException(404)
    sid=r["short_id"] or (gen_short() if security=="reality" else "")
    execdb("""update inbounds set name=?,user_id=?,security=?,domain=?,sni=?,fingerprint=?,flow=?,path=?,service_name=?,xhttp_mode=?,external_host=?,external_port=?,expiry=?,quota_gb=?,ip_limit=?,short_id=? where id=?""",
           (name,user_id or None,security,domain,sni,fingerprint,flow,path,service_name,xhttp_mode,external_host,external_port,expiry,quota_gb,ip_limit,sid,id))
    ok,err=restart_xray()
    if not ok: raise HTTPException(400,"Xray config test failed: "+err)
    return RedirectResponse("/",303)

@app.post("/user/new")
def user_new(req:Request,username:str=Form(...),group_name:str=Form(""),note:str=Form("")):
    guard(req); execdb("insert or ignore into users(username,group_name,note) values(?,?,?)",(username,group_name,note)); return RedirectResponse("/",303)
@app.post("/user/toggle/{id}")
def user_toggle(req:Request,id:int):
    guard(req); execdb("update users set enabled=1-enabled where id=?",(id,)); restart_xray(); return RedirectResponse("/",303)
@app.post("/user/delete/{id}")
def user_delete(req:Request,id:int):
    guard(req); execdb("delete from users where id=?",(id,)); execdb("update inbounds set user_id=NULL where user_id=?",(id,)); restart_xray(); return RedirectResponse("/",303)

@app.get("/config/{id}",response_class=PlainTextResponse)
def config(req:Request,id:int):
    guard(req); r=q("select i.*,u.username from inbounds i left join users u on u.id=i.user_id where i.id=?",(id,),True)
    if not r: raise HTTPException(404)
    return link_for(r)

@app.get("/qr/{id}")
def qr(req:Request,id:int):
    guard(req)
    try:
        import qrcode
        from io import BytesIO
        r=q("select i.*,u.username from inbounds i left join users u on u.id=i.user_id where i.id=?",(id,),True)
        if not r: raise HTTPException(404)
        im=qrcode.make(link_for(r)); b=BytesIO(); im.save(b,format="PNG"); b.seek(0)
        return StreamingResponse(b,media_type="image/png")
    except ImportError: raise HTTPException(500,"qrcode package unavailable")

@app.get("/subscription/{token}")
def subscription(token:str,format:str="base64"):
    if not secrets.compare_digest(token,setting("sub_token","")): raise HTTPException(404)
    rows=q("""select i.*,u.username from inbounds i left join users u on u.id=i.user_id
              where i.enabled=1 and (i.expiry='' or i.expiry is null or i.expiry>=?)""",(datetime.now().strftime("%Y-%m-%dT%H:%M"),))
    links=[link_for(r) for r in rows]
    if format=="clash":
        return PlainTextResponse(yaml.safe_dump({"mixed-port":7890,"proxies":[clash(r) for r in rows],"proxy-groups":[{"name":"AUTO","type":"select","proxies":[r["name"] for r in rows]}],"rules":["MATCH,AUTO"]},allow_unicode=True,sort_keys=False),media_type="text/yaml")
    if format=="singbox":
        return JSONResponse({"outbounds":[singbox(r) for r in rows]})
    return PlainTextResponse(base64.b64encode(("\n".join(links)).encode()).decode())
@app.get("/subscription")
def subscription_page(req:Request):
    guard(req)
    token=setting("sub_token","")
    if not token: token=secrets.token_urlsafe(24); set_setting("sub_token",token)
    base=f"https://{public_domain()}" if public_domain() else ""
    return templates.TemplateResponse("subscription.html",{"request":req,"token":token,"base":base})

@app.post("/settings")
def settings(req:Request,domain:str=Form(""),admin_password:str=Form("")):
    guard(req)
    if domain: set_setting("public_domain",domain.strip())
    if admin_password: set_setting("admin_password_override",admin_password.strip())
    return RedirectResponse("/",303)

@app.post("/restart")
def restart(req:Request):
    guard(req); ok,err=restart_xray(); return JSONResponse({"ok":ok,"error":err})
@app.get("/raw")
def raw(req:Request): guard(req); return PlainTextResponse(CFG.read_text())

@app.get("/metrics")
def metrics(req:Request):
    guard(req)
    # Best effort OS metrics without external deps.
    load=os.getloadavg()[0] if hasattr(os,"getloadavg") else 0
    mem=0
    try:
        m=re.search(r"MemAvailable:\s+(\d+)",Path("/proc/meminfo").read_text()); mem=int(m.group(1))*1024 if m else 0
    except: pass
    return {"load1":load,"mem_available":mem,"inbounds":len(q("select * from inbounds where enabled=1"))}

@app.get("/traffic")
def traffic(req:Request):
    guard(req); out=[]
    for r in q("""select i.*,u.username from inbounds i left join users u on u.id=i.user_id order by i.id desc"""):
        up,down=stats_for(r); out.append({"id":r["id"],"name":r["name"],"uplink":up,"downlink":down})
    return out

@app.get("/logs",response_class=PlainTextResponse)
def logs(req:Request,kind:str="error"):
    guard(req); p=ACCESS if kind=="access" else ERROR
    return PlainTextResponse(p.read_text(errors="replace")[-30000:] if p.exists() else "")

@app.get("/backup")
def backup(req:Request):
    guard(req)
    import io, zipfile
    bio=io.BytesIO()
    with zipfile.ZipFile(bio,"w",zipfile.ZIP_DEFLATED) as z:
        z.write(DB,"panel.db"); z.write(CFG,"xray-config.json")
    bio.seek(0); return StreamingResponse(bio,media_type="application/zip",headers={"Content-Disposition":"attachment; filename=railway-vpn-backup.zip"})

@app.post("/restore")
async def restore(req:Request,file:UploadFile=File(...)):
    guard(req)
    data=await file.read()
    if len(data)>20*1024*1024: raise HTTPException(400,"فایل بزرگ است")
    import io, zipfile
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            if "panel.db" not in z.namelist(): raise ValueError()
            z.extract("panel.db",DATA)
        init(); restart_xray()
    except Exception: raise HTTPException(400,"Backup نامعتبر است")
    return RedirectResponse("/",303)


@app.get("/settings",response_class=HTMLResponse)
def settings_page(req:Request):
    guard(req)
    token=setting("sub_token","")
    if not token: token=secrets.token_urlsafe(24); set_setting("sub_token",token)
    return templates.TemplateResponse("settings.html",{"request":req,"domain":public_domain(),"token":token,"admin_user":ADMIN_USER})

@app.post("/settings/full")
def settings_full(req:Request,domain:str=Form(""),admin_password_new:str=Form(""),sub_token:str=Form("")):
    guard(req)
    if domain.strip(): set_setting("public_domain",domain.strip())
    if admin_password_new.strip(): set_setting("admin_password",admin_password_new.strip())
    if sub_token.strip(): set_setting("sub_token",sub_token.strip())
    ensure_nginx()
    return RedirectResponse("/settings",303)

@app.get("/health")
def health(): return {"ok":True}

