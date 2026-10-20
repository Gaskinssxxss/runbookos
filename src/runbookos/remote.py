"""Fixed remote dispatcher. The request contains registry IDs and JSON args, never shell text."""

import base64
import json
import shlex

REMOTE_SOURCE = r"""import base64, http.client, ipaddress, json, os, re, shutil, socket, ssl, struct, subprocess, sys, time
def emit(ok, data=None, error=None, uncertain=False):
    print(json.dumps({"ok": ok, "data": data or {}, "error": error, "uncertain": uncertain}, separators=(",", ":")))
def probe_endpoint(action, args, timeout):
    endpoint=args.get("_endpoint")
    if not isinstance(endpoint,dict) or set(endpoint) != {"protocol","address","port","path"}: raise ValueError("invalid endpoint")
    address=endpoint["address"]
    if not isinstance(address,str) or not re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}",address): raise ValueError("endpoint address denied")
    ip=ipaddress.ip_address(address)
    if not isinstance(ip,ipaddress.IPv4Address) or not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified: raise ValueError("endpoint address denied")
    port=endpoint["port"]
    if isinstance(port,bool) or not isinstance(port,int) or not 1 <= port <= 65535: raise ValueError("endpoint port denied")
    protocol=endpoint["protocol"]
    endpoint_id=args.get("endpoint_id")
    if not isinstance(endpoint_id,str) or not re.fullmatch(r"[a-z][a-z0-9_-]{1,62}",endpoint_id): raise ValueError("endpoint ID denied")
    expected={"network.tcp_connect":{"tcp","http","https","postgresql"},"network.reachability":{"tcp","http","https","postgresql"},"http.readiness":{"http","https"},"postgresql.protocol_available":{"postgresql"}}
    if protocol not in expected.get(action,set()): raise ValueError("endpoint protocol denied")
    if not isinstance(timeout,int) or isinstance(timeout,bool) or not 1 <= timeout <= 10: raise ValueError("probe timeout denied")
    start=time.monotonic()
    data={"endpoint_id":endpoint_id,"address":address,"port":port,"protocol":protocol}
    if action in ("network.tcp_connect","network.reachability"):
        try:
            with socket.create_connection((address,port),timeout=timeout): connected=True
            error=None
        except (OSError,TimeoutError) as exc:
            connected=False
            error=type(exc).__name__
        data.update({"connected":connected,"reachable":connected,"duration_seconds":round(time.monotonic()-start,3)})
        if action == "network.tcp_connect": data["tcp_connected"]=connected
        return data,error
    if action == "http.readiness":
        path=endpoint["path"]
        if not isinstance(path,str) or not re.fullmatch(r"/[A-Za-z0-9_./-]{0,127}",path) or ".." in path.split("/") or path.startswith("//"): raise ValueError("HTTP path denied")
        connection=None
        try:
            if protocol == "https":
                connection=http.client.HTTPSConnection(address,port,timeout=timeout,context=ssl.create_default_context())
            else:
                connection=http.client.HTTPConnection(address,port,timeout=timeout)
            connection.request("GET",path,headers={"Connection":"close","User-Agent":"RunbookOS-readiness/1"})
            response=connection.getresponse()
            status=response.status
            content_type=response.getheader("Content-Type","")[:100]
            data.update({"http_status":status,"ready":200 <= status < 300,"redirect_followed":False,"content_type":content_type,"body_bytes_sampled":0,"tls_verified":protocol == "https","duration_seconds":round(time.monotonic()-start,3)})
            return data,None
        except (OSError,http.client.HTTPException,ssl.SSLError,TimeoutError) as exc:
            data.update({"http_status":None,"ready":False,"redirect_followed":False,"content_type":"","body_bytes_sampled":0,"tls_verified":protocol == "https","duration_seconds":round(time.monotonic()-start,3)})
            return data,type(exc).__name__
        finally:
            if connection is not None: connection.close()
    if action == "postgresql.protocol_available":
        try:
            with socket.create_connection((address,port),timeout=timeout) as connection:
                connection.settimeout(timeout)
                connection.sendall(struct.pack("!II",8,80877103))
                response=connection.recv(1)
            available=response in (b"S",b"N")
            code=response.decode("ascii","replace")[:1] or None
            error=None if available else "no PostgreSQL SSL negotiation response"
        except (OSError,TimeoutError) as exc:
            available=False
            code=None
            error=type(exc).__name__
        data.update({"protocol_available":available,"ssl_supported":code == "S","ssl_negotiation_response":code,"authentication_attempted":False,"database_readiness_verified":False,"duration_seconds":round(time.monotonic()-start,3)})
        return data,error
    raise ValueError("unsupported diagnostic action")
try:
    req=json.loads(base64.b64decode(sys.argv[1]))
    action=req.get("action")
    args=req.get("arguments", {})
    timeout=req.get("timeout_seconds", 15)
    unit=args.get("unit", "")
    if not isinstance(timeout, int) or timeout < 1 or timeout > 300: raise ValueError("invalid timeout")
    if action in ("systemd.is_active", "systemd.restart"):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}\.(service|timer)", unit): raise ValueError("invalid unit")
        cmd=["/usr/bin/systemctl", "is-active" if action.endswith("is_active") else "restart", unit]
        try:
            r=subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
            if action.endswith("is_active"):
                active=r.returncode == 0 and r.stdout.strip() == "active"
                emit(True, {"unit":unit,"active":active,"state":r.stdout.strip() or r.stderr.strip()})
            else:
                emit(r.returncode == 0, {"unit":unit,"restarted":r.returncode == 0,"detail":r.stderr.strip()}, None if r.returncode == 0 else "systemctl returned non-zero", False)
        except subprocess.TimeoutExpired:
            emit(False, {"unit":unit}, "action timeout", action.endswith("restart"))
    elif action == "systemd.failed_units":
        r=subprocess.run(["/usr/bin/systemctl","list-units","--failed","--no-legend","--plain"],capture_output=True,text=True,timeout=timeout,check=False)
        units=[line.split()[0] for line in r.stdout.splitlines() if line.split()]
        emit(r.returncode == 0, {"units":units}, r.stderr.strip() or None)
    elif action == "os.uptime":
        raw=open("/proc/uptime",encoding="ascii").read().split()[0]
        emit(True,{"seconds":int(float(raw))})
    elif action == "os.memory":
        values={}
        for line in open("/proc/meminfo",encoding="ascii"):
            key, value=line.split(":",1)
            parts=value.split()
            if parts and parts[0].isdigit(): values[key]=int(parts[0])*(1024 if len(parts)>1 and parts[1]=="kB" else 1)
        emit(True,{"total_bytes":values.get("MemTotal",0),"available_bytes":values.get("MemAvailable",0),"swap_total_bytes":values.get("SwapTotal",0),"swap_free_bytes":values.get("SwapFree",0)})
    elif action == "os.disk":
        path=args.get("path","/")
        if not isinstance(path,str) or not path.startswith("/") or "\x00" in path: raise ValueError("invalid path")
        d=shutil.disk_usage(path)
        emit(True,{"path":path,"total_bytes":d.total,"used_bytes":d.used,"free_bytes":d.free,"percent":int(d.used*100/d.total) if d.total else 0})
    elif action == "network.interfaces":
        r=subprocess.run(["/usr/sbin/ip","-j","address","show"],capture_output=True,text=True,timeout=timeout,check=False)
        emit(r.returncode == 0,{"interfaces":json.loads(r.stdout) if r.returncode == 0 else []},r.stderr.strip() or None)
    elif action == "network.routes":
        r=subprocess.run(["/usr/sbin/ip","-j","route","show"],capture_output=True,text=True,timeout=timeout,check=False)
        emit(r.returncode == 0,{"routes":json.loads(r.stdout) if r.returncode == 0 else []},r.stderr.strip() or None)
    elif action in ("network.tcp_connect","network.reachability","http.readiness","postgresql.protocol_available"):
        data,error=probe_endpoint(action,args,timeout)
        emit(True,data,error)
    else:
        emit(False,{},"action is not in the remote registry")
except subprocess.TimeoutExpired:
    emit(False,{},"action timeout",False)
except Exception as exc:
    emit(False,{},type(exc).__name__+": "+str(exc))
"""

REMOTE_CODE_B64 = base64.b64encode(REMOTE_SOURCE.encode()).decode()


def command(request: dict) -> str:
    payload = base64.b64encode(
        json.dumps(request, separators=(",", ":"), sort_keys=True).encode()
    ).decode()
    wrapper = f"import base64;exec(compile(base64.b64decode('{REMOTE_CODE_B64}'),'<runbookos-remote>','exec'))"
    # OpenSSH joins remote argv into a shell command. shlex.quote is used only
    # for this fixed interpreter invocation; untrusted values are base64 JSON.
    return shlex.join(["python3", "-c", wrapper, payload])
