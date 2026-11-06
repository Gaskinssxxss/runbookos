"""Fixed remote dispatcher. The request contains registry IDs and JSON args, never shell text."""

import base64
import json
import shlex

REMOTE_SOURCE = r"""import base64, http.client, ipaddress, json, os, re, selectors, shutil, socket, ssl, struct, subprocess, sys, time
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
def bounded_stdout(argv, timeout, byte_limit):
    try:
        process=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,close_fds=True,start_new_session=True)
    except OSError as exc:
        return None,type(exc).__name__
    selector=selectors.DefaultSelector()
    output=bytearray()
    deadline=time.monotonic()+timeout
    try:
        selector.register(process.stdout,selectors.EVENT_READ)
        while selector.get_map():
            remaining=deadline-time.monotonic()
            events=selector.select(remaining) if remaining > 0 else []
            if not events:
                process.kill()
                process.wait()
                return None,"TimeoutError"
            for key,_ in events:
                chunk=os.read(key.fd,min(8192,byte_limit-len(output)+1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output.extend(chunk)
                if len(output)>byte_limit:
                    process.kill()
                    process.wait()
                    return None,"output_limit"
        try:
            code=process.wait(timeout=max(0.01,deadline-time.monotonic()))
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            return None,"TimeoutError"
        if code != 0:
            return None,"command_failed"
        return bytes(output),None
    finally:
        selector.close()
        if process.stdout is not None:
            process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait()
def safe_log_message(value):
    text=value if isinstance(value,str) else ""
    text=re.sub(r"(?i)(authorization\s*[:=]\s*bearer\s+)\S+",r"\1[REDACTED]",text)
    text=re.sub(r"(?i)\b(bearer\s+)\S+",r"\1[REDACTED]",text)
    text=re.sub(r"(?i)\b(password|passwd|token|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+",r"\1=[REDACTED]",text)
    text=re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----","[REDACTED PRIVATE KEY]",text,flags=re.S)
    text="".join(ch for ch in text if ch in "\t" or ch.isprintable())
    return text[:1024]
try:
    req=json.loads(base64.b64decode(sys.argv[1]))
    action=req.get("action")
    args=req.get("arguments", {})
    timeout=req.get("timeout_seconds", 15)
    unit=args.get("unit", "")
    if not isinstance(timeout, int) or timeout < 1 or timeout > 300: raise ValueError("invalid timeout")
    if action in ("systemd.is_active", "systemd.restart", "systemd.start"):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}\.(service|timer)", unit): raise ValueError("invalid unit")
        if action.endswith("is_active"):
            cmd=["/usr/bin/systemctl", "is-active", unit]
        elif action == "systemd.restart":
            # Mutating unit control must use the target's explicit, non-interactive
            # least-privilege sudoers grant. The action/policy layer has already
            # validated the registered action and target-scoped unit allowlist.
            cmd=["/usr/bin/sudo", "-n", "/usr/bin/systemctl", "restart", unit]
        else:
            cmd=["/usr/bin/sudo", "-n", "/usr/bin/systemctl", "start", unit]
        try:
            r=subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
            if action.endswith("is_active"):
                active=r.returncode == 0 and r.stdout.strip() == "active"
                emit(True, {"unit":unit,"active":active,"state":r.stdout.strip() or r.stderr.strip()})
            else:
                successful = r.returncode == 0
                result_key = "started" if action == "systemd.start" else "restarted"
                emit(successful, {"unit":unit,result_key:successful,"detail":r.stderr.strip()}, None if successful else "systemctl returned non-zero", False)
        except subprocess.TimeoutExpired:
            emit(False, {"unit":unit}, "action timeout", action in ("systemd.restart", "systemd.start"))
    elif action in ("config.restore_fixture", "dns.restore_fixture", "network.restore_fixture", "storage.release_fixture", "resource.restore_fixture", "dependency.restore_fixture", "application.recover_worker", "postgresql.start_fixture"):
        fixture_id=args.get("fixture_id")
        cluster=args.get("cluster")
        helper_calls={
            ("dependency.restore_fixture","backend_service"): ["restore-dependency","backend_service"],
            ("application.recover_worker","worker_service"): ["recover-worker","worker_service"],
            ("config.restore_fixture","app_config"):["restore-config","app_config"],
            ("config.restore_fixture","proxy_config"):["restore-config","proxy_config"],
            ("dns.restore_fixture","resolver_config"):["restore-dns","resolver_config"],
            ("network.restore_fixture","isolated_link"):["restore-network","isolated_link"],
            ("storage.release_fixture","bounded_volume"):["release-storage","bounded_volume"],
            ("resource.restore_fixture","worker_quota"):["restore-resource","worker_quota"],
            ("postgresql.start_fixture","16-b04"): ["start-postgres","16-b04"],
        }
        key=(action,fixture_id if action != "postgresql.start_fixture" else cluster)
        if key not in helper_calls: raise ValueError("campaign fixture recovery identity denied")
        cmd=["/usr/bin/sudo","-n","/usr/local/sbin/runbookos-campaign-b04-recover",*helper_calls[key]]
        try:
            r=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout,check=False)
            try: outcome=json.loads(r.stdout)
            except (json.JSONDecodeError,TypeError): outcome={}
            valid=isinstance(outcome,dict) and set(outcome)=={"ok","data","error"} and type(outcome.get("ok")) is bool and isinstance(outcome.get("data"),dict) and (outcome.get("error") is None or isinstance(outcome.get("error"),str))
            if not valid:
                emit(False,{"action":action,"fixture_id":fixture_id or cluster},"fixture_helper_invalid_response")
            else:
                emit(bool(outcome["ok"] and r.returncode==0),outcome["data"],outcome.get("error") or (None if r.returncode==0 else "fixture recovery returned non-zero"))
        except subprocess.TimeoutExpired:
            emit(False,{"action":action,"fixture_id":fixture_id or cluster},"action timeout",True)
    elif action == "application.inspect_fixture":
        if args.get("fixture_id") != "web_stack": raise ValueError("fixture inspection identity denied")
        base="/var/lib/runbookos-campaign-b04/config/"
        observations={}
        expected={"app":{"backend_host":"backend.b04.test","backend_port":18911},"proxy":{"upstream_host":"10.60.20.10","upstream_port":18891}}
        for name,manifest in expected.items():
            try:
                path=base+name+".json"
                if os.path.islink(path) or os.stat(path).st_size>4096: raise ValueError("config identity")
                with open(path,encoding="utf-8") as stream: actual=json.load(stream)
                valid=actual==manifest
            except (OSError,ValueError): valid=False
            observations[name]={"configuration_valid":valid}
        allowed={"ready","application-configuration-invalid","worker-resource-pressure","worker-unavailable","storage-capacity-exhausted","isolated-network-not-ready","proxy-upstream-unavailable","dependency-ConnectionRefusedError","dependency-TimeoutError","isolated-network-TimeoutError","isolated-network-OSError"}
        for name,port in (("app",18891),("proxy",18892)):
            connection=http.client.HTTPConnection("10.60.20.10",port,timeout=min(timeout/2,2))
            try:
                connection.request("GET","/health",headers={"Connection":"close"})
                response=connection.getresponse(); body=response.read(64).decode("ascii","replace").strip()
                observations[name].update({"http_status":response.status,"health_code":body if body in allowed else "unrecognized-response"})
            except (OSError,http.client.HTTPException):
                observations[name].update({"http_status":None,"health_code":"probe-unavailable"})
            finally: connection.close()
        emit(True,{"fixture_id":"web_stack","observations":observations})
    elif action == "resource.inspect_fixture":
        if args.get("fixture_id") != "worker_quota": raise ValueError("fixture resource identity denied")
        r=subprocess.run(["/usr/bin/systemctl","show","runbookos-campaign-b04-worker.service","--property=ActiveState,CPUQuotaPerSecUSec,CPUUsageNSec"],capture_output=True,text=True,timeout=timeout,check=False)
        properties=dict(line.split("=",1) for line in r.stdout.splitlines() if "=" in line)
        raw_quota=properties.get("CPUQuotaPerSecUSec","")
        quota_match=re.fullmatch(r"([0-9.]+)(us|ms|s)",raw_quota)
        quota_percent=(float(quota_match[1])*{"us":0.0001,"ms":0.1,"s":100}[quota_match[2]]) if quota_match else None
        emit(r.returncode==0,{"fixture_id":"worker_quota","unit":"runbookos-campaign-b04-worker.service","properties":properties,"cpu_quota_percent":quota_percent,"baseline_cpu_quota_percent":30,"quota_below_baseline":None if quota_percent is None else quota_percent<30},None if r.returncode==0 else "fixture_resource_read_failed")
    elif action == "systemd.failed_units":
        r=subprocess.run(["/usr/bin/systemctl","list-units","--failed","--no-legend","--plain"],capture_output=True,text=True,timeout=timeout,check=False)
        units=[line.split()[0] for line in r.stdout.splitlines() if line.split()]
        emit(r.returncode == 0, {"units":units}, r.stderr.strip() or None)
    elif action == "systemd.journal_tail":
        unit=args.get("unit")
        lines=args.get("lines",20)
        if not isinstance(unit,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}\.(service|timer)",unit): raise ValueError("journal unit denied")
        if isinstance(lines,bool) or not isinstance(lines,int) or not 1 <= lines <= 50: raise ValueError("journal line limit denied")
        if not isinstance(timeout,int) or isinstance(timeout,bool) or not 1 <= timeout <= 10: raise ValueError("journal timeout denied")
        raw,error=bounded_stdout(["/usr/bin/journalctl","--unit",unit,"--lines",str(lines),"--no-pager","--output=json"],timeout,65536)
        if error:
            emit(False,{"unit":unit,"entries":[]},error)
        else:
            entries=[]
            for line in raw.splitlines():
                try:
                    item=json.loads(line)
                except (json.JSONDecodeError,UnicodeDecodeError):
                    emit(False,{"unit":unit,"entries":[]},"invalid_journal_record")
                    break
                entries.append({"timestamp_usec":str(item.get("__REALTIME_TIMESTAMP",""))[:24],"priority":str(item.get("PRIORITY",""))[:2],"message":safe_log_message(item.get("MESSAGE",""))})
            else:
                emit(True,{"unit":unit,"entries":entries,"entry_count":len(entries),"output_truncated":False})
    elif action == "network.resolver_config":
        try:
            with open("/etc/resolv.conf",encoding="utf-8",errors="replace") as stream:
                content=stream.read(4097)
        except OSError as exc:
            emit(False,{"nameservers":[],"search_domains":[]},type(exc).__name__)
        else:
            if len(content)>4096:
                emit(False,{"nameservers":[],"search_domains":[]},"resolver_config_exceeds_limit")
            else:
                nameservers=[]
                domains=[]
                for raw_line in content.splitlines()[:128]:
                    tokens=raw_line.split("#",1)[0].split()
                    if not tokens: continue
                    if tokens[0]=="nameserver" and len(tokens)==2:
                        try: address=str(ipaddress.ip_address(tokens[1]))
                        except ValueError: continue
                        if address not in nameservers and len(nameservers)<8: nameservers.append(address)
                    elif tokens[0] in ("search","domain"):
                        for domain in tokens[1:]:
                            if re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?",domain) and domain not in domains and len(domains)<8:
                                domains.append(domain.lower())
                emit(True,{"nameservers":nameservers,"search_domains":domains,"nameserver_count":len(nameservers),"search_domain_count":len(domains)})
    elif action == "dns.resolve_fixture":
        if args.get("fixture_id") != "b04_resolver": raise ValueError("DNS fixture identity denied")
        ident=os.urandom(2)
        query=ident+struct.pack("!HHHHH",0x0100,1,0,0,0)+b"\x07backend\x03b04\x04test\x00\x00\x01\x00\x01"
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                client.settimeout(min(timeout,3))
                client.sendto(query,("10.60.20.10",18954))
                response,_=client.recvfrom(512)
            if len(response)<16 or response[:2]!=ident or int.from_bytes(response[6:8],"big")!=1 or response[3]&15:
                raise ValueError("invalid DNS fixture response")
            address=socket.inet_ntoa(response[-4:])
            emit(True,{"fixture_id":"b04_resolver","name":"backend.b04.test","address":address,"fixture_backend_address":"10.60.20.10","matches_fixture_backend":address=="10.60.20.10"})
        except (OSError,TimeoutError) as exc:
            emit(False,{"fixture_id":"b04_resolver","name":"backend.b04.test","address":None},type(exc).__name__)
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
