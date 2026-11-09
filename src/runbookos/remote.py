"""Fixed remote dispatcher. The request contains registry IDs and JSON args, never shell text."""

import base64
import json
import shlex

REMOTE_SOURCE = r"""import base64, hashlib, http.client, ipaddress, json, math, os, pwd, re, selectors, socket, ssl, stat, struct, subprocess, sys, time
def emit(ok, data=None, error=None, uncertain=False):
    print(json.dumps({"ok": ok, "data": data or {}, "error": error, "uncertain": uncertain}, separators=(",", ":")))
PG_QUERIES={
    "readiness": "SELECT json_build_object('query_succeeded',true,'in_recovery',pg_is_in_recovery())::text",
    "connections": "SELECT json_build_object('stats_visible',pg_has_role(current_user,'pg_read_all_stats','MEMBER'),'active',count(*) FILTER (WHERE state='active'),'idle',count(*) FILTER (WHERE state='idle'),'total',count(*),'max_connections',current_setting('max_connections')::int,'superuser_reserved',current_setting('superuser_reserved_connections')::int,'reserved_connections',coalesce(current_setting('reserved_connections',true)::int,0))::text FROM pg_stat_activity",
    "replication": "SELECT json_build_object('stats_visible',pg_has_role(current_user,'pg_read_all_stats','MEMBER'),'in_recovery',pg_is_in_recovery(),'sender_count',(SELECT count(*) FROM pg_stat_replication),'receiver_count',(SELECT count(*) FROM pg_stat_wal_receiver),'max_replay_lag_seconds',(SELECT max(extract(epoch from replay_lag)) FROM pg_stat_replication))::text",
    "sessions": "SELECT json_build_object('stats_visible',pg_has_role(current_user,'pg_read_all_stats','MEMBER'),'active',count(*) FILTER (WHERE state='active'),'idle',count(*) FILTER (WHERE state='idle'),'long_transaction_count',count(*) FILTER (WHERE xact_start IS NOT NULL AND clock_timestamp()-xact_start > interval '5 minutes'),'long_query_count',count(*) FILTER (WHERE state='active' AND query_start IS NOT NULL AND clock_timestamp()-query_start > interval '5 minutes'),'waiting_count',count(*) FILTER (WHERE wait_event_type IS NOT NULL),'oldest_transaction_seconds',max(extract(epoch from clock_timestamp()-xact_start)))::text FROM pg_stat_activity",
}
def valid_probe_metadata(endpoint):
    if not isinstance(endpoint,dict): return False
    base={'protocol','address','port','path'}
    dns=base|{'dns_name','resolver_address'}
    legacy=dns|{'local_listener'}
    current=legacy|{'database_name','database_user','credential_id','pressure_storage_ids'}
    if set(endpoint) not in (base,dns,legacy,current): return False
    protocol=endpoint.get('protocol')
    if protocol not in ('tcp','http','https','postgresql') or not valid_private_ipv4(endpoint.get('address')) or type(endpoint.get('port')) is not int or not 1<=endpoint['port']<=65535: return False
    path=endpoint.get('path')
    if protocol in ('http','https'):
        if not isinstance(path,str) or not re.fullmatch(r'/[A-Za-z0-9_./-]{0,127}',path) or path.startswith('//') or '..' in path.split('/'): return False
    elif path is not None: return False
    name=endpoint.get('dns_name'); resolver=endpoint.get('resolver_address')
    if name is not None and not valid_dns_name(name): return False
    if resolver is not None and (name is None or not valid_private_ipv4(resolver)): return False
    if 'local_listener' in endpoint and type(endpoint['local_listener']) is not bool: return False
    database=endpoint.get('database_name'); user=endpoint.get('database_user'); credential=endpoint.get('credential_id')
    if any(value is not None for value in (database,user,credential)):
        if protocol!='postgresql' or name is None or not isinstance(database,str) or not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_]{0,62}',database) or not isinstance(user,str) or not re.fullmatch(r'[a-z_][a-z0-9_]{0,62}',user) or not isinstance(credential,str) or not re.fullmatch(r'[a-z][a-z0-9_-]{1,62}',credential): return False
    storage=endpoint.get('pressure_storage_ids',[])
    if type(storage) is not list or len(storage)>8 or len(storage)!=len(set(str(value) for value in storage)) or any(not isinstance(value,str) or not re.fullmatch(r'[a-z][a-z0-9_-]{1,62}',value) for value in storage) or storage and protocol!='postgresql': return False
    return True
def open_postgresql_credential(home,credential):
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    parent=os.open(home,flags)
    try:
        if os.fstat(parent).st_uid!=os.getuid(): raise OSError('home ownership denied')
        for part in ('.config','runbookos','pgpass'):
            child=os.open(part,flags,dir_fd=parent)
            try:
                info=os.fstat(child)
                if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode & 0o077: raise OSError('credential directory denied')
            except BaseException:
                os.close(child); raise
            os.close(parent); parent=child
        fd=os.open(credential,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode & 0o077 or info.st_size>4096: raise OSError('credential file denied')
        except BaseException:
            os.close(fd); raise
        return fd
    finally: os.close(parent)
def bounded_postgresql(argv,env,timeout,credential_fd):
    try: process=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,pass_fds=(credential_fd,),start_new_session=True)
    except OSError: return None,b'',b'','psql_unavailable'
    output={process.stdout:bytearray(),process.stderr:bytearray()}
    limits={process.stdout:4096,process.stderr:256}
    selector=selectors.DefaultSelector(); deadline=time.monotonic()+timeout
    try:
        for stream in output: selector.register(stream,selectors.EVENT_READ)
        while selector.get_map():
            remaining=deadline-time.monotonic()
            if remaining<=0: return None,b'',b'','query_timeout'
            events=selector.select(remaining)
            if not events: return None,b'',b'','query_timeout'
            for key,_ in events:
                stream=key.fileobj
                chunk=os.read(stream.fileno(),min(4096,limits[stream]-len(output[stream])+1))
                if not chunk: selector.unregister(stream)
                else:
                    output[stream].extend(chunk)
                    if len(output[stream])>limits[stream]: return None,b'',b'','output_limit_exceeded'
        remaining=deadline-time.monotonic()
        if remaining<=0: return None,b'',b'','query_timeout'
        return process.wait(timeout=remaining),bytes(output[process.stdout]),bytes(output[process.stderr]),None
    except (OSError,subprocess.TimeoutExpired): return None,b'',b'','query_timeout'
    finally:
        selector.close()
        if process.poll() is None:
            process.kill(); process.wait()
        process.stdout.close(); process.stderr.close()
def postgresql_inspect(args,timeout):
    endpoint=args.get('_endpoint'); endpoint_id=args.get('endpoint_id'); check=args.get('check')
    if not valid_probe_metadata(endpoint) or check not in PG_QUERIES or not isinstance(endpoint_id,str) or not re.fullmatch(r'[a-z][a-z0-9_-]{1,62}',endpoint_id): raise ValueError('PostgreSQL check denied')
    address=endpoint.get('address'); name=endpoint.get('dns_name'); port=endpoint.get('port'); database=endpoint.get('database_name'); user=endpoint.get('database_user'); credential=endpoint.get('credential_id')
    if endpoint.get('protocol')!='postgresql' or not valid_private_ipv4(address) or not valid_dns_name(name) or type(port) is not int or not 1<=port<=65535 or not isinstance(database,str) or not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_]{0,62}',database) or not isinstance(user,str) or not re.fullmatch(r'[a-z_][a-z0-9_]{0,62}',user) or not isinstance(credential,str) or not re.fullmatch(r'[a-z][a-z0-9_-]{1,62}',credential) or type(timeout) is not int or not 1<=timeout<=10: raise ValueError('PostgreSQL source denied')
    data={'endpoint_id':endpoint_id,'check':check,'status':'unknown','authentication_available':None,'query_succeeded':False,'sql_health_authorized':True,'tcp_reachable':None,'protocol_responsive':None}
    home=pwd.getpwuid(os.getuid()).pw_dir
    try: credential_fd=open_postgresql_credential(home,credential)
    except OSError: return data,'credential_unavailable'
    if not os.path.isfile('/usr/bin/psql'):
        os.close(credential_fd); return data,'psql_unavailable'
    env={'PATH':'/usr/bin:/bin','HOME':home,'PGPASSFILE':'/proc/self/fd/'+str(credential_fd),'PGHOST':name,'PGHOSTADDR':address,'PGPORT':str(port),'PGDATABASE':database,'PGUSER':user,'PGSSLMODE':'verify-full','PGCONNECT_TIMEOUT':str(min(timeout,5)),'PGOPTIONS':'-c default_transaction_read_only=on -c statement_timeout=5000 -c lock_timeout=1000 -c search_path=pg_catalog'}
    argv=['/usr/bin/psql','-X','-w','-q','-t','-A','-v','ON_ERROR_STOP=1','-v','VERBOSITY=sqlstate','-c',PG_QUERIES[check]]
    started=time.monotonic()
    try: returncode,stdout,stderr,command_error=bounded_postgresql(argv,env,timeout,credential_fd)
    finally: os.close(credential_fd)
    data['duration_seconds']=round(time.monotonic()-started,3)
    if command_error: return data,command_error
    if returncode!=0:
        if b'28P01' in stderr or b'28000' in stderr: error='authentication_denied'
        elif b'42501' in stderr: error='permission_denied'
        else: error='query_unavailable'
        return data,error
    data['authentication_available']=True
    try:
        line=stdout.decode('utf-8').strip()
        if '\n' in line: raise ValueError('multiple rows')
        values=json.loads(line)
        if not isinstance(values,dict): raise ValueError('invalid row')
        fields={'readiness':{'query_succeeded','in_recovery'},'connections':{'stats_visible','active','idle','total','max_connections','superuser_reserved','reserved_connections'},'replication':{'stats_visible','in_recovery','sender_count','receiver_count','max_replay_lag_seconds'},'sessions':{'stats_visible','active','idle','long_transaction_count','long_query_count','waiting_count','oldest_transaction_seconds'}}[check]
        if set(values)!=fields or any(type(v) not in (int,float,bool,type(None)) for v in values.values()): raise ValueError('invalid fields')
        if any(type(v) in (int,float) and (not math.isfinite(v) or v<0 or v>1000000000) for v in values.values()): raise ValueError('invalid value')
        if check=='readiness' and (values['query_succeeded'] is not True or type(values['in_recovery']) is not bool): raise ValueError('invalid readiness')
        if check!='readiness' and type(values['stats_visible']) is not bool: raise ValueError('invalid privilege status')
        if check=='connections' and any(type(values[k]) is not int for k in ('active','idle','total','max_connections','superuser_reserved','reserved_connections')): raise ValueError('invalid connection counts')
        if check=='sessions' and (any(type(values[k]) is not int for k in ('active','idle','long_transaction_count','long_query_count','waiting_count')) or values['oldest_transaction_seconds'] is not None and type(values['oldest_transaction_seconds']) not in (int,float)): raise ValueError('invalid session counts')
        if check=='replication' and (type(values['in_recovery']) is not bool or any(type(values[k]) is not int for k in ('sender_count','receiver_count')) or values['max_replay_lag_seconds'] is not None and type(values['max_replay_lag_seconds']) not in (int,float)): raise ValueError('invalid replication counts')
    except (UnicodeError,ValueError): return data,'invalid_query_response'
    data.update(values); data['query_succeeded']=True; data['status']='observed'
    if check != 'readiness' and values['stats_visible'] is not True:
        data['status']='unknown'; data['query_succeeded']=False
        for field in fields-{'stats_visible'}: data.pop(field,None)
        return data,'statistics_privilege_unavailable'
    if check=='connections':
        maximum=values['max_connections']; reserved=values['superuser_reserved']+values['reserved_connections']; total=values['total']
        if not all(type(v) is int for v in (maximum,reserved,total,values['active'],values['idle'])) or maximum<=0 or reserved>=maximum: return data,'invalid_query_response'
        data['utilization_percent']=round(total*100/maximum,2); data['possible_exhaustion']=total>=maximum-reserved
    if check=='replication':
        if type(values['in_recovery']) is not bool or type(values['sender_count']) is not int or type(values['receiver_count']) is not int: return data,'invalid_query_response'
        data['role']='standby' if values['in_recovery'] else 'primary'; data['replication_evidence']='observed' if values['sender_count'] or values['receiver_count'] else 'missing'
    return data,None
def application_diagnostic(action,args,timeout):
    app_id=args.get("application_id"); app=args.get("_application")
    if not isinstance(app_id,str) or not re.fullmatch(r"[a-z][a-z0-9_-]{1,62}",app_id) or not isinstance(app,dict): raise ValueError("application identity denied")
    if not isinstance(timeout,int) or isinstance(timeout,bool) or not 1<=timeout<=10: raise ValueError("application timeout denied")
    start=time.monotonic()
    if action in ("application.health","application.queue_health"):
        endpoint=args.get("_endpoint")
        if not isinstance(endpoint,dict) or not {"protocol","address","port","path"}<=set(endpoint): raise ValueError("application endpoint denied")
        protocol=endpoint.get("protocol"); address=endpoint.get("address"); port=endpoint.get("port"); path=endpoint.get("path"); name=endpoint.get("dns_name")
        if protocol not in ("http","https") or not valid_private_ipv4(address) or type(port) is not int or not 1<=port<=65535 or not isinstance(path,str) or not re.fullmatch(r"/[A-Za-z0-9_./-]{0,127}",path) or path.startswith("//") or ".." in path.split("/"): raise ValueError("application endpoint denied")
        if name is not None and not valid_dns_name(name): raise ValueError("application hostname denied")
        if protocol=="https" and name is None: raise ValueError("TLS hostname denied")
        expected_id=app.get("health_endpoint_id") if action=="application.health" else app.get("queue_endpoint_id")
        if args.get("_endpoint_id")!=expected_id: raise ValueError("application endpoint binding denied")
        data={"application_id":app_id,"endpoint_id":expected_id,"http_status":None,"status":"unknown","redirect_followed":False,"body_bytes_sampled":0,"tls_verified":False,"duration_seconds":None}
        connection=http.client.HTTPConnection(address,port,timeout=timeout)
        try:
            if protocol=="https":
                connection.connect()
                connection.sock=ssl.create_default_context().wrap_socket(connection.sock,server_hostname=name)
                data["tls_verified"]=True
            connection.request("GET",path,headers={"Connection":"close","Host":name or address,"User-Agent":"RunbookOS-application/1"})
            response=connection.getresponse(); code=response.status
            data["http_status"]=code
            if action=="application.health":
                content_type=response.getheader("Content-Type","").split(";",1)[0].strip().lower()
                data["content_type_category"]="json" if content_type=="application/json" else "html" if content_type=="text/html" else "text" if content_type=="text/plain" else "other" if content_type else "missing"
                data["status"]="healthy" if 200<=code<300 else "redirect" if 300<=code<400 else "unhealthy"
            else:
                depth=response.getheader("X-Queue-Depth"); age=response.getheader("X-Queue-Oldest-Age-Seconds")
                max_depth=app.get("queue_max_depth"); max_age=app.get("queue_max_age_seconds")
                if type(max_depth) is not int or type(max_age) is not int or not 0<=max_depth<=1000000 or not 0<=max_age<=86400: raise ValueError("queue bounds denied")
                if 200<=code<300 and isinstance(depth,str) and isinstance(age,str) and re.fullmatch(r"[0-9]{1,7}",depth) and re.fullmatch(r"[0-9]{1,7}",age) and int(depth)<=1000000 and int(age)<=86400:
                    data["depth"]=int(depth); data["oldest_age_seconds"]=int(age)
                    data["status"]="backlog" if data["depth"]>max_depth or data["oldest_age_seconds"]>max_age else "healthy"
                elif not 200<=code<300: data["status"]="unhealthy"
            return data,None
        except (TimeoutError,socket.timeout): return data,"timeout"
        except ssl.SSLError: return data,"tls_invalid"
        except (OSError,http.client.HTTPException): return data,"endpoint_unavailable"
        finally:
            data["duration_seconds"]=round(time.monotonic()-start,3)
            connection.close()
    storage=args.get("_storage")
    if not isinstance(storage,dict) or set(storage)!={"path","kind"} or storage.get("kind")!="file": raise ValueError("application artifact denied")
    path=storage.get("path")
    if not isinstance(path,str) or not path.startswith("/") or path.startswith("//") or path.endswith("/") or any(part in ("",".","..") for part in path.split("/")[1:]) or len(path)>256: raise ValueError("application artifact path denied")
    expected_id=app.get("config_storage_id") if action=="application.config_fingerprint" else app.get("version_storage_id")
    if args.get("_storage_id")!=expected_id: raise ValueError("application artifact binding denied")
    data={"application_id":app_id,"storage_id":expected_id,"status":"unknown","contents_included":False,"duration_seconds":None}
    limit=65536 if action=="application.config_fingerprint" else 64
    try:
        parent=storage_fd(os.path.dirname(path),True)
        try: fd=os.open(os.path.basename(path),os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        finally: os.close(parent)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>limit: return data,"artifact_unavailable"
            content=os.read(fd,limit+1)
            after=os.fstat(fd)
            if len(content)!=info.st_size or (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)!=(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns): return data,"artifact_changed"
        finally: os.close(fd)
        if action=="application.config_fingerprint":
            expected=app.get("expected_config_sha256")
            if not isinstance(expected,str) or not re.fullmatch(r"[a-f0-9]{64}",expected): raise ValueError("config baseline denied")
            data["sha256"]=hashlib.sha256(content).hexdigest(); data["status"]="matched" if data["sha256"]==expected else "drift"
        else:
            expected=app.get("expected_version")
            if not isinstance(expected,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}",expected): raise ValueError("version baseline denied")
            version=content.decode("ascii").strip()
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}",version): return data,"invalid_version_metadata"
            data["version"]=version; data["status"]="matched" if version==expected else "drift"
        return data,None
    except (OSError,UnicodeError): return data,"artifact_unavailable"
    finally: data["duration_seconds"]=round(time.monotonic()-start,3)
def probe_endpoint(action, args, timeout):
    endpoint=args.get("_endpoint")
    if not isinstance(endpoint,dict) or not {"protocol","address","port","path"}<=set(endpoint): raise ValueError("invalid endpoint")
    if not valid_private_ipv4(endpoint["address"]): raise ValueError("endpoint address denied")
    if not valid_probe_metadata(endpoint): raise ValueError("invalid endpoint")
    address=endpoint["address"]
    if not isinstance(address,str) or not re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}",address): raise ValueError("endpoint address denied")
    ip=ipaddress.ip_address(address)
    if not isinstance(ip,ipaddress.IPv4Address) or not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified: raise ValueError("endpoint address denied")
    port=endpoint["port"]
    if isinstance(port,bool) or not isinstance(port,int) or not 1 <= port <= 65535: raise ValueError("endpoint port denied")
    protocol=endpoint["protocol"]
    endpoint_id=args.get("endpoint_id")
    if not isinstance(endpoint_id,str) or not re.fullmatch(r"[a-z][a-z0-9_-]{1,62}",endpoint_id): raise ValueError("endpoint ID denied")
    expected={"network.tcp_connect":{"tcp","http","https","postgresql"},"network.reachability":{"tcp","http","https","postgresql"},"http.readiness":{"http","https"},"postgresql.protocol_available":{"postgresql"},"network.dns_resolve":{"tcp","http","https","postgresql"},"network.listener":{"tcp","http","https","postgresql"},"network.tls_certificate":{"https"}}
    if protocol not in expected.get(action,set()): raise ValueError("endpoint protocol denied")
    if not isinstance(timeout,int) or isinstance(timeout,bool) or not 1 <= timeout <= 10: raise ValueError("probe timeout denied")
    start=time.monotonic()
    data={"endpoint_id":endpoint_id,"address":address,"port":port,"protocol":protocol}
    if action == "network.dns_resolve":
        name=endpoint.get("dns_name"); resolver=endpoint.get("resolver_address")
        if not valid_dns_name(name) or not valid_private_ipv4(resolver): raise ValueError("DNS endpoint configuration denied")
        return dns_query(endpoint_id,name,resolver,address,timeout)
    if action == "network.listener":
        if endpoint.get("local_listener") is not True: raise ValueError("local listener scope denied")
        return listener_snapshot(endpoint_id,address,port,timeout)
    if action == "network.tls_certificate":
        name=endpoint.get("dns_name")
        if not valid_dns_name(name): raise ValueError("TLS hostname configuration denied")
        return tls_certificate(endpoint_id,address,port,name,timeout)
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
def bounded_stdout(argv, timeout, byte_limit, pass_fds=()):
    try:
        process=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,close_fds=True,start_new_session=True,pass_fds=pass_fds)
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
def valid_private_ipv4(value):
    try:
        address=ipaddress.ip_address(value)
        return isinstance(address,ipaddress.IPv4Address) and address.is_private and not (address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved or address.is_unspecified)
    except ValueError: return False
def valid_dns_name(value):
    return isinstance(value,str) and len(value)<=253 and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+",value) is not None
def dns_query(endpoint_id,name,resolver,expected_address,timeout):
    identifier=int.from_bytes(os.urandom(2),"big")
    labels=name.lower().encode("ascii").split(b".")
    question=b"".join(bytes([len(label)])+label for label in labels)+b"\0\0\1\0\1"
    request=struct.pack("!HHHHHH",identifier,0x0100,1,0,0,0)+question
    data={"endpoint_id":endpoint_id,"dns_name":name,"resolver_address":resolver,"expected_address":expected_address,"answers":[],"matches_expected":False,"status":"unknown"}
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as connection:
            connection.settimeout(timeout)
            connection.sendto(request,(resolver,53))
            response,source=connection.recvfrom(2049)
        if source[0]!=resolver or source[1]!=53 or len(response)>2048 or len(response)<12: raise ValueError("invalid_dns_response")
        reply_id,flags,queries,answers,_,_=struct.unpack("!HHHHHH",response[:12])
        if reply_id!=identifier or flags&0x8000==0 or flags&0x0200 or queries!=1 or answers>32 or response[12:12+len(question)].lower()!=question: raise ValueError("invalid_dns_response")
        code=flags&15
        if code==3: data["status"]="nxdomain"; return data,None
        if code!=0: data["status"]="resolver_failure"; return data,None
        offset=12+len(question); addresses=[]
        for _ in range(answers):
            if offset>=len(response): raise ValueError("invalid_dns_response")
            if response[offset]&0xc0==0xc0:
                if offset+2>len(response) or ((response[offset]&0x3f)<<8 | response[offset+1])!=12: raise ValueError("invalid_dns_response")
                offset+=2
            else:
                owner_start=offset
                while True:
                    if offset>=len(response): raise ValueError("invalid_dns_response")
                    length=response[offset]; offset+=1
                    if length==0: break
                    if length>63 or offset+length>len(response): raise ValueError("invalid_dns_response")
                    offset+=length
                if response[owner_start:offset].lower()!=question[:-4]: raise ValueError("invalid_dns_response")
            if offset+10>len(response): raise ValueError("invalid_dns_response")
            kind,record_class,_,size=struct.unpack("!HHIH",response[offset:offset+10]); offset+=10
            if offset+size>len(response): raise ValueError("invalid_dns_response")
            if kind==1 and record_class==1 and size==4: addresses.append(socket.inet_ntoa(response[offset:offset+4]))
            offset+=size
        data["answers"]=sorted(set(addresses))[:32]
        data["matches_expected"]=expected_address in data["answers"]
        data["status"]="matched" if data["matches_expected"] else "mismatch" if data["answers"] else "no_a_record"
        return data,None
    except (socket.timeout,TimeoutError): data["status"]="timeout"; return data,None
    except OSError: data["status"]="resolver_unavailable"; return data,None
    except ValueError: data["status"]="invalid_response"; return data,None
def listener_snapshot(endpoint_id,address,port,timeout):
    if timeout>3: raise ValueError("listener timeout denied")
    data={"endpoint_id":endpoint_id,"port":port,"scope":"observed_host_local_ipv4","address_owned":False,"listening":False,"listener_count":0,"other_address_listeners":0,"status":"unknown","scan_truncated":False}
    deadline=time.monotonic()+timeout
    output,error=bounded_stdout(["/usr/sbin/ip","-j","-4","address","show"],timeout,65536)
    if error is not None: return data,"local_address_inventory_unavailable"
    try:
        interfaces=json.loads(output)
        if not isinstance(interfaces,list) or len(interfaces)>128: raise ValueError("invalid interface inventory")
        owned=set()
        for interface in interfaces:
            if not isinstance(interface,dict) or not isinstance(interface.get("addr_info"),list) or len(interface["addr_info"])>128: raise ValueError("invalid interface inventory")
            for entry in interface["addr_info"]:
                if not isinstance(entry,dict) or entry.get("family")!="inet": continue
                literal=entry.get("local")
                if not isinstance(literal,str): raise ValueError("invalid local address")
                owned.add(str(ipaddress.IPv4Address(literal)))
        if address not in owned:
            data["status"]="not_applicable"
            return data,None
        data["address_owned"]=True
    except (ValueError,TypeError,KeyError): return data,"local_address_inventory_unavailable"
    if time.monotonic()>=deadline: return data,"listener_scan_incomplete"
    try:
        count=0
        expected=socket.inet_aton(address)[::-1].hex().upper()
        with open("/proc/net/tcp",encoding="ascii") as stream:
            for line in stream:
                count+=1
                if count>4096 or time.monotonic()>=deadline: data["scan_truncated"]=True; return data,"listener_scan_incomplete"
                fields=line.split()
                if len(fields)<4 or fields[3]!="0A": continue
                candidate=fields[1].split(":")
                if len(candidate)!=2 or int(candidate[1],16)!=port: continue
                if candidate[0].upper() in (expected,"00000000"): data["listener_count"]+=1
                else: data["other_address_listeners"]+=1
        data["listening"]=data["listener_count"]>0
        data["status"]="listening" if data["listening"] else "address_mismatch" if data["other_address_listeners"] else "port_closed"
        return data,None
    except (OSError,ValueError): return data,"listener_inventory_unavailable"
def tls_certificate(endpoint_id,address,port,name,timeout):
    data={"endpoint_id":endpoint_id,"dns_name":name,"certificate_status":"unknown","chain_valid":False,"hostname_valid":False,"expires_at":None,"days_remaining":None}
    try:
        deadline=time.monotonic()+timeout
        context=ssl.create_default_context()
        with socket.create_connection((address,port),timeout=timeout) as connection:
            remaining=deadline-time.monotonic()
            if remaining<=0: raise TimeoutError()
            connection.settimeout(remaining)
            with context.wrap_socket(connection,server_hostname=name) as secure:
                certificate=secure.getpeercert()
        expiry=certificate.get("notAfter")
        if not isinstance(expiry,str): return data,"certificate_metadata_unavailable"
        remaining=int((ssl.cert_time_to_seconds(expiry)-time.time())//86400)
        data.update({"certificate_status":"valid" if remaining>=0 else "expired","chain_valid":True,"hostname_valid":True,"expires_at":expiry[:32],"days_remaining":remaining})
        return data,None
    except ssl.SSLCertVerificationError as exc:
        code=getattr(exc,"verify_code",None)
        data["certificate_status"]="expired" if code==10 else "hostname_mismatch" if code==62 else "invalid_chain" if code in (20,21) else "invalid_certificate"
        return data,None
    except (socket.timeout,TimeoutError): data["certificate_status"]="timeout"; return data,None
    except (OSError,ssl.SSLError,ValueError): data["certificate_status"]="unavailable"; return data,None
def firewall_summary(timeout):
    data={"backend":"nftables","status":"unavailable","tables":0,"chains":0,"rules":0,"raw_rules_included":False}
    if timeout>5: raise ValueError("firewall timeout denied")
    output,error=bounded_stdout(["/usr/sbin/nft","-j","list","ruleset"],timeout,65536)
    if error is not None: return data,"firewall_inspection_unavailable"
    try:
        parsed=json.loads(output)
        entries=parsed["nftables"]
        if not isinstance(entries,list) or len(entries)>4096: raise ValueError("invalid ruleset")
        for entry in entries:
            if not isinstance(entry,dict) or len(entry)!=1: raise ValueError("invalid ruleset")
            kind=next(iter(entry))
            if kind=="table": data["tables"]+=1
            elif kind=="chain": data["chains"]+=1
            elif kind=="rule": data["rules"]+=1
        data["status"]="available"
        return data,None
    except (ValueError,KeyError,TypeError): return data,"firewall_inventory_invalid"
def proc_record(pid):
    if isinstance(pid,bool) or not isinstance(pid,int) or not 1 <= pid <= 4194304: return None
    try:
        with open("/proc/"+str(pid)+"/stat",encoding="ascii") as stream: raw=stream.read(4096)
        end=raw.rfind(")")
        if end < 0: return None
        comm=raw[raw.find("(")+1:end][:15]
        fields=raw[end+2:].split()
        if len(fields)<22: return None
        state=fields[0]
        ppid=int(fields[1]); user_ticks=int(fields[11]); system_ticks=int(fields[12]); start_ticks=int(fields[19]); rss_pages=max(0,int(fields[21]))
        uid=os.stat("/proc/"+str(pid)).st_uid
        return {"pid":pid,"parent_pid":ppid,"name":safe_log_message(comm)[:15],"state":state[:1],"uid":uid,"user_cpu_ticks":user_ticks,"system_cpu_ticks":system_ticks,"start_time_ticks":start_ticks,"rss_bytes":rss_pages*os.sysconf("SC_PAGE_SIZE")}
    except (OSError,ValueError,IndexError): return None
def proc_snapshot(scan_limit=4096, timeout=4):
    deadline=time.monotonic()+timeout
    records=[]; scanned=0; examined=0; unavailable=0; truncated=False
    try:
        with os.scandir("/proc") as entries:
            for entry in entries:
                examined+=1
                if examined>8192 or time.monotonic()>=deadline:
                    truncated=True; break
                if not entry.name.isdigit(): continue
                if scanned>=scan_limit or time.monotonic()>=deadline:
                    truncated=True; break
                scanned+=1
                record=proc_record(int(entry.name))
                if record is not None: records.append(record)
                else: unavailable+=1
    except OSError:
        return None,scanned,truncated,unavailable
    return records,scanned,truncated,unavailable
def mount_records(limit=128):
    try:
        with open("/proc/self/mountinfo",encoding="utf-8",errors="replace") as stream: raw=stream.read(65537)
    except OSError: return None,False
    if len(raw)>65536: return None,False
    records=[]; truncated=False; lines=raw.splitlines()
    if len(lines)>4096: truncated=True
    for line in lines[:4096]:
        left,separator,right=line.partition(" - ")
        before=left.split()
        after=right.split()
        if not separator or len(before)<6 or len(after)<3:
            truncated=True; continue
        def unescape(value):
            return re.sub(r"\\([0-7]{3})",lambda match:chr(int(match.group(1),8)),value)
        mountpoint=unescape(before[4])
        options=before[5].split(",")
        records.append({"mountpoint":mountpoint[:512],"filesystem_type":after[0][:64],"read_only":"ro" in options})
        if len(records)>=limit: truncated=True; break
    return records,truncated
def storage_target(args, action):
    target=args.get("_storage")
    target_id=args.get("storage_id")
    allowed={"storage_id","_storage"}
    if action=="filesystem.usage_summary": allowed.add("max_entries")
    if action=="filesystem.log_growth": allowed.add("interval_seconds")
    if set(args)-allowed: raise ValueError("storage arguments denied")
    if not isinstance(target_id,str) or not re.fullmatch(r"[a-z][a-z0-9_-]{1,62}",target_id): raise ValueError("storage alias denied")
    if not isinstance(target,dict) or set(target)!={"path","kind"}: raise ValueError("storage target denied")
    path=target["path"]; kind=target["kind"]
    if not isinstance(path,str) or len(path)>256 or not path.startswith("/") or path.startswith("//") or (path!="/" and path.endswith("/")) or any(part in ("",".","..") for part in path.split("/")[1:]) or any(char in path for char in "\x00\n\r"): raise ValueError("storage path denied")
    if kind not in ("file","directory","mount"): raise ValueError("storage kind denied")
    if action in ("filesystem.usage_summary","filesystem.pressure") and kind!="directory": raise ValueError("storage directory required")
    if action=="filesystem.log_growth" and kind!="file": raise ValueError("storage file required")
    if action=="filesystem.mount_status" and kind!="mount": raise ValueError("storage mount required")
    return target_id,path,kind
def value_has_unsafe_parts(path):
    return path.endswith("/") or any(part in ("",".","..") for part in path.split("/")[1:])
def storage_fd(path, directory=False):
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    fd=os.open("/",flags)
    try:
        parts=path.split("/")[1:] if path!="/" else []
        for index,part in enumerate(parts):
            final=index==len(parts)-1
            mode=(os.O_RDONLY|os.O_DIRECTORY if directory or not final else os.O_PATH)|os.O_NOFOLLOW|os.O_CLOEXEC
            child=os.open(part,mode,dir_fd=fd)
            os.close(fd); fd=child
        return fd
    except BaseException:
        os.close(fd); raise
def storage_mount_id(fd):
    try:
        with open("/proc/self/fdinfo/"+str(fd),encoding="ascii") as stream: raw=stream.read(4097)
        if len(raw)>4096: return None
        match=re.search(r"(?m)^mnt_id:\s*(\d+)$",raw)
        return int(match.group(1)) if match else None
    except (OSError,ValueError): return None
def storage_metadata(target_id,path):
    data={"storage_id":target_id,"status":"unknown","type":None,"size_bytes":None,"permissions":None,"modified_at_ns":None,"symlink":False,"contents_included":False}
    try:
        fd=storage_fd(path)
        try: info=os.fstat(fd)
        finally: os.close(fd)
    except PermissionError: return data,"permission_denied"
    except (OSError,ValueError): return data,"path_unavailable"
    kind="file" if stat.S_ISREG(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else "symlink" if stat.S_ISLNK(info.st_mode) else "special"
    data.update({"status":"available","type":kind,"size_bytes":info.st_size if kind=="file" else None,"permissions":format(stat.S_IMODE(info.st_mode),"04o"),"modified_at_ns":info.st_mtime_ns,"symlink":kind=="symlink"})
    return data,None
def storage_mount_status(target_id,path):
    mounts,incomplete=mount_records(256)
    data={"storage_id":target_id,"status":"unknown","present":None,"filesystem_type":None,"read_only":None,"inventory_complete":False}
    if mounts is None: return data,"mount_inventory_unavailable"
    found=next((item for item in mounts if item["mountpoint"]==path),None)
    data.update({"status":"present" if found else "unknown" if incomplete else "missing","present":True if found else None if incomplete else False,"filesystem_type":found["filesystem_type"] if found else None,"read_only":found["read_only"] if found else None,"inventory_complete":not incomplete})
    return data,None
def storage_pressure(target_id,path):
    data={"storage_id":target_id,"status":"unknown","total_bytes":None,"used_bytes":None,"available_bytes":None,"used_percent":None,"total_inodes":None,"free_inodes":None,"inode_used_percent":None,"read_only":None,"byte_capacity_known":False,"inode_capacity_known":False}
    try:
        fd=storage_fd(path,True)
        try: info=os.fstatvfs(fd)
        finally: os.close(fd)
    except PermissionError: return data,"permission_denied"
    except OSError: return data,"filesystem_unavailable"
    total=info.f_blocks*info.f_frsize
    free=info.f_bfree*info.f_frsize
    available=info.f_bavail*info.f_frsize
    inodes=info.f_files
    inode_free=info.f_ffree
    data.update({"total_bytes":total,"used_bytes":total-free,"available_bytes":available,"used_percent":round((total-free)*100/total,2) if total>0 else None,"total_inodes":inodes,"free_inodes":inode_free,"inode_used_percent":round((inodes-inode_free)*100/inodes,2) if inodes>0 else None,"read_only":bool(info.f_flag & os.ST_RDONLY),"byte_capacity_known":total>0,"inode_capacity_known":inodes>0})
    if total>0 and inodes>0:
        data["status"]="both_full" if available==0 and inode_free==0 else "byte_full" if available==0 else "inode_full" if inode_free==0 else "available"
    return data,None
def storage_usage(target_id,path,max_entries,timeout):
    data={"storage_id":target_id,"status":"unknown","total_bytes":0,"regular_files":0,"directories":0,"hardlinks_deduplicated":0,"symlinks_skipped":0,"special_files_skipped":0,"mounts_skipped":0,"entries_scanned":0,"truncated":False,"inventory_complete":False,"contents_included":False}
    deadline=time.monotonic()+timeout
    mounts,incomplete=mount_records(256)
    if mounts is None or incomplete: return data,"mount_inventory_unavailable"
    mountpoints={record["mountpoint"] for record in mounts if record["mountpoint"]!=path}
    try:
        root=storage_fd(path,True); root_dev=os.fstat(root).st_dev
    except PermissionError: return data,"permission_denied"
    except OSError: return data,"path_unavailable"
    root_mount=storage_mount_id(root)
    if root_mount is None:
        os.close(root)
        return data,"mount_identity_unavailable"
    stack=[(root,path)]; seen=set(); error=None
    try:
        while stack:
            if time.monotonic()>=deadline or data["entries_scanned"]>=max_entries:
                data["truncated"]=True; break
            parent,current=stack.pop()
            try:
                data["directories"]+=1
                with os.scandir(parent) as stream:
                    for entry in stream:
                        if time.monotonic()>=deadline or data["entries_scanned"]>=max_entries:
                            data["truncated"]=True; break
                        data["entries_scanned"]+=1
                        try:
                            item_fd=os.open(entry.name,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
                            try: info=os.fstat(item_fd); item_mount=storage_mount_id(item_fd)
                            finally: os.close(item_fd)
                        except OSError as exc: error="permission_denied" if isinstance(exc,PermissionError) else "entry_unavailable"; break
                        if item_mount is None: error="mount_identity_unavailable"; break
                        child_path=current.rstrip("/")+"/"+entry.name
                        if child_path in mountpoints or info.st_dev!=root_dev or item_mount!=root_mount:
                            data["mounts_skipped"]+=1; continue
                        if stat.S_ISLNK(info.st_mode): data["symlinks_skipped"]+=1; continue
                        if stat.S_ISDIR(info.st_mode):
                            try: child=os.open(entry.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
                            except OSError as exc: error="permission_denied" if isinstance(exc,PermissionError) else "entry_unavailable"; break
                            child_info=os.fstat(child)
                            if (child_info.st_dev,child_info.st_ino)!=(info.st_dev,info.st_ino) or storage_mount_id(child)!=root_mount:
                                os.close(child); error="entry_changed"; break
                            if child_info.st_dev!=root_dev: os.close(child); data["mounts_skipped"]+=1
                            else: stack.append((child,child_path))
                        elif stat.S_ISREG(info.st_mode):
                            identity=(info.st_dev,info.st_ino)
                            if identity in seen: data["hardlinks_deduplicated"]+=1
                            else: seen.add(identity); data["regular_files"]+=1; data["total_bytes"]+=info.st_size
                        else: data["special_files_skipped"]+=1
                    if data["truncated"] or error: break
            except OSError as exc: error="permission_denied" if isinstance(exc,PermissionError) else "entry_unavailable"; break
            finally: os.close(parent)
        data["inventory_complete"]=not data["truncated"] and error is None
        data["status"]="complete" if data["inventory_complete"] else "unknown"
        return data,error
    finally:
        for fd,_ in stack: os.close(fd)
def storage_growth(target_id,path,interval):
    data={"storage_id":target_id,"status":"unknown","snapshots":[],"interval_seconds":None,"growth_bytes":None,"contents_included":False}
    for index in range(2):
        try:
            fd=storage_fd(path)
            try: info=os.fstat(fd)
            finally: os.close(fd)
        except PermissionError: return data,"permission_denied"
        except OSError: return data,"path_unavailable"
        if not stat.S_ISREG(info.st_mode): return data,"regular_file_required"
        data["snapshots"].append({"observed_at":time.time(),"size_bytes":info.st_size,"device":info.st_dev,"inode":info.st_ino})
        if index==0: time.sleep(interval)
    first,second=data["snapshots"]
    data["interval_seconds"]=round(second["observed_at"]-first["observed_at"],3)
    if (first["device"],first["inode"])!=(second["device"],second["inode"]): return data,"file_replaced"
    data["growth_bytes"]=second["size_bytes"]-first["size_bytes"]
    data["status"]="growing" if data["growth_bytes"]>0 else "shrinking" if data["growth_bytes"]<0 else "stable"
    return data,None
def read_bounded_regular(path,limit):
    fd=None
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        metadata=os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size>limit: return None
        data=os.read(fd,limit+1)
        if len(data)>limit: return None
        return data.decode("utf-8","replace")
    except OSError: return None
    finally:
        if fd is not None: os.close(fd)
def cron_records(limit=50):
    entries=[]; periodic=[]; total_bytes=0; truncated=False; unrecognized=0
    fixed_files=["/etc/crontab"]
    try:
        with os.scandir("/etc/cron.d") as directory:
            names=[]
            for item in directory:
                if len(names)>=64: truncated=True; break
                if item.is_file(follow_symlinks=False) and not item.is_symlink(): fixed_files.append("/etc/cron.d/"+item.name)
                names.append(item.name)
            fixed_files[1:]=sorted(fixed_files[1:])
    except OSError: pass
    for path in fixed_files:
        if len(entries)>=limit: truncated=True; break
        try:
            if os.path.islink(path): continue
            content=read_bounded_regular(path,16384)
            if content is None: truncated=True; continue
            size=len(content.encode("utf-8"))
            if total_bytes+size>65536: truncated=True; continue
            total_bytes+=size
            lines=content.splitlines()
        except OSError: continue
        if len(lines)>512: truncated=True
        for line in lines[:512]:
            fields=line.split()
            if not fields or line.lstrip().startswith("#") or "=" in fields[0]: continue
            if fields[0].startswith("@"):
                schedule=fields[0]
                if len(fields)<3: unrecognized+=1; continue
            else:
                if len(fields)<7: unrecognized+=1; continue
                schedule=" ".join(fields[:5])
            if not re.fullmatch(r"[A-Za-z0-9*/?,@#-]{1,100}(?: [A-Za-z0-9*/?,@#-]{1,100}){0,4}",schedule): unrecognized+=1; continue
            entries.append({"source":safe_log_message(path.rsplit("/",1)[-1] if path!="/etc/crontab" else "crontab")[:128],"schedule":schedule})
            if len(entries)>=limit: truncated=True; break
    for name in ("hourly","daily","weekly","monthly"):
        path="/etc/cron."+name
        try:
            with os.scandir(path) as directory:
                count=0; entries_seen=0
                for item in directory:
                    entries_seen+=1
                    if entries_seen>2048: truncated=True; break
                    if item.is_file(follow_symlinks=False) and not item.is_symlink(): count+=1
            periodic.append({"frequency":name,"job_count":count,"count_capped":entries_seen>2048})
        except OSError: continue
    return {"entries":entries,"periodic_directories":periodic,"entry_count":len(entries),"unrecognized_job_lines":unrecognized,"output_truncated":truncated}
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
    elif action == "systemd.service_status":
        unit=args.get("unit")
        if not isinstance(unit,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}\.service",unit): raise ValueError("service unit denied")
        if not isinstance(timeout,int) or isinstance(timeout,bool) or not 1<=timeout<=10: raise ValueError("service status timeout denied")
        raw,error=bounded_stdout(["/usr/bin/systemctl","show","--no-pager","--property=Id,LoadState,ActiveState,SubState,UnitFileState,Result,ExecMainStatus",unit],timeout,8192)
        if error: emit(False,{"unit":unit,"properties":{}},error)
        else:
            allowed={"Id","LoadState","ActiveState","SubState","UnitFileState","Result","ExecMainStatus"}
            properties={}
            for line in raw.decode("utf-8","replace").splitlines()[:16]:
                key,separator,value=line.partition("=")
                if separator and key in allowed: properties[key]=safe_log_message(value)[:128]
            if not {"Id","LoadState","ActiveState","SubState"}.issubset(properties): emit(False,{"unit":unit,"properties":properties},"invalid_service_status_output")
            else: emit(True,{"unit":unit,"properties":properties,"loaded":properties.get("LoadState")=="loaded","active":properties.get("ActiveState")=="active"})
    elif action == "systemd.failed_units":
        if not isinstance(timeout,int) or isinstance(timeout,bool) or not 1<=timeout<=15: raise ValueError("failed units timeout denied")
        raw,error=bounded_stdout(["/usr/bin/systemctl","list-units","--failed","--no-legend","--plain","--no-pager"],timeout,16384)
        if error: emit(False,{"units":[]},error)
        else:
            units=[line.split()[0][:128] for line in raw.decode("utf-8","replace").splitlines() if line.split()][:100]
            emit(True,{"units":units,"unit_count":len(units),"output_truncated":len(units)>=100})
    elif action == "systemd.timers":
        limit=args.get("limit",50)
        if type(limit) is not int or not 1<=limit<=100: raise ValueError("timer limit denied")
        if not isinstance(timeout,int) or isinstance(timeout,bool) or not 1<=timeout<=10: raise ValueError("timer timeout denied")
        raw,error=bounded_stdout(["/usr/bin/systemctl","list-timers","--all","--no-legend","--no-pager"],timeout,32768)
        if error: emit(False,{"timers":[]},error)
        else:
            timers=[]
            for line in raw.decode("utf-8","replace").splitlines():
                fields=line.split()
                timer_index=next((index for index,field in enumerate(fields) if re.fullmatch(r"[A-Za-z0-9_.@:-]{1,128}\.timer",field)),None)
                if timer_index is None: continue
                timer=fields[timer_index]
                activates=fields[timer_index+1] if timer_index+1<len(fields) and re.fullmatch(r"[A-Za-z0-9_.@:-]{1,128}\.(service|target)",fields[timer_index+1]) else None
                timers.append({"unit":timer,"activates":activates,"schedule_summary":" ".join(fields[:timer_index])[:160]})
                if len(timers)>=limit: break
            emit(True,{"timers":timers,"timer_count":len(timers),"output_truncated":len(timers)>=limit})
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
    elif action == "systemd.journal_summary":
        unit=args.get("unit"); window=args.get("window_minutes",60); maximum=args.get("max_entries",100)
        if not isinstance(unit,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}\.(service|timer)",unit): raise ValueError("journal unit denied")
        if type(window) is not int or not 1<=window<=1440 or type(maximum) is not int or not 1<=maximum<=200: raise ValueError("journal summary bounds denied")
        if not isinstance(timeout,int) or isinstance(timeout,bool) or not 1<=timeout<=10: raise ValueError("journal summary timeout denied")
        raw,error=bounded_stdout(["/usr/bin/journalctl","--unit",unit,"--since",str(window)+" minutes ago","--lines",str(maximum),"--no-pager","--output=json"],timeout,65536)
        if error: emit(False,{"unit":unit,"entry_count":0,"priority_counts":{}},error)
        else:
            counts={str(priority):0 for priority in range(8)}; timestamps=[]; valid=True; sampled=0
            for line in raw.splitlines()[:maximum]:
                try: item=json.loads(line)
                except (json.JSONDecodeError,UnicodeDecodeError): valid=False; break
                priority=str(item.get("PRIORITY",""))
                if priority in counts: counts[priority]+=1
                timestamp=str(item.get("__REALTIME_TIMESTAMP",""))
                if timestamp.isdigit(): timestamps.append(timestamp[:24])
                sampled+=1
            if not valid: emit(False,{"unit":unit,"entry_count":0,"priority_counts":{}},"invalid_journal_record")
            else: emit(True,{"unit":unit,"window_minutes":window,"entry_count":sampled,"priority_counts":counts,"earliest_timestamp_usec":min(timestamps) if timestamps else None,"latest_timestamp_usec":max(timestamps) if timestamps else None,"sample_limit_reached":sampled>=maximum,"messages_included":False})
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
    elif action == "os.cpu":
        if not isinstance(timeout,int) or isinstance(timeout,bool) or not 1<=timeout<=3: raise ValueError("CPU diagnostic timeout denied")
        raw=open("/proc/stat",encoding="ascii").read(32769)
        if len(raw)>32768: raise ValueError("CPU statistics exceed limit")
        cpus=[]
        names=("user","nice","system","idle","iowait","irq","softirq","steal","guest","guest_nice")
        for line in raw.splitlines():
            fields=line.split()
            if not fields or not re.fullmatch(r"cpu[0-9]*",fields[0]): continue
            if len(cpus)>=257: break
            ticks=[int(value) for value in fields[1:11] if value.isdigit()]
            if len(ticks)<4: continue
            cpus.append({"cpu":fields[0],"ticks":{name:ticks[index] if index<len(ticks) else 0 for index,name in enumerate(names)}})
        load=open("/proc/loadavg",encoding="ascii").read(256).split()
        if not load or not cpus: raise ValueError("CPU statistics unavailable")
        logical=max(1,os.cpu_count() or len(cpus)-1)
        averages=[float(value) for value in load[:3]]
        emit(True,{"logical_cpu_count":logical,"load_average_1m":averages[0],"load_average_5m":averages[1],"load_average_15m":averages[2],"load_per_logical_cpu_1m":round(averages[0]/logical,4),"cpu_counters":cpus,"cpu_count_includes_aggregate":True})
    elif action == "os.release":
        if not isinstance(timeout,int) or isinstance(timeout,bool) or not 1<=timeout<=3: raise ValueError("OS release timeout denied")
        try:
            with open("/etc/os-release",encoding="utf-8",errors="replace") as stream: content=stream.read(8193)
        except OSError: content=""
        if len(content)>8192: emit(False,{},"os_release_exceeds_limit")
        else:
            values={}
            for line in content.splitlines()[:128]:
                key,separator,value=line.partition("=")
                if separator and key in ("ID","ID_LIKE","NAME","VERSION_ID"):
                    values[key]=safe_log_message(value.strip().strip("\\\"'"))[:128]
            identity=os.uname()
            emit(True,{"distribution_id":values.get("ID"),"distribution_id_like":values.get("ID_LIKE"),"distribution_name":values.get("NAME"),"distribution_version":values.get("VERSION_ID"),"kernel_name":safe_log_message(identity.sysname)[:64],"kernel_release":safe_log_message(identity.release)[:128],"machine_architecture":safe_log_message(identity.machine)[:64]})
    elif action == "os.memory":
        values={}
        for line in open("/proc/meminfo",encoding="ascii"):
            key, value=line.split(":",1)
            parts=value.split()
            if parts and parts[0].isdigit(): values[key]=int(parts[0])*(1024 if len(parts)>1 and parts[1]=="kB" else 1)
        emit(True,{"total_bytes":values.get("MemTotal",0),"available_bytes":values.get("MemAvailable",0),"swap_total_bytes":values.get("SwapTotal",0),"swap_free_bytes":values.get("SwapFree",0)})
    elif action == "process.list":
        limit=args.get("limit",50); order=args.get("order_by","pid")
        if type(limit) is not int or not 1<=limit<=100 or order not in ("pid","memory_rss"): raise ValueError("process list bounds denied")
        if not isinstance(timeout,int) or isinstance(timeout,bool) or not 1<=timeout<=5: raise ValueError("process list timeout denied")
        records,scanned,scan_truncated,unavailable=proc_snapshot(4096,min(timeout,4))
        if records is None: emit(False,{"processes":[]},"process_snapshot_unavailable")
        else:
            if order=="memory_rss": records.sort(key=lambda item:(-item["rss_bytes"],item["pid"]))
            else: records.sort(key=lambda item:item["pid"])
            selected=records[:limit]
            output_truncated=len(records)>limit
            inventory_complete=not scan_truncated and unavailable==0 and not output_truncated
            emit(True,{"processes":selected,"process_count":len(selected),"scanned_processes":scanned,"unavailable_processes":unavailable,"truncated":scan_truncated or output_truncated,"scan_truncated":scan_truncated,"inventory_complete":inventory_complete,"order_by":order,"command_lines_included":False})
    elif action == "process.inspect":
        pid=args.get("pid")
        if isinstance(pid,bool) or not isinstance(pid,int) or not 1<=pid<=4194304: raise ValueError("process identity denied")
        record=proc_record(pid)
        if record is None: emit(False,{"pid":pid},"process_unavailable")
        else: emit(True,{"process":record,"command_line_included":False})
    elif action == "process.tree":
        pid=args.get("pid"); depth_limit=args.get("max_depth",4); node_limit=args.get("max_nodes",50)
        if isinstance(pid,bool) or not isinstance(pid,int) or not 1<=pid<=4194304 or type(depth_limit) is not int or not 1<=depth_limit<=8 or type(node_limit) is not int or not 1<=node_limit<=100: raise ValueError("process tree bounds denied")
        if not isinstance(timeout,int) or isinstance(timeout,bool) or not 1<=timeout<=5: raise ValueError("process tree timeout denied")
        records,scanned,scan_truncated,unavailable=proc_snapshot(4096,min(timeout,4))
        if records is None: emit(False,{"root_pid":pid,"processes":[]},"process_snapshot_unavailable")
        else:
            by_pid={item["pid"]:item for item in records}; children={}
            for item in records: children.setdefault(item["parent_pid"],[]).append(item["pid"])
            for values in children.values(): values.sort()
            if pid not in by_pid: emit(False,{"root_pid":pid,"processes":[]},"process_unavailable")
            else:
                tree=[]; queue=[(pid,0)]; omitted=False
                while queue:
                    current,depth=queue.pop(0)
                    if len(tree)>=node_limit: omitted=True; break
                    node=dict(by_pid[current]); node["depth"]=depth; tree.append(node)
                    descendants=children.get(current,[])
                    if depth<depth_limit: queue.extend((child,depth+1) for child in descendants)
                    elif descendants: omitted=True
                truncated=omitted or scan_truncated or unavailable>0
                emit(True,{"root_pid":pid,"processes":tree,"node_count":len(tree),"truncated":truncated,"scan_truncated":scan_truncated,"inventory_complete":not truncated,"scanned_processes":scanned,"unavailable_processes":unavailable,"command_lines_included":False})
    elif action == "os.disk":
        path=args.get("path","/")
        if not isinstance(path,str) or len(path)>256 or not path.startswith("/") or path.startswith("//") or (path!="/" and path.endswith("/")) or (path!="/" and any(part in ("",".","..") for part in path.split("/")[1:])) or any(char in path for char in "\x00\n\r"): raise ValueError("invalid path")
        if not isinstance(timeout,int) or isinstance(timeout,bool) or not 1<=timeout<=15: raise ValueError("disk diagnostic timeout denied")
        try:
            fd=storage_fd(path)
            try:
                if stat.S_ISLNK(os.fstat(fd).st_mode): raise OSError("symlink denied")
                info=os.fstatvfs(fd)
            finally: os.close(fd)
            total=info.f_blocks*info.f_frsize; used=(info.f_blocks-info.f_bfree)*info.f_frsize; free=info.f_bavail*info.f_frsize
            percent=int(used*100/total) if total else 0
            emit(True,{"path":path,"total_bytes":total,"used_bytes":used,"free_bytes":free,"percent":percent,"capacity_known":total>0,"status":"full" if total>0 and free==0 else "available" if total>0 else "unknown"},uncertain=total==0)
        except OSError: emit(False,{"path":path,"status":"unknown","capacity_known":False},"disk_unavailable",True)
    elif action == "filesystem.mounts":
        if not isinstance(timeout,int) or isinstance(timeout,bool) or not 1<=timeout<=5: raise ValueError("mount diagnostic timeout denied")
        mounts,truncated=mount_records(128)
        if mounts is None: emit(False,{"mounts":[]},"mount_inventory_unavailable")
        else: emit(True,{"mounts":mounts,"mount_count":len(mounts),"possibly_truncated":truncated,"inventory_complete":not truncated,"device_sources_included":False},uncertain=truncated)
    elif action == "filesystem.inodes":
        path=args.get("path")
        if not isinstance(path,str) or len(path)>256 or not path.startswith("/") or path.startswith("//") or (path!="/" and value_has_unsafe_parts(path)) or any(char in path for char in "\x00\n\r"): raise ValueError("filesystem path denied")
        if not isinstance(timeout,int) or isinstance(timeout,bool) or not 1<=timeout<=3: raise ValueError("inode diagnostic timeout denied")
        try:
            fd=storage_fd(path)
            if stat.S_ISLNK(os.fstat(fd).st_mode): raise OSError("symlink denied")
        except OSError:
            emit(False,{"path":path,"status":"unknown"},"filesystem_unavailable",True)
        else:
            try: raw,error=bounded_stdout(["/usr/bin/stat","--file-system","--format=%T|%c|%d","--","/proc/self/fd/"+str(fd)],timeout,4096,pass_fds=(fd,))
            finally: os.close(fd)
            if error: emit(False,{"path":path},error)
            else:
                fields=raw.decode("utf-8","replace").strip().split("|")
                if len(fields)!=3 or not all(value.isdigit() for value in fields[1:]): emit(False,{"path":path},"invalid_filesystem_statistics")
                else:
                    fs_type,total_inodes,free_inodes=fields
                    total=int(total_inodes); free=int(free_inodes)
                    emit(True,{"path":path,"filesystem_type":fs_type[:64],"total_inodes":total,"free_inodes":free,"used_percent":round((total-free)*100/total,2) if total else None,"inode_capacity_known":total>0,"status":"full" if total>0 and free==0 else "available" if total>0 else "unknown"},uncertain=total==0)
    elif action in ("filesystem.mount_status","filesystem.pressure","filesystem.path_metadata","filesystem.usage_summary","filesystem.log_growth"):
        target_id,path,kind=storage_target(args,action)
        if not isinstance(timeout,int) or isinstance(timeout,bool) or not 1<=timeout<=5: raise ValueError("storage diagnostic timeout denied")
        if action=="filesystem.mount_status":
            data,error=storage_mount_status(target_id,path)
        elif action=="filesystem.pressure": data,error=storage_pressure(target_id,path)
        elif action=="filesystem.path_metadata": data,error=storage_metadata(target_id,path)
        elif action=="filesystem.usage_summary":
            limit=args.get("max_entries",256)
            if type(limit) is not int or not 1<=limit<=1024: raise ValueError("storage scan limit denied")
            data,error=storage_usage(target_id,path,limit,timeout)
        else:
            interval=args.get("interval_seconds",1)
            if type(interval) is not int or not 1<=interval<=3 or interval>=timeout: raise ValueError("growth interval denied")
            data,error=storage_growth(target_id,path,interval)
        emit(error is None,data,error,error is not None or data.get("status")=="unknown")
    elif action == "os.packages":
        limit=args.get("limit",50)
        if type(limit) is not int or not 1<=limit<=100: raise ValueError("package inventory limit denied")
        if not isinstance(timeout,int) or isinstance(timeout,bool) or not 1<=timeout<=10: raise ValueError("package inventory timeout denied")
        if os.path.isfile("/usr/bin/dpkg-query"):
            argv=["/usr/bin/dpkg-query","-W","-f=${binary:Package}\\t${Version}\\t${db:Status-Abbrev}\\n"]; manager="dpkg"
        elif os.path.isfile("/usr/bin/rpm"):
            argv=["/usr/bin/rpm","-qa","--qf","%{NAME}\\t%{VERSION}-%{RELEASE}\\n"]; manager="rpm"
        else: argv=None; manager=None
        if argv is None: emit(False,{"packages":[],"manager":None,"package_count":0,"inventory_count":0},"package_manager_unavailable")
        else:
            raw,error=bounded_stdout(argv,timeout,262144)
            if error: emit(False,{"packages":[],"manager":manager},error)
            else:
                packages=[]
                for line in raw.decode("utf-8","replace").splitlines():
                    fields=line.split("\t")
                    if manager=="dpkg":
                        if len(fields)!=3:
                            emit(False,{"packages":[],"manager":manager},"invalid_package_record"); break
                        if not fields[2].startswith("ii "): continue
                        name,version=fields[:2]
                    else:
                        if len(fields)!=2:
                            emit(False,{"packages":[],"manager":manager},"invalid_package_record"); break
                        name,version=fields
                    if not name or not version:
                        emit(False,{"packages":[],"manager":manager},"invalid_package_record"); break
                    packages.append({"name":safe_log_message(name)[:128],"version":safe_log_message(version)[:128]})
                else:
                    packages.sort(key=lambda item:(item["name"],item["version"]))
                    emit(True,{"manager":manager,"packages":packages[:limit],"package_count":min(len(packages),limit),"inventory_count":len(packages),"output_truncated":len(packages)>limit})
    elif action == "os.cron":
        limit=args.get("limit",50)
        if type(limit) is not int or not 1<=limit<=100: raise ValueError("cron inventory limit denied")
        if not isinstance(timeout,int) or isinstance(timeout,bool) or not 1<=timeout<=5: raise ValueError("cron inventory timeout denied")
        summary=cron_records(limit)
        emit(True,summary)
    elif action == "network.interfaces":
        output,error=bounded_stdout(["/usr/sbin/ip","-j","address","show"],min(timeout,15),65536)
        if error is not None: emit(False,{"interfaces":[]},error,True)
        else:
            try:
                interfaces=json.loads(output)
                if not isinstance(interfaces,list): raise ValueError("invalid network inventory")
                emit(True,{"interfaces":interfaces})
            except (ValueError,TypeError): emit(False,{"interfaces":[]},"invalid_network_inventory",True)
    elif action == "network.routes":
        output,error=bounded_stdout(["/usr/sbin/ip","-j","route","show"],min(timeout,15),65536)
        if error is not None: emit(False,{"routes":[]},error,True)
        else:
            try:
                routes=json.loads(output)
                if not isinstance(routes,list): raise ValueError("invalid route inventory")
                emit(True,{"routes":routes})
            except (ValueError,TypeError): emit(False,{"routes":[]},"invalid_route_inventory",True)
    elif action == "network.firewall_summary":
        data,error=firewall_summary(timeout)
        emit(error is None,data,error,error is not None)
    elif action in ("application.health","application.queue_health","application.config_fingerprint","application.deploy_version"):
        data,error=application_diagnostic(action,args,timeout)
        emit(error is None,data,error,error is not None or data.get("status")=="unknown")
    elif action == "postgresql.inspect":
        data,error=postgresql_inspect(args,timeout)
        emit(error is None,data,error,error is not None)
    elif action in ("network.tcp_connect","network.reachability","http.readiness","postgresql.protocol_available","network.dns_resolve","network.listener","network.tls_certificate"):
        data,error=probe_endpoint(action,args,timeout)
        if action in ("network.tcp_connect","network.reachability","http.readiness","postgresql.protocol_available"): emit(True,data,error)
        else: emit(error is None,data,error,error is not None or data.get("status") in ("timeout","resolver_failure","resolver_unavailable","invalid_response","not_applicable") or data.get("certificate_status") in ("timeout","unavailable"))
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
