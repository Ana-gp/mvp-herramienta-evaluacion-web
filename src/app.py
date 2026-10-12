import base64, hashlib, html, ipaddress, json, os, re, socket, ssl, subprocess, tempfile, threading, time, urllib.parse, urllib.request, http.client, uuid, shutil
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from html.parser import HTMLParser

HOST='127.0.0.1'; PORT=int(os.getenv('PORT','8787'))
ALLOW_PRIVATE=os.getenv('ALLOW_PRIVATE_TARGETS','0')=='1'
CHROME=None
APP_VERSION='0.3-f10-consistency'
TARGET_DOCUMENT_MARKER='TARGET_DOCUMENT_MARKER'
DYNAMIC_MARKER='DYNAMIC_TARGET_MARKER'

class RunBudget:
    def __init__(self,max_seconds=45,max_requests=20,max_bytes=25_000_000): self.start=time.monotonic(); self.max_seconds=max_seconds; self.max_requests=max_requests; self.max_bytes=max_bytes; self.requests=0; self.bytes=0
    def request(self):
        if time.monotonic()-self.start>self.max_seconds: raise TimeoutError('RunBudget agotado: tiempo máximo.')
        if self.requests>=self.max_requests: raise RuntimeError('RunBudget agotado: máximo de solicitudes.')
        self.requests+=1
    def add_bytes(self,n):
        self.bytes+=n
        if self.bytes>self.max_bytes: raise RuntimeError('RunBudget agotado: máximo de bytes.')


class Collector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True); self.tags=[]; self.text=[]; self.headings=[]; self.images=[]; self.links=[]; self.inputs=[]; self.meta=[]; self.scripts=[]; self.forms=0; self.title=''; self.in_title=False; self.h1=[]; self.lang=''; self.main=0; self.nav=0; self.footer=0; self.header=0; self.aside=0
    def handle_starttag(self,tag,attrs):
        d=dict(attrs); self.tags.append(tag); self.meta.append((tag,d))
        if tag=='html': self.lang=d.get('lang','')
        if tag=='title': self.in_title=True
        if tag in ('h1','h2','h3','h4','h5','h6'): self.headings.append((int(tag[1]),d.get('id','')))
        if tag=='h1': self.h1.append(d)
        if tag=='img': self.images.append(d)
        if tag=='a': self.links.append(d)
        if tag in ('input','select','textarea','button'): self.inputs.append((tag,d))
        if tag=='form': self.forms+=1
        if tag=='script' and d.get('type','').lower()=='application/ld+json': self.scripts.append(d)
        if tag=='main' or d.get('role')=='main': self.main+=1
        if tag=='nav' or d.get('role')=='navigation': self.nav+=1
        if tag=='footer' or d.get('role')=='contentinfo': self.footer+=1
        if tag=='header' or d.get('role')=='banner': self.header+=1
        if tag=='aside' or d.get('role')=='complementary': self.aside+=1
    def handle_endtag(self,tag):
        if tag=='title': self.in_title=False
        if self.tags: self.tags.pop()
    def handle_data(self,data):
        if data.strip(): self.text.append(data.strip())
        if self.in_title: self.title += data.strip()

class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port=None, *, pinned_ip=None, timeout=20, **kwargs):
        super().__init__(host, port=port, timeout=timeout, **kwargs); self.pinned_ip=pinned_ip
    def connect(self):
        self.sock=socket.create_connection((self.pinned_ip,self.port), self.timeout)
        try: self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError: pass

class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port=None, *, pinned_ip=None, timeout=20, context=None, **kwargs):
        super().__init__(host, port=port, timeout=timeout, context=context, **kwargs); self.pinned_ip=pinned_ip
    def connect(self):
        self.sock=socket.create_connection((self.pinned_ip,self.port), self.timeout)
        try: self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError: pass
        self.sock=self._context.wrap_socket(self.sock, server_hostname=self.host)

def resolve_public(host):
    try: infos=socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except Exception as e: raise ValueError(f'No se pudo resolver el dominio: {e}')
    ips=[]
    for i in infos:
        ip=i[4][0]
        if ip not in ips: ips.append(ip)
    if not ALLOW_PRIVATE:
        for s in ips:
            ip=ipaddress.ip_address(s)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                raise ValueError('Destino bloqueado: dirección privada/loopback/link-local/reservada.')
    return ips

def validate_target(raw):
    u=urllib.parse.urlparse(raw)
    if u.scheme not in ('http','https') or not u.hostname: raise ValueError('Solo se permiten URLs HTTP/HTTPS.')
    if u.username or u.password: raise ValueError('No se permiten credenciales embebidas en la URL.')
    ips=resolve_public(u.hostname)
    return u, ips

def _read_response(conn, max_bytes):
    r=conn.getresponse(); data=r.read(max_bytes+1)
    if len(data)>max_bytes: raise ValueError('Respuesta demasiado grande para este análisis.')
    return r, data

def fetch_url(url, max_bytes=5_000_000, max_redirects=5, budget=None):
    current=url; chain=[]; initial_status=None
    for hop in range(max_redirects+1):
        if budget: budget.request()
        u, ips=validate_target(current)
        ip=ips[0]
        port=u.port or (443 if u.scheme=='https' else 80)
        headers={'User-Agent':'WebAuditPRO/0.2 (+local-audit)','Accept':'text/html,application/xhtml+xml,text/plain,*/*'}
        if u.hostname: headers['Host']=u.hostname if not u.port else f'{u.hostname}:{u.port}'
        path=u.path or '/'
        if u.query: path+='?'+u.query
        ctx=ssl.create_default_context() if u.scheme=='https' else None
        conn=(PinnedHTTPSConnection(u.hostname,port,pinned_ip=ip,timeout=20,context=ctx)
              if u.scheme=='https' else PinnedHTTPConnection(u.hostname,port,pinned_ip=ip,timeout=20))
        try:
            conn.request('GET',path,headers=headers); r,data=_read_response(conn,max_bytes)
            if budget: budget.add_bytes(len(data))
            status=r.status; hdrs={k:v for k,v in r.getheaders()}; effective=current
            hop_record={'hop':hop+1,'from':current,'status':status,'location':hdrs.get('Location'),'resolved_ip':ip,
                        'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'method':'GET','scope':'PAGE',
                        'tool_version':APP_VERSION}
        finally:
            try: conn.close()
            except Exception: pass
        if initial_status is None: initial_status=status
        if status in (301,302,303,307,308):
            loc=hdrs.get('Location')
            if not loc:
                chain.append({**hop_record,'to':None,'error':'REDIRECT_WITHOUT_LOCATION'})
                return {'status':status,'final_url':effective,'headers':hdrs,'body':data,'content_length':len(data),'content_type':hdrs.get('Content-Type',''),'redirect_chain':chain,'resolved_ip':ip,'initial_status':initial_status,'redirect_count':len(chain),'redirect_terminal_error':'REDIRECT_WITHOUT_LOCATION'}
            nxt=urllib.parse.urljoin(current,loc)
            # Validate every redirect destination before the next connection.
            nxt_u,nxt_ips=validate_target(nxt)
            chain.append({**hop_record,'to':nxt,'next_validated_ip':nxt_ips[0] if nxt_ips else None})
            current=nxt; continue
        return {'status':status,'final_url':effective,'headers':hdrs,'body':data,'content_length':len(data),'content_type':hdrs.get('Content-Type',''),'redirect_chain':chain,'resolved_ip':ip,'initial_status':initial_status,'redirect_count':len(chain)}
    raise ValueError(f'Se superó el máximo de redirecciones ({max_redirects}).')

def chrome_path():
    global CHROME
    if CHROME: return CHROME
    for p in ['/usr/bin/chromium','/usr/bin/chromium-browser','/usr/bin/google-chrome']:
        if os.path.exists(p): CHROME=p; return p
    raise RuntimeError('No se encontró Chromium/Chrome.')

def _norm_url(raw):
    try:
        u=urllib.parse.urlsplit(raw); return (u.scheme.lower(), (u.hostname or '').lower(), u.port or (443 if u.scheme=='https' else 80), u.path or '/', u.query)
    except Exception: return None

def _chromium_security(proc, port):
    rows=[]
    try:
        ps=subprocess.check_output(['ps','-eo','pid,ppid,user,args'],text=True)
        for line in ps.splitlines()[1:]:
            if f'--remote-debugging-port={port}' in line: rows.append(line.strip())
    except Exception: ps=''
    chromium_pid=None
    try:
        for line in ps.splitlines()[1:]:
            parts=line.split(None,3)
            if len(parts)>=4 and parts[1]==str(proc.pid) and 'chromium' in parts[3]: chromium_pid=int(parts[0]); break
    except Exception: pass
    uid=None; seccomp=None; nnp=None
    if chromium_pid:
        try:
            st=Path(f'/proc/{chromium_pid}/status').read_text()
            for line in st.splitlines():
                if line.startswith('Uid:'): uid=int(line.split()[1])
                elif line.startswith('Seccomp:'): seccomp=int(line.split()[1])
                elif line.startswith('NoNewPrivs:'): nnp=int(line.split()[1])
        except Exception: pass
    args=' '.join(rows)
    return {'chromium_process_lines':rows,'chromium_pid':chromium_pid,'effective_user':'nobody' if any(' nobody ' in r for r in rows) else None,'effective_uid':uid,'sandbox_flag_absent':('--'+'no-sandbox') not in args,'seccomp_mode':seccomp,'no_new_privs':nnp,'sandbox_evidence':bool((uid==65534 or any(' nobody ' in r for r in rows)) and ('--'+'no-sandbox') not in args)}

def cdp_session(url, pdf=False, screenshot=False):
    try: import websocket
    except ImportError: return {'ok':False,'error':'Falta websocket-client. Instala requirements.txt.'}
    import urllib.request as ur, random
    port=random.randint(9300,9399); profile=tempfile.mkdtemp(prefix='web_audit_chrome_')
    cmd=[chrome_path(),'--headless=new','--disable-gpu','--disable-dev-shm-usage','--disable-software-rasterizer','--remote-debugging-address=127.0.0.1','--remote-allow-origins=*',f'--remote-debugging-port={port}','--user-data-dir='+profile,'about:blank']
    if os.geteuid()==0 and shutil.which('runuser'):
        try: os.chown(profile,65534,65534)
        except Exception: pass
        launch=['runuser','-u','nobody','--']+cmd
    else: launch=cmd
    proc=subprocess.Popen(launch,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    tabs=None; start=time.time()
    while time.time()-start<8:
        try:
            tabs=json.load(ur.urlopen(f'http://127.0.0.1:{port}/json',timeout=1))
            if tabs: break
        except Exception: time.sleep(.15)
    security=_chromium_security(proc,port)
    if not tabs:
        proc.kill(); return {'ok':False,'error':'No se pudo conectar con DevTools de Chromium.','browser_started':True,'cdp_connected':False,'security':security}
    try:
        ws=websocket.create_connection(tabs[0]['webSocketDebuggerUrl'],timeout=15,origin='http://127.0.0.1'); counter=0
        def cmd_call(method,params=None):
            nonlocal counter; counter+=1; ident=counter; ws.send(json.dumps({'id':ident,'method':method,'params':params or {}}))
            while True:
                msg=json.loads(ws.recv())
                if msg.get('id')==ident:return msg
        for m in ('Page.enable','Runtime.enable','Performance.enable','Network.enable','Accessibility.enable'): cmd_call(m)
        nav=cmd_call('Page.navigate',{'url':url}); time.sleep(3)
        expr="""(()=>({href:location.href,title:document.title,readyState:document.readyState,text:(document.body?.innerText||'').slice(0,1000),htmlLength:document.documentElement?.outerHTML.length||0,targetMarker:!!document.querySelector('[data-audit-target-marker=\"TARGET_DOCUMENT_MARKER\"]'),dynamicMarker:!!document.querySelector('#dynamic-marker'),html:document.documentElement?.outerHTML||''}))()"""
        info=cmd_call('Runtime.evaluate',{'expression':expr,'returnByValue':True}).get('result',{}).get('result',{}).get('value',{}) or {}
        target=_norm_url(url); actual=_norm_url(info.get('href','')); text=(info.get('text') or '').lower()
        blocked=any(x in text for x in ('err_blocked_by_client','this site has been blocked','navigation blocked','blocked by your administrator','chrome is managed')) or info.get('href','').startswith('chrome-error://')
        marker=bool(info.get('targetMarker')); confirmed=bool(target and actual==target and info.get('readyState') in ('interactive','complete') and info.get('htmlLength',0)>0 and not blocked and marker)
        dom=info.get('html','') if confirmed else ''; metrics={}; ax_nodes=0; contrast_samples=[]; interaction_signals={}
        if confirmed:
            js="""(()=>{const n=performance.getEntriesByType('navigation')[0],p=performance.getEntriesByType('paint'),l=performance.getEntriesByType('largest-contentful-paint');return {navigation:n?{dns:n.domainLookupEnd-n.domainLookupStart,connect:n.connectEnd-n.connectStart,ttfb:n.responseStart-n.requestStart,domContentLoaded:n.domContentLoadedEventEnd-n.startTime,load:n.loadEventEnd-n.startTime,transfer:n.transferSize}:null,paint:Object.fromEntries(p.map(x=>[x.name,x.startTime])),lcp:l.length?l[l.length-1].startTime:null,resources:performance.getEntriesByType('resource').map(x=>({name:x.name,duration:x.duration,size:x.transferSize||0}))}})()"""
            metrics=cmd_call('Runtime.evaluate',{'expression':js,'returnByValue':True}).get('result',{}).get('result',{}).get('value',{}) or {}
            contrast_js="""(()=>{
              const parse=(s)=>{const m=(s||'').match(/rgba?\(([^)]+)\)/i);if(!m)return null;const a=m[1].split(',').map(x=>parseFloat(x.trim()));return {r:a[0],g:a[1],b:a[2],a:a.length>3?a[3]:1};};
              const lum=(c)=>{if(!c||c.a<=0)return null;const f=v=>{v/=255;return v<=0.03928?v/12.92:Math.pow((v+0.055)/1.055,2.4)};return 0.2126*f(c.r)+0.7152*f(c.g)+0.0722*f(c.b)};
              const ratio=(a,b)=>{const la=lum(a),lb=lum(b);if(la==null||lb==null)return null;const hi=Math.max(la,lb),lo=Math.min(la,lb);return (hi+0.05)/(lo+0.05)};
              const elems=[...document.querySelectorAll('p,a,button,label,h1,h2,h3,h4,h5,h6,li,td,th,input,textarea,select')];
              const rows=[];
              for(const el of elems){const r=el.getBoundingClientRect();if(!r.width||!r.height)continue;const cs=getComputedStyle(el);if(cs.visibility==='hidden'||cs.display==='none')continue;
                const fg=parse(cs.color);let bg=null;let node=el;let unresolved=false;
                while(node&&node.nodeType===1){const s=getComputedStyle(node);if(s.backgroundImage&&s.backgroundImage!=='none'){unresolved=true;break;}const bc=parse(s.backgroundColor);if(bc&&bc.a>0){if(bc.a<1){unresolved=true;break;}bg=bc;break;}node=node.parentElement;}
                const px=parseFloat(cs.fontSize)||0;const fw=parseInt(cs.fontWeight,10)||400;const large=px>=24 || (px>=18.66 && fw>=700);
                rows.push({selector:el.tagName.toLowerCase()+(el.id?'#'+el.id:''),text:(el.innerText||el.value||'').trim().slice(0,120),color:cs.color,background:bg?`rgb(${bg.r},${bg.g},${bg.b})`:null,background_image:cs.backgroundImage,font_size_px:px,font_weight:fw,large_text:large,ratio:unresolved?null:ratio(fg,bg),unresolvable:unresolved});
                if(rows.length>=100)break;
              }return rows;})()"""
            contrast_samples=cmd_call('Runtime.evaluate',{'expression':contrast_js,'returnByValue':True}).get('result',{}).get('result',{}).get('value',[]) or []
            ax_nodes=len(cmd_call('Accessibility.getFullAXTree').get('result',{}).get('nodes',[]))
        shot=cmd_call('Page.captureScreenshot',{'format':'png','captureBeyondViewport':True}).get('result',{}).get('data') if screenshot and confirmed else None
        pdfdata=cmd_call('Page.printToPDF',{'printBackground':True,'preferCSSPageSize':True}).get('result',{}).get('data') if pdf and confirmed else None
        out={'ok':confirmed,'browser_started':True,'cdp_connected':True,'navigation_attempted':True,'navigation_completed':bool(nav.get('result',{}).get('frameId')),'effective_url':info.get('href'),'target_marker_detected':marker,'block_page_detected':blocked,'target_document_confirmed':confirmed,'dom_extracted':bool(dom),'executed_dom':bool(confirmed and dom),'dom':dom,'initial_html_marker':bool(DYNAMIC_MARKER not in (info.get('html') or '')),'dynamic_marker':bool(info.get('dynamicMarker')),'metrics':metrics,'contrast_samples':contrast_samples,'ax_nodes':ax_nodes,'screenshot':shot,'pdf':pdfdata,'browser_error':None if confirmed else 'El documento objetivo no fue confirmado por Chromium.','security':security}
        if not out['target_document_confirmed']: out['executed_dom']=False; out['dom_extracted']=False
        ws.close(); proc.terminate(); return out
    except Exception as e:
        try: proc.kill()
        except Exception: pass
        return {'ok':False,'browser_started':True,'cdp_connected':True,'navigation_attempted':True,'navigation_completed':False,'target_document_confirmed':False,'dom_extracted':False,'executed_dom':False,'error':str(e),'security':security}

def ev(eid, criterion, scope, value, method, certainty='ALTA', source='HTTP/DOM', limitation='', run_id='', requested_url='', effective_url='', conditions=None, tool_version='0.2'):
    return {'evidence_id':eid,'run_id':run_id,'criterion':criterion,'scope':scope,'value':value,'method':method,'source':source,'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'requested_url':requested_url,'effective_url':effective_url,'reference':criterion,'conditions':conditions or {},'tool_version':tool_version,'certainty':certainty,'limitation':limitation}

def rr(rid, criterion, state, eid, explanation, recommendation='', limitation='', priority='MEDIA', run_id=''):
    base=rid.split('-',2)[-1] if rid else criterion
    return {'id':rid,'run_id':run_id,'criterion':criterion,'state':state,'evidence_id':eid,'explanation':explanation,'diagnosis_id':f'DIA-{run_id}-{criterion}','diagnosis':explanation,'recommendation_id':f'REC-{run_id}-{criterion}','recommendation':recommendation,'limitation_id':f'LIM-{run_id}-{criterion}','limitation':limitation,'priority':priority}

def analyze(raw, want_shot=False, want_pdf=False):
    requested_url=raw
    t0=time.time(); run_id=uuid.uuid4().hex[:12]; budget=RunBudget()
    try:
        http=fetch_url(requested_url,budget=budget)
    except (socket.timeout, TimeoutError) as e:
        seo02_eid=f'E-SEO-02-{run_id}'
        seo02_err={'requested_url':requested_url,'redirect_hops':[],'status':None,'Location':None,'resolved_ip':None,'effective_url':None,'error':{'class':'TARGET_TIMEOUT','message':str(e)}}
        seo02_ev=ev(seo02_eid,'SEO-02','PAGE',seo02_err,'HTTP redirect acquisition',certainty='BAJA',source='HTTP client',limitation='No pudo evaluarse la cadena de redirección por timeout.',run_id=run_id,requested_url=requested_url,effective_url=requested_url,conditions={'execution_error':True})
        seo02_rr=rr(f'R-SEO-02-{run_id}','SEO-02','NO_EVALUABLE',seo02_eid,'No pudo evaluarse la cadena de redirección por timeout.','Revisar el acceso y repetir la evaluación cuando exista evidencia observable.','El error técnico no demuestra ausencia de redirección.','ALTA',run_id)
        return {'ok':True,'run_id':run_id,'generated_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'target':{'input':requested_url,'requested_url':requested_url},'execution_error':{'class':'TARGET_TIMEOUT','message':str(e)},'coverage':{'static_html':False,'executed_dom':False,'browser':False,'browser_started':False,'cdp_connected':False,'navigation_attempted':False,'navigation_completed':False,'target_document_confirmed':False,'dom_extracted':False,'human_review':False},'evidence':[seo02_ev, ev('E-TR-ERROR','TR-07','PAGE',{'error_class':'TARGET_TIMEOUT','message':str(e)},'HTTP acquisition',certainty='ALTA',source='HTTP client',limitation='No se obtuvo el documento objetivo.',run_id=run_id,requested_url=requested_url,effective_url=requested_url,conditions={'execution_error':True})],'results':[seo02_rr, rr('R-TR-ERROR','TR-07','NO_EVALUABLE','E-TR-ERROR','El target agotó el tiempo de acceso; no se dispone de evidencia suficiente para evaluar el documento.','Reintentar bajo condiciones de red controladas.','La ausencia de respuesta no equivale a ausencia de problema.','ALTA',run_id)],'priorities':[],'limitations':['La ejecución se abstuvo por timeout del target.'],'duration_ms':round((time.time()-t0)*1000)}
    except Exception as e:
        seo02_eid=f'E-SEO-02-{run_id}'
        seo02_err={'requested_url':requested_url,'redirect_hops':[],'status':None,'Location':None,'resolved_ip':None,'effective_url':None,'error':{'class':'TARGET_ACCESS_OR_VALIDATION','message':str(e)}}
        seo02_ev=ev(seo02_eid,'SEO-02','PAGE',seo02_err,'HTTP redirect acquisition',certainty='BAJA',source='HTTP client',limitation='No pudo evaluarse la cadena de redirección por fallo de acceso o validación.',run_id=run_id,requested_url=requested_url,effective_url=requested_url,conditions={'execution_error':True})
        seo02_rr=rr(f'R-SEO-02-{run_id}','SEO-02','NO_EVALUABLE',seo02_eid,'No pudo evaluarse la cadena de redirección por fallo de acceso o validación.','Revisar el acceso y repetir la evaluación cuando exista evidencia observable.','El error técnico no demuestra ausencia de redirección.','ALTA',run_id)
        return {'ok':True,'run_id':run_id,'generated_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'target':{'input':requested_url,'requested_url':requested_url},'execution_error':{'class':'TARGET_ACCESS_OR_VALIDATION','message':str(e)},'coverage':{'static_html':False,'executed_dom':False,'browser':False,'browser_started':False,'cdp_connected':False,'navigation_attempted':False,'navigation_completed':False,'target_document_confirmed':False,'dom_extracted':False,'human_review':False},'evidence':[seo02_ev, ev('E-TR-ERROR','TR-07','PAGE',{'error_class':'TARGET_ACCESS_OR_VALIDATION','message':str(e)},'HTTP acquisition',certainty='ALTA',source='HTTP client',limitation='No se obtuvo el documento objetivo.',run_id=run_id,requested_url=requested_url,effective_url=requested_url,conditions={'execution_error':True})],'results':[seo02_rr, rr('R-TR-ERROR','TR-07','NO_EVALUABLE','E-TR-ERROR','No se obtuvo evidencia suficiente del target por un fallo de acceso o validación.','Revisar el acceso y repetir la evaluación cuando exista evidencia observable.','El fallo de acceso no equivale a ausencia de problema.','ALTA',run_id)],'priorities':[],'limitations':['La ejecución se abstuvo por fallo de acceso/validación del target.'],'duration_ms':round((time.time()-t0)*1000)}
    static=http['body'].decode('utf-8','replace'); c=Collector(); c.feed(static)
    static_sufficient=bool(static.strip()) and bool(http.get('content_type','').lower().startswith(('text/html','application/xhtml+xml','text/plain')) or '<html' in static.lower())
    rendered=cdp_session(http['final_url'],pdf=want_pdf,screenshot=want_shot)
    dom=rendered.get('dom','') if rendered.get('target_document_confirmed') else ''
    initial_html_sha256=hashlib.sha256(static.encode('utf-8','replace')).hexdigest()
    executed_dom_sha256=hashlib.sha256(dom.encode('utf-8','replace')).hexdigest() if dom else None
    dynamic_marker_in_initial_html=DYNAMIC_MARKER in static
    dynamic_marker_in_executed_dom=DYNAMIC_MARKER in dom if dom else False
    html_initial_diff=bool(dom) and static != dom
    rendered['initial_html_sha256']=initial_html_sha256
    rendered['executed_dom_sha256']=executed_dom_sha256
    rendered['dynamic_marker_in_initial_html']=dynamic_marker_in_initial_html
    rendered['dynamic_marker_in_executed_dom']=dynamic_marker_in_executed_dom
    rendered['html_initial_diff']=html_initial_diff
    cr=Collector(); cr.feed(dom) if dom else None
    page=cr if dom else c if static_sufficient else Collector()
    # HTTP/metadata
    robots_txt=None; sitemap=None
    try: robots_txt=fetch_url(urllib.parse.urljoin(http['final_url'],'/robots.txt'),800_000,budget=budget)['body'].decode('utf-8','replace')
    except: robots_txt=None
    try: sitemap=fetch_url(urllib.parse.urljoin(http['final_url'],'/sitemap.xml'),2_000_000,budget=budget)['body'].decode('utf-8','replace')
    except: sitemap=None
    headers=http['headers']; meta=dict((d.get('name','').lower(),d.get('content','')) for tag,d in c.meta if tag=='meta' and d.get('name'))
    og={d.get('property','').lower():d.get('content','') for tag,d in c.meta if tag=='meta' and d.get('property','').lower().startswith('og:')}
    canon=next((d.get('href') for tag,d in c.meta if tag=='link' and 'canonical' in d.get('rel','').lower().split()),'')
    robots_meta=meta.get('robots','')
    xrobots=headers.get('X-Robots-Tag','')
    evidence=[]; results=[]
    def add(e,r):
        e['run_id']=run_id
        if not e.get('requested_url'):
            e['requested_url']=requested_url
        if not e.get('effective_url'):
            e['effective_url']=http.get('final_url') or requested_url
        e.setdefault('timestamp',time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()))
        e['tool_version']=APP_VERSION
        e.setdefault('conditions',{})
        e.setdefault('reference',e.get('criterion'))
        r['run_id']=run_id
        r['diagnosis_id']=f'DIA-{run_id}-{r["criterion"]}'
        r['recommendation_id']=f'REC-{run_id}-{r["criterion"]}'
        r['limitation_id']=f'LIM-{run_id}-{r["criterion"]}'
        r['diagnosis']=r.get('explanation','')
        evidence.append(e); results.append(r)
    seo01_state='CORRECTO' if http['status']==200 and static_sufficient else 'DETECTADO' if http['status']>=400 else 'EVIDENCIA_INSUFICIENTE'
    seo01_expl=f'HTTP {http["status"]} y documento con contenido suficiente.' if seo01_state=='CORRECTO' else f'HTTP {http["status"]}; la evidencia no permite declarar disponibilidad positiva.'
    add(ev('E-SEO-01','SEO-01','PAGE',{'status':http['status'],'final_url':http['final_url'],'content_type':http.get('content_type'),'content_length':http.get('content_length'),'redirect_chain':http.get('redirect_chain',[])},'HTTP GET',run_id=run_id,requested_url=requested_url,effective_url=http['final_url'],conditions={'static_sufficient':static_sufficient}), rr('R-SEO-01','SEO-01',seo01_state,'E-SEO-01',seo01_expl,'Revisar disponibilidad y contenido de la URL objetivo.' if seo01_state!='CORRECTO' else '', 'HTTP 200 vacío o contenido no soportado no constituye evidencia suficiente.', 'ALTA',run_id))
    # SEO-02 — redirect chain as an independent, reproducible result.
    redirect_chain=http.get('redirect_chain',[]) or []
    redirect_evidence={'requested_url':requested_url,'initial_status':http.get('initial_status',http.get('status')),'redirect_count':len(redirect_chain),
                       'redirect_chain':redirect_chain,'effective_url':http.get('final_url'),'final_status':http.get('status'),'max_redirects':5,
                       'hop_validation':'Cada destino fue validado antes de la siguiente conexión.'}
    if http.get('redirect_terminal_error'):
        seo02_state='EVIDENCIA_INSUFICIENTE'
        seo02_expl='Se detectó una respuesta de redirección sin Location; la cadena no puede reconstruirse completamente.'
        seo02_lim='La ausencia de Location impide reconstruir el destino de ese salto.'
    else:
        seo02_state='DETECTADO' if redirect_chain else 'CORRECTO'
        seo02_expl=(f'Se detectaron {len(redirect_chain)} redirección(es) y se reconstruyó la cadena hasta la URL efectiva.'
                    if redirect_chain else 'No se detectó redirección; la URL solicitada fue evaluada directamente.')
        seo02_lim='Detectar una redirección no implica por sí mismo que sea incorrecta; la interpretación debe considerar destino, cadena y contexto.'
    add(ev('E-SEO-02','SEO-02','PAGE',redirect_evidence,'HTTP GET / redirect chain',certainty='ALTA',source='HTTP client',
           limitation=seo02_lim,run_id=run_id,requested_url=requested_url,effective_url=http['final_url'],conditions={'per_hop_target_validation':True,'max_redirects':5}),
        rr('R-SEO-02','SEO-02',seo02_state,'E-SEO-02',seo02_expl,
           'Revisar la cadena de redirecciones, destinos y URL efectiva.' if redirect_chain else '',seo02_lim,'ALTA',run_id))
    add(ev('E-SEO-03','SEO-03','PAGE',{'scheme':urllib.parse.urlparse(http['final_url']).scheme},'URL/HTTP'), rr('R-SEO-03','SEO-03','CORRECTO' if http['final_url'].startswith('https://') else 'DETECTADO','E-SEO-03','HTTPS activo.' if http['final_url'].startswith('https://') else 'La URL final no usa HTTPS.','Servir la página mediante HTTPS.','No evalúa toda la configuración TLS.', 'ALTA'))
    add(ev('E-SEO-04','SEO-04','SITE',{'robots_available':robots_txt is not None,'sample':robots_txt[:1000] if robots_txt else None},'HTTP GET'), rr('R-SEO-04','SEO-04','CORRECTO' if robots_txt is not None else 'EVIDENCIA_INSUFICIENTE','E-SEO-04','robots.txt recuperable.' if robots_txt else 'No se pudo recuperar robots.txt.','Revisar reglas de rastreo.','La existencia de robots.txt no demuestra una configuración correcta.','MEDIA'))
    add(ev('E-SEO-07','SEO-07','SITE',{'sitemap_available':sitemap is not None},'HTTP GET'), rr('R-SEO-07','SEO-07','CORRECTO' if sitemap is not None else 'EVIDENCIA_INSUFICIENTE','E-SEO-07','Sitemap recuperable.' if sitemap else 'No se pudo recuperar sitemap.xml.','Revisar descubrimiento y consistencia del sitemap.','Evidencia auxiliar; no demuestra indexación.','MEDIA'))
    add(ev('E-SEO-14','SEO-14','PAGE',{'title':page.title,'length':len(page.title)},'DOM/HTML'), rr('R-SEO-14','SEO-14','CORRECTO' if page.title else 'DETECTADO','E-SEO-14','Existe title.' if page.title else 'No se detectó title.','Definir un title descriptivo.','No se impone una longitud rígida.','ALTA'))
    desc=next((d.get('content','') for tag,d in c.meta if tag=='meta' and d.get('name','').lower()=='description'),'')
    add(ev('E-SEO-15','SEO-15','PAGE',{'description':desc,'length':len(desc)},'HTML'), rr('R-SEO-15','SEO-15','CORRECTO' if desc else 'EVIDENCIA_INSUFICIENTE','E-SEO-15','Meta description presente.' if desc else 'No se detectó meta description.','Revisar descripción y propósito de la página.','No se impone una longitud rígida.','MEDIA'))
    add(ev('E-SEO-16','SEO-16','PAGE',{'h1_count':len(page.h1),'headings':page.headings},'DOM/HTML'), rr('R-SEO-16','SEO-16','CORRECTO' if len(page.h1)==1 else 'PARCIAL' if len(page.h1)>1 else 'DETECTADO','E-SEO-16',f'Se detectan {len(page.h1)} H1.','Revisar jerarquía y claridad semántica.','La cantidad de H1 no determina por sí sola calidad SEO.','MEDIA'))
    add(ev('E-SEO-12','SEO-12','PAGE',{'canonical':canon},'HTML'), rr('R-SEO-12','SEO-12','CORRECTO' if canon else 'EVIDENCIA_INSUFICIENTE','E-SEO-12','Canonical declarado.' if canon else 'No se detectó canonical.','Revisar coherencia del canonical con la URL preferida.','La declaración no demuestra la selección del buscador.','MEDIA'))
    add(ev('E-SEO-10','SEO-10','PAGE',{'meta_robots':robots_meta,'x_robots_tag':xrobots},'HTML/HTTP'), rr('R-SEO-10','SEO-10','CORRECTO' if 'noindex' not in (robots_meta+' '+xrobots).lower() else 'DETECTADO','E-SEO-10','No se detecta noindex.' if 'noindex' not in (robots_meta+' '+xrobots).lower() else 'Se detecta noindex en la señal analizada.','Confirmar que la indexabilidad pretendida coincide con la intención.','La indexación real requiere evidencia externa.','ALTA'))
    add(ev('E-SEO-19','SEO-19','PAGE',{'lang':page.lang},'DOM/HTML'), rr('R-SEO-19','SEO-19','CORRECTO' if page.lang else 'DETECTADO','E-SEO-19','Idioma declarado.' if page.lang else 'No se detectó lang.','Declarar correctamente el idioma.','No sustituye revisión de experiencia accesible.','MEDIA'))
    add(ev('E-SEO-20','SEO-20','PAGE',{'viewport':next((d.get('content','') for tag,d in c.meta if tag=='meta' and d.get('name','').lower()=='viewport'),'')},'HTML'), rr('R-SEO-20','SEO-20','CORRECTO' if any(tag=='meta' and d.get('name','').lower()=='viewport' for tag,d in c.meta) else 'EVIDENCIA_INSUFICIENTE','E-SEO-20','Viewport declarado.' if any(tag=='meta' and d.get('name','').lower()=='viewport' for tag,d in c.meta) else 'No se detectó viewport.','Revisar adaptación móvil.','No demuestra equivalencia funcional móvil.','MEDIA'))
    # SEO-09 — separate DOM difference from functional JS dependency.
    script_count=len(re.findall(r'<script\b',static,re.I))
    material_dynamic=bool(dynamic_marker_in_executed_dom and not dynamic_marker_in_initial_html)
    dynamic_content_detected=material_dynamic
    dynamic_content_relevance='OBSERVABLE_MARKER' if material_dynamic else 'NOT_DEMONSTRATED'
    js_dependency_evidence='DIRECT_DYNAMIC_MARKER' if material_dynamic else 'INSUFFICIENT'
    if not rendered.get('target_document_confirmed'):
        seo09_state='NO_EVALUABLE'
        seo09_expl='No se confirmó el documento objetivo en Chromium; no puede determinarse la relación entre HTML inicial y DOM ejecutado.'
        seo09_lim='Sin target_document_confirmed=true no se considera válida la evidencia de DOM ejecutado.'
    elif material_dynamic:
        seo09_state='DETECTADO'
        seo09_expl='Se observó contenido dinámico mediante el marcador controlado en el DOM ejecutado que no estaba presente en el HTML inicial.'
        seo09_lim='La evidencia demuestra contenido dinámico observable; no demuestra por sí sola que toda la indexabilidad dependa de JavaScript.'
    elif html_initial_diff:
        seo09_state='EVIDENCIA_INSUFICIENTE'
        seo09_expl='HTML inicial y DOM ejecutado difieren, pero la diferencia observada no demuestra por sí sola dependencia funcional de JavaScript.'
        seo09_lim='La diferencia de serialización/estado del documento es una señal no concluyente; no se atribuye dependencia funcional sin evidencia contextual suficiente.'
    else:
        seo09_state='CORRECTO'
        seo09_expl='No se observó diferencia material entre HTML inicial y DOM ejecutado que demuestre dependencia funcional de JavaScript.'
        seo09_lim='La conclusión se limita a la ejecución observada y no demuestra comportamiento en estados o navegaciones no ejecutados.'
    add(ev('E-SEO-09','SEO-09','PAGE',{'initial_html_sha256':initial_html_sha256,'executed_dom_sha256':executed_dom_sha256,'html_initial_diff':html_initial_diff,
           'dynamic_marker_in_initial_html':dynamic_marker_in_initial_html,'dynamic_marker_in_executed_dom':dynamic_marker_in_executed_dom,
           'dynamic_content_detected':dynamic_content_detected,'dynamic_content_relevance':dynamic_content_relevance,
           'js_dependency_evidence':js_dependency_evidence,'script_count_initial':script_count,
           'browser_started':bool(rendered.get('browser_started')),'cdp_connected':bool(rendered.get('cdp_connected')),'navigation_completed':bool(rendered.get('navigation_completed')),
           'target_document_confirmed':bool(rendered.get('target_document_confirmed')),'executed_dom':bool(rendered.get('executed_dom'))},
           'Chromium/CDP real navigation + initial HTML vs executed DOM',certainty='ALTA' if rendered.get('target_document_confirmed') else 'BAJA',source='Chromium/CDP',
           limitation=seo09_lim,run_id=run_id,requested_url=requested_url,effective_url=http['final_url'],conditions={'Page.setDocumentContent':False}),
        rr('R-SEO-09','SEO-09',seo09_state,'E-SEO-09',seo09_expl,
           'Revisar contenido crítico que aparece o cambia tras la ejecución de JavaScript.' if seo09_state in ('DETECTADO','PARCIAL') else '',seo09_lim,'ALTA',run_id))
    imgs=page.images; missing=sum('alt' not in x for x in imgs)
    add(ev('E-ACC-05','ACC-05','PAGE',{'images':len(imgs),'missing_alt':missing},'DOM/HTML'), rr('R-ACC-05','ACC-05','NO_APLICABLE' if not imgs else 'CORRECTO' if not missing else 'PARCIAL','E-ACC-05',f'Imágenes {len(imgs)}; sin alt {missing}.','Revisar adecuación contextual de textos alternativos.','Presencia técnica de alt no demuestra adecuación.','ALTA'))
    forms=page.inputs; labels=[]
    for tag,d in forms:
        if tag in ('input','select','textarea'):
            ok=bool(d.get('aria-label') or d.get('aria-labelledby') or d.get('title') or (d.get('id') and re.search(r'<label[^>]+for=["\']'+re.escape(d.get('id'))+'["\']',dom,re.I)) or re.search(r'<label[^>]*>[^<]*',dom,re.I))
            labels.append(ok)
    unlabeled=labels.count(False)
    add(ev('E-ACC-06','ACC-06','PAGE',{'controls':len(labels),'unlabeled':unlabeled},'DOM/HTML'), rr('R-ACC-06','ACC-06','NO_APLICABLE' if not labels else 'CORRECTO' if not unlabeled else 'PARCIAL','E-ACC-06',f'Controles de formulario {len(labels)}; sin asociación detectable {unlabeled}.','Revisar nombres y asociación contextual.','No sustituye tecnología asistiva.','ALTA'))
    unnamed=sum(1 for tag,d in page.inputs if tag=='button' and not (d.get('aria-label') or d.get('aria-labelledby') or d.get('title')))
    add(ev('E-ACC-07','ACC-07','PAGE',{'controls':len(page.inputs),'potentially_unnamed_buttons':unnamed},'DOM/HTML'), rr('R-ACC-07','ACC-07','CORRECTO' if unnamed==0 else 'PARCIAL','E-ACC-07','Nombres técnicos de controles revisados.','Revisar nombres accesibles.','No valida el nombre calculado completo.','ALTA'))
    add(ev('E-ACC-04','ACC-04','PAGE',{'main':page.main,'nav':page.nav,'header':page.header,'footer':page.footer,'aside':page.aside},'DOM/HTML'), rr('R-ACC-04','ACC-04','CORRECTO' if page.main else 'DETECTADO','E-ACC-04','Región main detectada.' if page.main else 'No se detectó main.','Revisar landmarks.','No demuestra experiencia con lector de pantalla.','MEDIA'))
    # ACC-08 — technical contrast signal based on computed browser styles.
    contrast_rows=rendered.get('contrast_samples',[]) if rendered.get('target_document_confirmed') else []
    # Technical thresholds used by the accessibility check: normal text 4.5:1, large text 3:1.
    contrast_evaluable=[x for x in contrast_rows if x.get('ratio') is not None and not x.get('unresolvable')]
    contrast_unresolved=[x for x in contrast_rows if x.get('unresolvable') or x.get('ratio') is None]
    contrast_fail=[x for x in contrast_evaluable if x.get('ratio') < (3.0 if x.get('large_text') else 4.5)]
    if not rendered.get('target_document_confirmed'):
        acc08_state='NO_EVALUABLE'; acc08_expl='No se pudo confirmar el documento en Chromium; no existe evidencia computada suficiente de estilos.'
        acc08_lim='La comprobación depende de estilos computados del navegador y requiere target confirmado.'
    elif not contrast_evaluable:
        acc08_state='EVIDENCIA_INSUFICIENTE'; acc08_expl='No se pudo calcular de forma fiable el contraste de los elementos observados.'
        acc08_lim='Casos complejos o estilos no resolubles requieren abstención/revisión humana.'
    elif contrast_fail:
        acc08_state='PARCIAL'; acc08_expl=f'Se calcularon {len(contrast_evaluable)} elementos; {len(contrast_fail)} presentan una ratio inferior al umbral técnico aplicable.'
        acc08_lim='Es una señal técnica de contraste, no una declaración de conformidad WCAG ni de experiencia perceptiva.'
    elif contrast_unresolved:
        acc08_state='PARCIAL'; acc08_expl=f'Se calcularon {len(contrast_evaluable)} elementos sin fallo técnico observado, pero {len(contrast_unresolved)} no pudieron resolverse de forma fiable.'
        acc08_lim='Los casos no resolubles deben revisarse manualmente; no se convierten en CORRECTO.'
    else:
        acc08_state='CORRECTO'; acc08_expl=f'Se calculó el contraste de {len(contrast_evaluable)} elementos y no se observaron ratios inferiores al umbral técnico aplicable.'
        acc08_lim='La comprobación es técnica y no sustituye evaluación humana o tecnología asistiva.'
    add(ev('E-ACC-08','ACC-08','PAGE',{'samples_total':len(contrast_rows),'evaluable':len(contrast_evaluable),'unresolved':len(contrast_unresolved),
           'failures':len(contrast_fail),'thresholds':{'normal_text_ratio':4.5,'large_text_ratio':3.0},'samples':contrast_rows},
           'Chromium/CDP computed styles + contrast calculation',certainty='ALTA' if contrast_evaluable else 'BAJA',source='Chromium computed styles',
           limitation=acc08_lim,run_id=run_id,requested_url=requested_url,effective_url=http['final_url'],conditions={'wcag_conformance_claim':False,'assistive_validation':False}),
        rr('R-ACC-08','ACC-08',acc08_state,'E-ACC-08',acc08_expl,
           'Revisar los elementos con contraste insuficiente o no resoluble.' if acc08_state in ('PARCIAL','DETECTADO') else '',acc08_lim,'ALTA',run_id))
    # SEO-08 — internal link status using the existing fetch/SSRF architecture.
    base_u=urllib.parse.urlparse(http['final_url']); base_host=(base_u.hostname or '').lower(); base_port=base_u.port or (443 if base_u.scheme=='https' else 80)
    link_rows=[]; seen_links=set(); internal_links=[]
    for idx,ld in enumerate(page.links):
        raw_href=(ld.get('href') or '').strip()
        if not raw_href or raw_href.startswith(('mailto:','tel:','javascript:')): continue
        dest=urllib.parse.urljoin(http['final_url'],raw_href)
        du=urllib.parse.urlparse(dest); host=(du.hostname or '').lower(); port=du.port or (443 if du.scheme=='https' else 80)
        if du.scheme not in ('http','https') or host!=base_host or port!=base_port: continue
        if du.fragment and urllib.parse.urlunsplit((du.scheme,du.netloc,du.path,du.query,''))==urllib.parse.urlunsplit((base_u.scheme,base_u.netloc,base_u.path,base_u.query,'')):
            link_rows.append({'index':idx,'href':raw_href,'destination':dest,'internal':True,'fragment_only':True,'state':'NO_APLICABLE'}); continue
        key=urllib.parse.urldefrag(dest)[0]
        if key in seen_links: link_rows.append({'index':idx,'href':raw_href,'destination':dest,'internal':True,'duplicate':True,'state':'NO_APLICABLE'}); continue
        seen_links.add(key); internal_links.append((idx,raw_href,dest))
    for idx,raw_href,dest in internal_links:
        row={'index':idx,'href':raw_href,'destination':dest,'internal':True}
        try:
            lr=fetch_url(dest,max_bytes=1_000_000,max_redirects=5,budget=budget)
            row.update({'evaluable':True,'status':lr.get('status'),'effective_url':lr.get('final_url'),'redirect_count':lr.get('redirect_count',0),'resolved_ip':lr.get('resolved_ip'),'error':None})
            row['state']='CORRECTO' if lr.get('status',0)<400 else 'DETECTADO'
        except Exception as e:
            row.update({'evaluable':False,'status':None,'error_class':type(e).__name__,'error':str(e),'state':'NO_EVALUABLE'})
        link_rows.append(row)
    evaluated_links=[x for x in link_rows if x.get('evaluable') is True]
    link_fail=[x for x in evaluated_links if (x.get('status') or 0)>=400]
    link_errors=[x for x in link_rows if x.get('state')=='NO_EVALUABLE']
    if not internal_links and not any(x.get('fragment_only') for x in link_rows):
        seo08_state='NO_APLICABLE'; seo08_expl='No se detectaron enlaces internos HTTP(S) evaluables en la página.'
    elif link_fail:
        seo08_state='DETECTADO'; seo08_expl=f'Se evaluaron {len(evaluated_links)} enlaces internos; {len(link_fail)} devolvieron HTTP >= 400.'
    elif link_errors and not evaluated_links:
        seo08_state='NO_EVALUABLE'; seo08_expl=f'No pudo evaluarse ninguno de los {len(link_errors)} enlaces internos detectados.'
    elif link_errors:
        seo08_state='PARCIAL'; seo08_expl=f'Se evaluaron {len(evaluated_links)} enlaces internos y {len(link_errors)} no pudieron evaluarse; la evidencia no permite tratarlos como enlaces rotos.'
    else:
        seo08_state='CORRECTO'; seo08_expl=f'Se evaluaron {len(evaluated_links)} enlaces internos sin respuestas HTTP >= 400.'
    seo08_lim='Un fallo de acceso no se interpreta como enlace roto; el resultado depende de la evidencia HTTP disponible y del presupuesto de ejecución.'
    add(ev('E-SEO-08','SEO-08','PAGE',{'base_url':http['final_url'],'internal_links_detected':len(internal_links),'rows':link_rows,'evaluated':len(evaluated_links),'errors':len(link_errors)},
           'DOM/HTML + HTTP GET using existing fetch_url/SSRF controls',certainty='ALTA' if evaluated_links or not internal_links else 'BAJA',source='DOM/HTTP client',
           limitation=seo08_lim,run_id=run_id,requested_url=requested_url,effective_url=http['final_url'],conditions={'same_host_and_port_only':True,'max_redirects':5}),
        rr('R-SEO-08','SEO-08',seo08_state,'E-SEO-08',seo08_expl,
           'Revisar enlaces internos con respuesta >= 400 y repetir los no evaluables bajo condiciones de red controladas.' if seo08_state in ('DETECTADO','PARCIAL') else '',seo08_lim,'ALTA',run_id))
    # JSON-LD
    jsonld=[]; invalid=0
    for jsonld_raw in re.findall(r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',static,re.I|re.S):
        try: jsonld.append(json.loads(jsonld_raw))
        except: invalid+=1
    seo26_source=dom if rendered.get('target_document_confirmed') and dom else static
    seo26_jsonld=[]; seo26_invalid=0
    for raw_jsonld in re.findall(r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',seo26_source,re.I|re.S):
        try: seo26_jsonld.append(json.loads(raw_jsonld))
        except: seo26_invalid+=1
    jsonld_blocks_detected=len(re.findall(r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>',seo26_source,re.I))
    seo26_state='CORRECTO' if jsonld_blocks_detected>0 and seo26_invalid==0 else 'DETECTADO' if jsonld_blocks_detected>0 else 'EVIDENCIA_INSUFICIENTE'
    seo26_expl=('Se detectó al menos un bloque JSON-LD en el documento analizado y todos los bloques observados fueron parseables.' if seo26_state=='CORRECTO' else
                'Se detectó uno o más bloques JSON-LD, pero al menos uno no pudo parsearse.' if seo26_state=='DETECTADO' else
                'No se detectó presencia de JSON-LD en el HTML analizado.')
    add(ev('E-SEO-26','SEO-26','PAGE',{'blocks_detected':jsonld_blocks_detected,'jsonld_parseable_blocks':len(seo26_jsonld),'invalid_blocks':seo26_invalid,'types':[x.get('@type') for x in seo26_jsonld if isinstance(x,dict) and x.get('@type')],'source':'executed_dom' if dom and rendered.get('target_document_confirmed') else 'initial_html'},
           'HTML/JSON-LD presence extraction'),
        rr('R-SEO-26','SEO-26',seo26_state,'E-SEO-26',seo26_expl,
           'Revisar sintaxis, tipos y correspondencia con el contenido visible.' if jsonld_blocks_detected else 'Añadir datos estructurados cuando sean apropiados.',
           'Presencia de JSON-LD no implica validez semántica, rich result ni citación.', 'MEDIA',run_id))
    add(ev('E-SEO-27','SEO-27','PAGE',{'blocks':len(jsonld),'invalid_blocks':invalid},'HTML/JSON'), rr('R-SEO-27','SEO-27','CORRECTO' if jsonld and invalid==0 else 'PARCIAL' if jsonld else 'EVIDENCIA_INSUFICIENTE','E-SEO-27','JSON-LD presente y parseable.' if jsonld and invalid==0 else 'JSON-LD parcial/ausente.','Validar sintaxis y correspondencia visible.','Schema presente no garantiza rich result ni citación.','MEDIA'))
    text=' '.join(page.text); sameas=len(re.findall(r'"sameAs"\s*:',static,re.I)); author=bool(re.search(r'(author|rel=["\']author)',static,re.I)); dates=bool(re.search(r'(datePublished|dateModified|<time)',static,re.I)); q=len(re.findall(r'<h[1-6][^>]*>.*?\?</h[1-6]>',dom or static,re.I|re.S)); lists=len(re.findall(r'<(?:ul|ol)\b',dom or static,re.I));
    add(ev('E-AI-04','AI-04','PAGE',{'text_chars':len(text)},'DOM/HTML'), rr('R-AI-04','AI-04','CORRECTO' if len(text)>100 else 'PARCIAL','E-AI-04',f'Texto recuperable: {len(text)} caracteres.','Revisar que el contenido relevante esté en el DOM accesible.','No demuestra citación por sistemas de IA.','ALTA'))
    add(ev('E-AI-07','AI-07','PAGE',{'jsonld_blocks':len(jsonld)},'HTML/JSON'), rr('R-AI-07','AI-07','PARCIAL' if jsonld else 'EVIDENCIA_INSUFICIENTE','E-AI-07','Hay señales estructuradas.' if jsonld else 'No se detectó JSON-LD.','Revisar entidades y correspondencia semántica.','No valida entidades externas.','MEDIA'))
    add(ev('E-AI-08','AI-08','PAGE',{'sameAs':sameas},'HTML'), rr('R-AI-08','AI-08','PARCIAL' if sameas else 'EVIDENCIA_INSUFICIENTE','E-AI-08',f'sameAs detectados: {sameas}.','Revisar relaciones e identidad.','Conteo de sameAs no demuestra relación correcta.','BAJA'))
    ext=0
    try: host=urllib.parse.urlparse(http['final_url']).hostname; ext=sum(1 for x in page.links if x.get('href','').startswith(('http://','https://')) and urllib.parse.urlparse(x.get('href')).hostname!=host)
    except: pass
    add(ev('E-AI-11','AI-11','PAGE',{'external_links':ext},'DOM/HTML'), rr('R-AI-11','AI-11','PARCIAL' if ext else 'EVIDENCIA_INSUFICIENTE','E-AI-11',f'Enlaces externos: {ext}.','Revisar fuentes pertinentes y verificables.','Número de enlaces no mide autoridad.','MEDIA'))
    add(ev('E-AI-12','AI-12','PAGE',{'author_signal':author},'HTML'), rr('R-AI-12','AI-12','PARCIAL' if author else 'EVIDENCIA_INSUFICIENTE','E-AI-12','Señal de autoría detectada.' if author else 'No se detectó señal de autoría.','Revisar autoría y contexto.','Presencia no demuestra autoridad.','MEDIA'))
    add(ev('E-AI-14','AI-14','PAGE',{'date_signal':dates},'HTML'), rr('R-AI-14','AI-14','PARCIAL' if dates else 'EVIDENCIA_INSUFICIENTE','E-AI-14','Señal de fecha detectada.' if dates else 'No se detectó fecha.','Revisar frescura contextual.','Fecha presente no demuestra actualidad.','BAJA'))
    add(ev('E-AI-15','AI-15','PAGE',{'questions':q,'lists':lists,'paragraphs':len(re.findall(r'<p\b',dom or static,re.I))},'DOM/HTML'), rr('R-AI-15','AI-15','PARCIAL' if (q or lists) else 'EVIDENCIA_INSUFICIENTE','E-AI-15',f'Preguntas: {q}; listas: {lists}.','Revisar claridad y estructura extractable.','Heurística, no métrica de citación.','MEDIA'))
    # bot access signals
    bots=['OAI-SearchBot','GPTBot','ClaudeBot','PerplexityBot','Google-Extended','bingbot']
    bot_rows=[]
    if robots_txt:
        for b in bots:
            lines=robots_txt.lower().splitlines(); relevant=[]; current=False
            for ln in lines:
                ln=ln.strip()
                if ln.startswith('user-agent:'): current=(b.lower() in ln[11:].strip() or ln[11:].strip()=='*')
                elif current and ln.startswith('disallow:'): relevant.append(ln[9:].strip())
            bot_rows.append({'bot':b,'disallow':relevant[:10]})
    add(ev('E-AI-01','AI-01','SITE',{'bots':bot_rows},'robots.txt'), rr('R-AI-01','AI-01','CORRECTO' if robots_txt is not None else 'EVIDENCIA_INSUFICIENTE','E-AI-01','Señales de robots recuperadas.' if robots_txt else 'No se pudo evaluar robots.','Revisar acceso declarado por bot.','Acceso permitido no garantiza citación.','MEDIA'))
    # performance
    perf=rendered.get('metrics',{}) if rendered.get('ok') else {}
    nav=perf.get('navigation') or {}; paint=perf.get('paint') or {}
    add(ev('E-TR-PERF','TR-PERF','PAGE',{'ttfb_ms':nav.get('ttfb'),'fcp_ms':paint.get('first-contentful-paint'),'lcp_ms':perf.get('lcp'),'dom_ms':nav.get('domContentLoaded'),'load_ms':nav.get('load'),'transfer_bytes':nav.get('transfer')},'Chromium Performance API',source='Chromium'), rr('R-TR-PERF','TR-PERF','CORRECTO' if perf else 'NO_EVALUABLE','E-TR-PERF','Métricas de navegación del navegador disponibles.' if perf else 'No se obtuvieron métricas del navegador.','Revisar tendencias de rendimiento y campo cuando existan datos.','No sustituye Core Web Vitals de campo.','MEDIA'))
    states=[r['state'] for r in results if r['state'] not in ('NO_APLICABLE',)]
    def cov(prefix):
        ss=[r['state'] for r in results if r['criterion'].startswith(prefix) and r['state']!='NO_APLICABLE']
        if not ss:return None
        return round(sum(1 if s=='CORRECTO' else .5 if s=='PARCIAL' else 0 for s in ss)/len(ss)*100)
    priorities=[r for r in results if r['state'] in ('DETECTADO','PARCIAL') and r['priority'] in ('ALTA','MEDIA')]
    nav_eid=f'E-NAV-{run_id}'
    evidence.append(ev(nav_eid,'TR-07','PAGE',{'browser_started':bool(rendered.get('browser_started')),'cdp_connected':bool(rendered.get('cdp_connected')),'navigation_attempted':bool(rendered.get('navigation_attempted')),'navigation_completed':bool(rendered.get('navigation_completed')),'effective_url':rendered.get('effective_url'),'target_marker_detected':bool(rendered.get('target_marker_detected')),'block_page_detected':bool(rendered.get('block_page_detected')),'target_document_confirmed':bool(rendered.get('target_document_confirmed')),'dom_extracted':bool(rendered.get('dom_extracted')),'executed_dom':bool(rendered.get('executed_dom')),'initial_html_sha256':rendered.get('initial_html_sha256'),'executed_dom_sha256':rendered.get('executed_dom_sha256'),'dynamic_marker_in_initial_html':bool(rendered.get('dynamic_marker_in_initial_html')),'dynamic_marker_in_executed_dom':bool(rendered.get('dynamic_marker_in_executed_dom')),'html_initial_diff':bool(rendered.get('html_initial_diff')),'chromium_security':rendered.get('security',{})},'Chromium/CDP real navigation',certainty='ALTA',source='Chromium/CDP',limitation='La confirmación positiva exige URL compatible, readyState válido, HTML no vacío, ausencia de bloqueo y marcador inequívoco de fixture.',run_id=run_id,requested_url=requested_url,effective_url=rendered.get('effective_url'),conditions={'executed_dom_requires_target_document_confirmed':True}))
    results.append(rr(f'R-NAV-{run_id}','TR-07','CORRECTO' if rendered.get('target_document_confirmed') else 'EVIDENCIA_INSUFICIENTE',nav_eid,'Navegación target confirmada.' if rendered.get('target_document_confirmed') else 'Chromium no confirmó el documento target; el DOM ejecutado permanece en abstención.','Repetir en un entorno Chromium sin la política de bloqueo global, manteniendo sandbox, usuario no privilegiado y controles SSRF.','Page.setDocumentContent es solo una prueba tecnológica y no sustituye navegación real.','ALTA',run_id))
    limitations=['Indicadores por área no son ranking ni probabilidad de posicionamiento.','AI Search readiness no es performance, indexación ni citación real.','No se declara conformidad WCAG ni accesibilidad real con lector/Braille.','La evidencia de campo requiere fuentes externas como Search Console/Bing Webmaster cuando estén disponibles.','La revisión heurística/humana sigue siendo necesaria para calidad semántica, contexto, alt y autoridad.']
    if not rendered.get('target_document_confirmed'): limitations.append('Chromium no confirmó que el DOM perteneciera al documento objetivo; executed_dom/browser se mantienen en falso.')
    if http['status']>=400: limitations.append(f'El recurso devolvió HTTP {http["status"]}; no se trata como error interno del motor.')
    return {'ok':True,'run_id':run_id,'generated_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'target':{'input':requested_url,'final_url':http['final_url'],'requested_url':requested_url,'redirect_chain':http.get('redirect_chain',[]),'status_code':http['status'],'content_type':http.get('content_type'),'content_length':http.get('content_length')},'coverage':{'static_html':True,'executed_dom':bool(dom),'browser':bool(rendered.get('target_document_confirmed')),'browser_started':bool(rendered.get('browser_started')),'cdp_connected':bool(rendered.get('cdp_connected')),'navigation_attempted':bool(rendered.get('navigation_attempted')),'navigation_completed':bool(rendered.get('navigation_completed')),'target_document_confirmed':bool(rendered.get('target_document_confirmed')),'dom_extracted':bool(rendered.get('dom_extracted')),'human_review':False,'target_marker_detected':bool(rendered.get('target_marker_detected')),'block_page_detected':bool(rendered.get('block_page_detected')),'chromium_security':rendered.get('security',{})},'areas':{'seo':cov('SEO'),'accessibility':cov('ACC'),'ai_search_readiness':cov('AI')},'evidence':evidence,'results':results,'priorities':priorities,'performance':perf,'accessibility_tree_nodes':rendered.get('ax_nodes'),'screenshot':rendered.get('screenshot'),'pdf':rendered.get('pdf'),'limitations':limitations,'duration_ms':round((time.time()-t0)*1000)}

HTML='''<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Web Audit PRO</title><link rel="stylesheet" href="/static/styles.css"></head><body><a class="skip" href="#main">Saltar al contenido</a><header><div><span class="eyebrow">AUDITORÍA WEB LOCAL</span><h1>SEO · Accesibilidad · AI Search · Rendimiento</h1><p>Un único campo URL. Evidencia técnica, resultados trazables y reporte.</p></div></header><main id="main"><section class="card"><h2>Analizar una página</h2><form id="f"><label for="url">URL</label><div class="inputrow"><input id="url" required type="url" placeholder="https://ejemplo.com"><button>Analizar</button></div><label class="check"><input type="checkbox" id="shot"> Capturar screenshot</label><p id="status" role="status" aria-live="polite"></p></form></section><section id="report" hidden><div id="hero"></div><nav class="tabs" aria-label="Secciones"><a href="#prioridades">Prioridades</a><a href="#seo">SEO</a><a href="#acc">Accesibilidad</a><a href="#ai">AI Search</a><a href="#perf">Rendimiento</a><a href="#evidence">Evidencia</a></nav><section id="prioridades" class="card"><h2>Prioridades</h2><div id="priority"></div></section><section id="seo" class="card"><h2>SEO</h2><div id="seoMetrics" class="grid"></div><div id="seoBars"></div></section><section id="acc" class="card"><h2>Accesibilidad técnica</h2><div id="accMetrics" class="grid"></div><div id="accBars"></div></section><section id="ai" class="card"><h2>AI Search — readiness</h2><div id="aiMetrics" class="grid"></div><div id="aiBars"></div></section><section id="perf" class="card"><h2>Rendimiento</h2><div id="perfMetrics" class="grid"></div><pre id="perfRaw"></pre></section><section id="evidence" class="card"><h2>Evidencia y trazabilidad</h2><details><summary>Ver evidencia</summary><pre id="ev"></pre></details><details><summary>Ver resultados</summary><pre id="res"></pre></details><h3>Limitaciones</h3><ul id="lims"></ul></section><div class="actions"><button id="pdf">Guardar reporte como PDF</button><button id="json">Descargar JSON</button></div></section></main><footer>Los indicadores son estados de auditoría, no garantías de ranking, indexación, citación ni conformidad WCAG.</footer><script src="/static/app.js"></script></body></html>'''

class Handler(BaseHTTPRequestHandler):
    def _send(self,status,ctype,data):
        if isinstance(data,str): data=data.encode()
        self.send_response(status); self.send_header('Content-Type',ctype); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        if self.path=='/': return self._send(200,'text/html; charset=utf-8',HTML)
        if self.path=='/static/app.js': return self._send(200,'text/javascript; charset=utf-8',APP_JS)
        if self.path=='/static/styles.css': return self._send(200,'text/css; charset=utf-8',CSS)
        self._send(404,'text/plain','Not found')
    def do_POST(self):
        if self.path!='/api/analyze': return self._send(404,'text/plain','Not found')
        try:
            n=int(self.headers.get('content-length','0')); payload=json.loads(self.rfile.read(n) or '{}'); out=analyze(payload.get('url',''),bool(payload.get('screenshot')),bool(payload.get('pdf'))); self._send(200,'application/json; charset=utf-8',json.dumps(out,ensure_ascii=False))
        except Exception as e: self._send(500,'application/json; charset=utf-8',json.dumps({'ok':False,'error':str(e),'error_class':'ENGINE_OR_INFRASTRUCTURE'},ensure_ascii=False))

APP_JS=r'''const $=s=>document.querySelector(s);let last=null;function esc(s){return String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));}function metric(t,v,sub=''){return `<article class="metric"><span>${esc(t)}</span><strong>${esc(v??'—')}</strong><small>${esc(sub)}</small></article>`}function bar(label,val){return `<div class="barrow"><span>${esc(label)}</span><div class="track"><i style="width:${Math.max(0,Math.min(100,val||0))}%"></i></div><b>${val??'—'}</b></div>`}function render(d){last=d;$('#report').hidden=false;$('#hero').innerHTML=`<div class="hero"><div><span class="eyebrow">INFORME GENERADO</span><h2>${esc(d.target.final_url)}</h2><p>Duración ${d.duration_ms} ms · DOM ejecutado: ${d.coverage.executed_dom?'sí':'no'} · navegador: ${d.coverage.browser?'sí':'no'}</p></div><div class="heroScores">${metric('SEO',d.areas.seo+'%','indicador de checks')}${metric('Accesibilidad',d.areas.accessibility+'%','indicador técnico')}${metric('AI Search',d.areas.ai_search_readiness+'%','readiness')}</div></div>`;$('#priority').innerHTML=d.priorities.length?d.priorities.map(x=>`<article class="priority ${x.priority}"><b>${esc(x.criterion)} · ${esc(x.state)}</b><p>${esc(x.explanation)}</p><small>${esc(x.recommendation||'Revisar evidencia')}</small></article>`).join(''):'<p>No se detectaron prioridades automáticas en la muestra.</p>';$('#seoMetrics').innerHTML=metric('Title',d.results.find(x=>x.criterion==='SEO-14')?.state)+metric('Canonical',d.results.find(x=>x.criterion==='SEO-12')?.state)+metric('Robots',d.results.find(x=>x.criterion==='SEO-10')?.state);$('#accMetrics').innerHTML=metric('ALT',d.results.find(x=>x.criterion==='ACC-05')?.state)+metric('Labels',d.results.find(x=>x.criterion==='ACC-06')?.state)+metric('Landmarks',d.results.find(x=>x.criterion==='ACC-04')?.state);$('#aiMetrics').innerHTML=metric('Contenido',d.results.find(x=>x.criterion==='AI-04')?.state)+metric('Entidades',d.results.find(x=>x.criterion==='AI-07')?.state)+metric('Autoría',d.results.find(x=>x.criterion==='AI-12')?.state);$('#seoBars').innerHTML=bar('Cobertura SEO',d.areas.seo);$('#accBars').innerHTML=bar('Cobertura técnica',d.areas.accessibility);$('#aiBars').innerHTML=bar('Readiness heurística',d.areas.ai_search_readiness);const p=d.performance||{};$('#perfMetrics').innerHTML=metric('TTFB',p.navigation?.ttfb?Math.round(p.navigation.ttfb)+' ms':'—')+metric('FCP',p.paint?.['first-contentful-paint']?Math.round(p.paint['first-contentful-paint'])+' ms':'—')+metric('LCP',p.lcp?Math.round(p.lcp)+' ms':'—')+metric('Carga',p.navigation?.load?Math.round(p.navigation.load)+' ms':'—');$('#perfRaw').textContent=JSON.stringify(p,null,2);$('#ev').textContent=JSON.stringify(d.evidence,null,2);$('#res').textContent=JSON.stringify(d.results,null,2);$('#lims').innerHTML=d.limitations.map(x=>`<li>${esc(x)}</li>`).join('');$('#status').textContent='Análisis completado.';location.hash='report'}$('#f').addEventListener('submit',async e=>{e.preventDefault();$('#status').textContent='Analizando…';try{const r=await fetch('/api/analyze',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({url:$('#url').value,screenshot:$('#shot').checked})});const d=await r.json();if(!d.ok)throw Error(d.error||'No se pudo analizar');render(d)}catch(err){$('#status').textContent='Error: '+err.message}});$('#pdf').onclick=async()=>{if(!last)return;$('#status').textContent='Generando PDF…';const r=await fetch('/api/analyze',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({url:last.target.input,pdf:true})});const d=await r.json();if(d.pdf){const a=document.createElement('a');a.href='data:application/pdf;base64,'+d.pdf;a.download='web-audit-report.pdf';a.click()}$('#status').textContent='PDF preparado.'};$('#json').onclick=()=>{if(!last)return;const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(last,null,2)],{type:'application/json'}));a.download='web-audit-report.json';a.click()};'''
CSS=r''':root{font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#16202a;background:#f3f5f8;line-height:1.5}*{box-sizing:border-box}body{margin:0}.skip{position:absolute;left:-9999px}.skip:focus{left:1rem;top:1rem;z-index:20;background:#fff;padding:.6rem;border:2px solid #111}header{background:#111827;color:#fff;padding:2.5rem max(1rem,calc((100vw - 1180px)/2))}main{max-width:1180px;margin:auto;padding:1rem}.eyebrow{font-size:.75rem;letter-spacing:.12em;font-weight:800}.card{background:#fff;border:1px solid #d8dee8;border-radius:16px;padding:1.25rem;margin:1rem 0;box-shadow:0 4px 16px #0000000b}h1{max-width:800px;margin:.4rem 0;font-size:clamp(1.8rem,4vw,3rem)}h2{margin-top:0}.inputrow{display:flex;gap:.75rem}input[type=url]{flex:1;padding:.9rem;border:1px solid #9aa5b5;border-radius:10px;font-size:1rem}button{padding:.85rem 1rem;border-radius:10px;border:1px solid #111827;background:#111827;color:#fff;font-weight:700;cursor:pointer}button:focus-visible,input:focus-visible{outline:3px solid #5b8def;outline-offset:3px}.check{display:block;margin-top:.75rem}.tabs{position:sticky;top:0;background:#f3f5f8;padding:.7rem 0;display:flex;gap:.5rem;flex-wrap:wrap;z-index:5}.tabs a{background:#fff;border:1px solid #d8dee8;border-radius:999px;padding:.45rem .75rem;text-decoration:none;color:#16202a}.hero{display:grid;grid-template-columns:1fr 1.4fr;gap:1rem;background:#111827;color:#fff;border-radius:16px;padding:1.25rem}.heroScores{display:grid;grid-template-columns:repeat(3,1fr);gap:.7rem}.metric{background:#fff;color:#16202a;border:1px solid #d8dee8;border-radius:12px;padding:.85rem;display:flex;flex-direction:column;min-height:100px}.hero .metric{background:#1f2937;color:#fff;border-color:#374151}.metric span{font-size:.85rem}.metric strong{font-size:1.45rem;margin:.25rem 0}.metric small{color:#667085}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:.8rem}.barrow{display:grid;grid-template-columns:180px 1fr 55px;gap:.75rem;align-items:center;margin:.7rem 0}.track{height:14px;background:#e5e7eb;border-radius:999px;overflow:hidden}.track i{display:block;height:100%;background:#2563eb}.priority{border-left:5px solid #ca8a04;background:#fafafa;padding:.8rem;margin:.6rem 0;border-radius:8px}.priority.ALTA{border-left-color:#b91c1c}.priority.BAJA{border-left-color:#64748b}pre{overflow:auto;background:#0f172a;color:#e2e8f0;padding:1rem;border-radius:10px;max-height:480px}.actions{display:flex;gap:.7rem;margin:1rem 0}footer{max-width:1180px;margin:auto;padding:2rem 1rem;color:#667085}@media(max-width:800px){.hero{grid-template-columns:1fr}.heroScores,.grid{grid-template-columns:1fr}.inputrow{flex-direction:column}.barrow{grid-template-columns:110px 1fr 45px}}@media print{header{background:#111827!important}.tabs,.actions,.card:first-of-type{display:none!important}.card{box-shadow:none;break-inside:avoid}.hero{color:#000;background:#fff;border:1px solid #aaa}.hero .metric{color:#000;background:#fff;border-color:#aaa}}'''

if __name__=='__main__':
    print(f'Web Audit PRO: http://{HOST}:{PORT}')
    ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()
