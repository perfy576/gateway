import assert from 'node:assert/strict';
import http from 'node:http';
import {readFileSync} from 'node:fs';
import {randomBytes,createHash} from 'node:crypto';

const port=Number(process.env.GATEWAY_TEST_PORT||19090);
const gateway='gateway.perfy576.com',origin='https://'+gateway;
const record=readFileSync('.secrets/initial-admin.txt','utf8');
const username=record.match(/^Username: (.+)$/m)[1],password=record.match(/^Password: (.+)$/m)[1];
const suffix=randomBytes(4).toString('hex'),host='client-info-'+suffix+'.invalid';
const jars=new Map(),sessionIds=new Set();
let csrf='',serviceId;
const agent='NAS/0.1.4 (Flutter; android) GatewayFlutterSDK/1.3.0',packageName='com.perfy576.nas';
const browserAgent='Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Version/18.0 Mobile Safari/604.1';
const appHeaders={'User-Agent':agent,'X-Gateway-App-Package':packageName};
const cookieFor=domain=>[...(jars.get(domain)||new Map())].map(([k,v])=>k+'='+v).join('; ');
async function request(path,{domain=gateway,method='GET',body,headers={}}={}){
  const encoded=body===undefined?undefined:Buffer.from(JSON.stringify(body));
  const outgoing={Host:domain,Cookie:cookieFor(domain),...headers};
  if(encoded)Object.assign(outgoing,{'Content-Type':'application/json','Content-Length':encoded.length,Origin:origin,'X-Gateway-Request':'1','X-CSRF-Token':csrf});
  return new Promise((resolve,reject)=>{
    const req=http.request({hostname:'127.0.0.1',port,path,method,headers:outgoing},res=>{
      const chunks=[];res.on('data',chunk=>chunks.push(chunk));res.on('end',()=>{
        for(const raw of res.headers['set-cookie']||[]){
          const pair=raw.split(';')[0],eq=pair.indexOf('=');
          if(!jars.has(domain))jars.set(domain,new Map());
          jars.get(domain).set(pair.slice(0,eq),pair.slice(eq+1));
        }
        const text=Buffer.concat(chunks).toString();let json;try{json=JSON.parse(text);}catch{}
        resolve({status:res.statusCode,headers:res.headers,json});
      });
    });req.on('error',reject);req.setTimeout(15000,()=>req.destroy(new Error('Timeout')));req.end(encoded);
  });
}
async function api(path,method='GET',body,headers={}){
  const response=await request(path,{method,body,headers});
  assert.equal(response.status,200,response.json?.error||response.json?.retmsg||path);return response.json;
}
async function challenge(){
  jars.delete(host);
  const result=await request('/internal/auth',{domain:host,headers:{'X-Forwarded-Host':host,'X-Forwarded-Uri':'/private','X-Forwarded-Method':'GET','User-Agent':browserAgent}});
  assert.equal(result.status,302);return new URL(result.headers.location).searchParams.get('token');
}
async function nativeLogin(headers){
  const result=await api('/login','POST',{appid:'client-info-'+suffix,token:await challenge(),username,passwd:password},headers);
  assert.equal(result.result,'Ok');
  const token=result.cookie.match(/__Host-gateway_session=([^;]+)/)[1];
  const id=createHash('sha256').update(token).digest('hex');sessionIds.add(id);return id;
}
try{
  await api('/api/login','POST',{username,password,mode:'admin'},appHeaders);
  csrf=(await api('/api/me')).csrf;
  const consoleSession=createHash('sha256').update(jars.get(gateway).get('__Host-gateway_session')).digest('hex');
  const config={appid:'client-info-'+suffix,name:'Client info test',host,upstream:'http://127.0.0.1:19091',allow_all:true,enabled:true,users:[],excluded_paths:[]};
  serviceId=(await api('/api/admin/services','POST',config,appHeaders)).id;
  const nativeId=await nativeLogin(appHeaders);

  const browser=await api('/api/login','POST',{username,password,mode:'service',appid:config.appid,token:await challenge()},{'User-Agent':browserAgent});
  const callback=new URL(browser.redirect);
  assert.equal((await request(callback.pathname+callback.search,{domain:host,headers:{'User-Agent':browserAgent}})).status,302);
  const browserId=createHash('sha256').update(jars.get(host).get('__Host-gateway_session')).digest('hex');sessionIds.add(browserId);
  const sessions=(await api('/api/admin/state')).sessions;
  for(const id of [consoleSession,nativeId]){
    const found=sessions.find(s=>s.id===id);assert(found);
    assert.equal(found.user_agent,agent);assert.equal(found.app_package,packageName);
  }
  const browserSession=sessions.find(s=>s.id===browserId);
  assert.equal(browserSession.user_agent,browserAgent);assert.equal(browserSession.app_package,'');
  const audits=(await api('/api/admin/audit')).entries;
  assert(audits.some(a=>a.action==='service.create'&&a.detail===host&&a.app_package===packageName&&a.user_agent===agent));
  assert(audits.some(a=>a.action==='login.success'&&a.detail==='appid='+config.appid&&a.app_package===packageName&&a.user_agent===agent));
  assert(audits.some(a=>a.action==='login.success'&&a.detail==='appid='+config.appid&&a.app_package===''&&a.user_agent===browserAgent));
  console.log('PASS app/console sessions and browser callback retain client identity; audit records each request identity');

  const legacyId=await nativeLogin({});
  const sanitizedId=await nativeLogin({'User-Agent':'A'.repeat(2048),'X-Gateway-App-Package':'invalid package'});
  const refreshed=(await api('/api/admin/state')).sessions;
  const legacy=refreshed.find(s=>s.id===legacyId);assert.equal(legacy.user_agent,'');assert.equal(legacy.app_package,'');
  const sanitized=refreshed.find(s=>s.id===sanitizedId);assert.equal(sanitized.app_package,'');assert.equal(sanitized.user_agent,'A'.repeat(1024));
  assert.equal((await request('/healthz',{headers:{'User-Agent':'invalid-\xff'}})).status,400);
  const failed=await request('/api/login',{method:'POST',body:{username:'missing_'+suffix,password:'not-a-password',mode:'admin'},headers:appHeaders});
  assert.equal(failed.status,401);
  const failure=(await api('/api/admin/audit')).entries.find(a=>a.actor==='missing_'+suffix&&a.action==='login.failed');
  assert(failure);assert.equal(failure.app_package,packageName);assert.equal(failure.user_agent,agent);
  console.log('PASS missing/invalid metadata stays compatible, lengths are bounded, malformed HTTP headers are rejected and failed login is audited');

  const quick=await api('/api/login/quick','POST',{appid:config.appid,token:await challenge()},{'User-Agent':browserAgent});
  const quickCallback=new URL(quick.redirect);
  assert.equal((await request(quickCallback.pathname+quickCallback.search,{domain:host,headers:{'User-Agent':browserAgent}})).status,302);
  const quickId=createHash('sha256').update(jars.get(host).get('__Host-gateway_session')).digest('hex');sessionIds.add(quickId);
  const quickSession=(await api('/api/admin/state')).sessions.find(s=>s.id===quickId);
  assert.equal(quickSession.user_agent,browserAgent);assert.equal(quickSession.app_package,'');
  assert((await api('/api/admin/audit')).entries.some(a=>a.detail==='appid='+config.appid+'; method=quick'&&a.user_agent===browserAgent&&a.app_package===''));
  console.log('PASS quick login records the active browser, rather than copying the console client identity');
}finally{
  for(const id of sessionIds)await api('/api/admin/sessions/'+id,'DELETE',{}).catch(()=>{});
  if(serviceId)await api('/api/admin/services/'+serviceId,'DELETE',{});
  if(jars.get(gateway)?.has('__Host-gateway_session')){
    const id=createHash('sha256').update(jars.get(gateway).get('__Host-gateway_session')).digest('hex');
    await api('/api/admin/sessions/'+id,'DELETE',{});
  }
}
