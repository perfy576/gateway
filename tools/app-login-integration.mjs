import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import {readFileSync} from 'node:fs';
import {spawn} from 'node:child_process';
import {createHmac,randomBytes} from 'node:crypto';

const origin='https://gateway.perfy576.com',host='gateway-app-login.invalid',other='gateway-app-other.invalid';
const appid='Custom_App.2026',sdk='/data/code/gateway-sdk';
const credentialRecord=readFileSync('.secrets/initial-admin.txt','utf8');
const adminUsername=credentialRecord.match(/^Username: (.+)$/m)[1];
const password=credentialRecord.match(/^Password: (.+)$/m)[1];
const username='app_'+randomBytes(4).toString('hex'),userPassword=randomBytes(20).toString('hex');
let adminCookie='',csrf='',id='',otherId='',userId='',secret='';
const sockets=new Set();
const backend=http.createServer((req,res)=>{res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({headers:req.headers,url:req.url}));});
backend.on('connection',socket=>{sockets.add(socket);socket.on('error',()=>{});socket.on('close',()=>sockets.delete(socket));});
await new Promise(resolve=>backend.listen(19094,'127.0.0.1',resolve));
function request(url,options={}){
  const u=new URL(url,origin),headers={Host:u.hostname,...options.headers};
  if(options.admin)headers.Cookie=adminCookie;
  let data=options.body;
  if(data!==undefined&&typeof data!=='string'){data=JSON.stringify(data);headers['Content-Type']='application/json';}
  if(data!==undefined)headers['Content-Length']=Buffer.byteLength(data);
  if(options.admin&&data!==undefined)Object.assign(headers,{Origin:origin,'X-Gateway-Request':'1','X-CSRF-Token':csrf});
  return new Promise((resolve,reject)=>{
    const req=https.request({hostname:'127.0.0.1',port:443,servername:new URL(origin).hostname,path:u.pathname+u.search,method:options.method||'GET',headers},res=>{
      const chunks=[];res.on('data',c=>chunks.push(c));res.on('end',()=>{
        let json;const text=Buffer.concat(chunks).toString();try{json=JSON.parse(text);}catch{}
        resolve({status:res.statusCode,headers:res.headers,json,text});
      });
    });req.on('error',reject);req.setTimeout(10000,()=>req.destroy(new Error('Request timeout')));req.end(data);
  });
}
async function api(path,method='GET',body){const r=await request(path,{method,body,admin:true});assert.equal(r.status,200,JSON.stringify(r.json)||r.text);return r.json;}
async function sdkCall(lang,operation,extra={}){
  const input={operation,gateway_host:origin,audience:host,appid,uri:'/private?from=app&next=%2Fdocs',method:'GET',...extra};
  return new Promise((resolve,reject)=>{
    const child=spawn(lang==='python'?sdk+'/.venv/bin/python':sdk+'/build/gateway-sdk-verify',lang==='python'?[sdk+'/python3-sdk/examples/verify.py']:[],{
      env:{...process.env,GATEWAY_TOKEN_SECRET:secret},stdio:['pipe','pipe','pipe']});
    let out='',err='';child.stdout.on('data',c=>out+=c);child.stderr.on('data',c=>err+=c);child.on('error',reject);
    child.on('close',code=>{try{assert.equal(code,0,lang+': '+err);resolve(JSON.parse(out));}catch(e){reject(e);}});child.stdin.end(JSON.stringify(input));
  });
}
const service={appid,name:'App API integration',host,upstream:'http://127.0.0.1:19094',enabled:true,allow_all:false,users:[],excluded_paths:[]};
async function login(token,changes={}){return request('/login',{method:'POST',body:{appid,token,username:adminUsername,passwd:password,...changes}});}
function failed(response,status){assert.equal(response.status,status);assert.deepEqual(Object.keys(response.json).sort(),['cookie','result','retmsg']);assert.equal(response.json.result,'Failed');assert.equal(response.json.cookie,'');assert(response.json.retmsg);assert.equal(response.headers['set-cookie'],undefined);}
function sign(claims,key=secret){const head=Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT',gwv:1})).toString('base64url'),body=Buffer.from(JSON.stringify(claims)).toString('base64url');return head+'.'+body+'.'+createHmac('sha256',createHmac('sha256',key).update('gateway/sdk-login/v1').digest('hex')).update(head+'.'+body).digest('base64url');}
try{
  const admin=await request('/api/login',{method:'POST',admin:true,body:{username:adminUsername,password,mode:'admin'}});assert.equal(admin.status,200);
  adminCookie=admin.headers['set-cookie'].map(c=>c.split(';')[0]).join('; ');csrf=(await api('/api/me')).csrf;
  const created=await api('/api/admin/services','POST',service);id=created.id;assert.equal(created.appid,appid);
  otherId=(await api('/api/admin/services','POST',{...service,appid:'Other_App',host:other})).id;
  secret=(await api(`/api/admin/services/${id}/secret`,'POST',{})).secret;assert.match(secret,/^[a-f0-9]{64}$/);
  assert.equal((await api(`/api/admin/services/${id}/secret`,'POST',{})).secret,secret);
  const duplicate=await request('/api/admin/services',{method:'POST',admin:true,body:{...service,host:'gateway-app-duplicate.invalid'}});assert.equal(duplicate.status,409);
  for(const bad of ['', 'invalid app', 'x'.repeat(65)])assert.equal((await request('/api/admin/services',{method:'POST',admin:true,body:{...service,appid:bad,host:'gateway-app-duplicate.invalid'}})).status,400);
  await api('/api/admin/users','POST',{username,display_name:'App API test',password:userPassword,role:'user',enabled:true});
  userId=(await api('/api/admin/state')).users.find(u=>u.username===username).id;
  const token=(await sdkCall('python','createLoginToken')).token;
  const claims=JSON.parse(Buffer.from(token.split('.')[1],'base64url'));assert.equal(claims.appid,appid);assert.equal(claims.exp-claims.iat,300);
  failed(await request('/login',{method:'POST',headers:{'Content-Type':'text/plain'},body:'{}'}),415);
  failed(await request('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:'{' }),400);
  failed(await login('bad-token'),400);failed(await login(token,{appid:'Unknown_App'}),400);failed(await login(token,{appid:'Other_App'}),400);
  const tampered=token.split('.');tampered[1]=Buffer.from(JSON.stringify({...claims,return_url:'https://attacker.invalid/'})).toString('base64url');failed(await login(tampered.join('.')),400);
  for(const changes of [{return_url:'https://attacker.invalid/'},{return_url:`https://${host}/%2f/evil.invalid`},{exp:claims.iat-1},{exp:claims.iat+301},{appid:'Other_App'}])failed(await login(sign({...claims,...changes})),400);
  failed(await login(token,{passwd:'wrong-password'}),401);
  failed(await login(token,{username,passwd:userPassword}),403);
  console.log('PASS custom unique AppID, generated stable Secret, login JSON error contract, signature/AppID/URL/expiry validation, wrong password and service permission denial');
  for(const lang of ['python','cpp']){
    const fresh=(await sdkCall(lang,'createLoginToken')).token;
    const result=await login(fresh);assert.equal(result.status,200);assert.equal(result.json.result,'Ok');assert.equal(result.headers['set-cookie'],undefined);
    assert.deepEqual(Object.keys(result.json).sort(),['cookie','result','retmsg']);
    assert.match(result.json.cookie,/^__Host-gateway_session=v1\.[0-9a-f]{64}; __Host-gateway_binding=v1\.[0-9a-f]{64}$/);
    const cookie=result.json.cookie;
    const forwarded=await request(`https://${host}/private?from=app&next=%2Fdocs`,{headers:{Cookie:cookie}});assert.equal(forwarded.status,200);
    assert(!forwarded.json.headers.cookie.includes('__Host-gateway_session'));
    const checked=await sdkCall(lang,'checkCookie',{token:forwarded.json.headers['x-gateway-token'],cookie:forwarded.json.headers.cookie});assert.equal(checked.result,'Ok');assert.equal(checked.claims.appid,appid);
    assert.equal((await request('/api/me',{headers:{Cookie:cookie}})).status,401);
    assert.equal((await request(`https://${other}/private`,{headers:{Cookie:cookie}})).status,302);
    assert.equal((await request(`https://${host}/private`,{headers:{Cookie:cookie.replace(/(__Host-gateway_binding=).+$/,'$1v1.'+'0'.repeat(64))}})).status,302);
    failed(await login(fresh),410);
  }
  assert.equal((await api('/api/me')).user.username,adminUsername);
  const queryToken=(await sdkCall('python','createLoginToken')).token;
  const queryUrl='/login?appid='+appid+'&token='+queryToken;
  failed(await request(queryUrl,{method:'POST',body:{appid:'Other_App',token:queryToken,username:adminUsername,passwd:password}}),400);
  const queryLogin=await request(queryUrl,{method:'POST',body:{username:adminUsername,passwd:password}});
  assert.equal(queryLogin.status,200);assert.equal(queryLogin.json.result,'Ok');assert(queryLogin.json.cookie);
  console.log('PASS both SDKs generate AppID-bound login tokens; returned cookie permits service access and checkCookie, denies admin/cross-service/binding mismatch and token replay; central browser session preserved');
  service.users=[userId];await api('/api/admin/services/'+id,'PUT',service);
  const once=(await sdkCall('cpp','createLoginToken')).token;
  const concurrent=await Promise.all([login(once,{username,passwd:userPassword}),login(once,{username,passwd:userPassword})]);
  assert.deepEqual(concurrent.map(r=>r.status).sort(),[200,410]);failed(concurrent.find(r=>r.status===410),410);
  const browser=await request(`https://${host}/browser-return?x=1`);assert.equal(browser.status,302);
  const url=new URL(browser.headers.location);assert.equal(url.searchParams.get('appid'),appid);
  const browserLogin=await login(url.searchParams.get('token'),{username,passwd:userPassword});assert.equal(browserLogin.status,200);
  failed(await login(url.searchParams.get('token'),{username,passwd:userPassword}),410);
  assert.equal((await request(`https://${host}/browser-return?x=1`,{headers:{Cookie:browserLogin.json.cookie}})).status,200);
  const oldToken=(await sdkCall('python','createLoginToken')).token,oldSecret=secret;
  const rotated=await api(`/api/admin/services/${id}/rotate`,'POST',{});secret=rotated.secret;assert.equal(rotated.appid,appid);assert.notEqual(secret,oldSecret);
  const current=await api(`/api/admin/services/${id}/secret`,'POST',{});assert.equal(current.secret,secret);assert.equal(current.appid,appid);assert.equal(current.old_secret,undefined);
  failed(await login(oldToken),400);
  const updated=(await sdkCall('python','createLoginToken')).token;
  service.enabled=false;await api('/api/admin/services/'+id,'PUT',service);failed(await login(updated),400);
  service.enabled=true;await api('/api/admin/services/'+id,'PUT',service);
  console.log('PASS concurrent one-time consumption, browser URL tokens accepted by POST /login, current-only Secret rotation and disabled-service rejection');
  let limited=false;
  for(let i=0;i<65;++i){const r=await login('bad-token');if(r.status===429){failed(r,429);limited=true;break;}failed(r,400);}
  assert(limited);console.log('PASS rate-limited API login failures never return a cookie');
}finally{
  if(id)await api('/api/admin/services/'+id,'DELETE',{}).catch(e=>{console.error('CLEANUP service',e.message);process.exitCode=1;});
  if(otherId)await api('/api/admin/services/'+otherId,'DELETE',{}).catch(e=>{console.error('CLEANUP other service',e.message);process.exitCode=1;});
  if(userId)await api('/api/admin/users/'+userId,'DELETE',{}).catch(e=>{console.error('CLEANUP user',e.message);process.exitCode=1;});
  for(const socket of sockets)socket.destroy();await new Promise(resolve=>backend.close(resolve));
}
