import assert from 'node:assert/strict';
import http from 'node:http';
import {readFileSync} from 'node:fs';
import {randomBytes,createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {resolve} from 'node:path';
import {encryptPasswordEnvelope,protectPasswordBody} from './password-envelope.mjs';

const port=Number(process.env.GATEWAY_TEST_PORT||19090),domain='gateway.perfy576.com',origin='https://'+domain;
const record=readFileSync('.secrets/initial-admin.txt','utf8');
const rootUsername=record.match(/^Username: (.+)$/m)[1],rootPassword=record.match(/^Password: (.+)$/m)[1];
const suffix=randomBytes(5).toString('hex'),username='encrypted_'+suffix,password=randomBytes(20).toString('hex');
const host='encrypted-'+suffix+'.invalid',appid='encrypted-'+suffix;
let rootCookie='',csrf='',userId='',serviceId='';
const cookies=response=>(response.headers['set-cookie']||[]).map(value=>value.split(';')[0]).join('; ');
async function raw(path,{method='GET',body,cookie=rootCookie,headers={}}={}){
  const encoded=body===undefined?undefined:Buffer.from(JSON.stringify(body));
  return new Promise((resolve,reject)=>{
    const req=http.request({host:'127.0.0.1',port,path,method,headers:{Host:domain,Cookie:cookie,
      'X-Forwarded-For':'192.0.2.95',...(encoded?{'Content-Type':'application/json','Content-Length':encoded.length,Origin:origin,'X-Gateway-Request':'1','X-CSRF-Token':csrf}:{}),...headers}},res=>{
      const chunks=[];res.on('data',chunk=>chunks.push(chunk));res.on('end',()=>{
        let json;try{json=JSON.parse(Buffer.concat(chunks).toString());}catch{}
        resolve({status:res.statusCode,headers:res.headers,json});
      });
    });req.on('error',reject);req.setTimeout(15000,()=>req.destroy(new Error('Test request timed out')));req.end(encoded);
  });
}
async function get(path){const r=await raw(path);assert.equal(r.status,200,path);return r.json;}
async function api(path,method='GET',body){
  body=await protectPasswordBody(path,method,body,get);
  const r=await raw(path,{method,body});assert.equal(r.status,200,r.json?.error||path);return r.json;
}
async function loginBody({key,pass=password,account=username,context=['POST','/api/login','admin','',''],audience=origin}={}){
  key??=await get('/api/public/password-key');
  return {username:account,mode:'admin',password_envelope:await encryptPasswordEnvelope({...key,audience},audience,account,context,{password:pass})};
}
const login=body=>raw('/api/login',{method:'POST',body,cookie:''});
async function dartEnvelope(){
  const key=await get('/api/public/password-key');
  const sdk=process.env.GATEWAY_SDK_DIR||resolve('../gateway-sdk/flutter-sdk');
  return new Promise((resolve,reject)=>{
    const child=spawn(process.env.DART_BIN||'dart',['run','tool/password_envelope_probe.dart'],{cwd:sdk,stdio:['pipe','pipe','pipe']});
    let output='',error='';child.stdout.on('data',part=>output+=part);child.stderr.on('data',part=>error+=part);
    child.on('error',reject);child.on('exit',code=>code===0?resolve(output.trim()):reject(new Error('Dart encryption probe failed: '+error)));
    child.stdin.end(JSON.stringify({key_response:key,audience:origin,username,context:['POST','/api/login','admin','',''],passwords:{password}}));
  });
}
async function flow(){
  const r=await raw('/internal/auth',{cookie:'',headers:{'X-Forwarded-Host':host,'X-Forwarded-Uri':'/private','X-Forwarded-Method':'GET'}});
  assert.equal(r.status,302);return new URL(r.headers.location).searchParams.get('token');
}
try{
  const root=await login(await loginBody({account:rootUsername,pass:rootPassword}));assert.equal(root.status,200);
  rootCookie=cookies(root);csrf=(await get('/api/me')).csrf;
  await api('/api/admin/users','POST',{username,display_name:'Encrypted password test',password,role:'admin',enabled:true});
  userId=(await get('/api/admin/state')).users.find(u=>u.username===username).id;
  serviceId=(await api('/api/admin/services','POST',{appid,name:'Encrypted password test',host,upstream:'http://127.0.0.1:19091',enabled:true,allow_all:false,users:[userId],excluded_paths:[]})).id;

  const key=await get('/api/public/password-key');
  assert.equal(key.jwk.d,undefined);assert.equal(key.jwk.alg,'RSA-OAEP-256');
  const body=await loginBody({key});assert(!JSON.stringify(body).includes(password));
  assert.notEqual(body.password_envelope,(await loginBody({key})).password_envelope);
  const concurrent=await Promise.all([login(body),login(body)]);
  assert.deepEqual(concurrent.map(r=>r.status).sort(),[200,409]);
  assert.equal((await login(await loginBody({key}))).status,409);
  assert.equal((await login(await loginBody({key:{...key,timestamp_ms:key.timestamp_ms-1}}))).status,409);
  let current=await login(await loginBody());assert.equal(current.status,200);
  console.log('PASS randomized JWE, private-key exclusion, concurrent/equal/lower timestamp rejection and newer timestamp acceptance');

  for(const changes of [
    {audience:'https://other.invalid'},
    {account:username+'x'},
    {context:['POST','/login',appid,'other-token']},
    {key:{...key,timestamp_ms:Date.now()-180000}},
    {key:{...key,timestamp_ms:Date.now()+60000}},
  ]){
    const bad=await loginBody(changes);
    if(changes.account)bad.username=username;
    assert.equal((await login(bad)).status,400);
  }
  const parts=body.password_envelope.split('.');
  const tamper=[...parts];tamper[4]=(tamper[4][0]==='A'?'B':'A')+tamper[4].slice(1);
  assert.equal((await login({...body,password_envelope:tamper.join('.')})).status,400);
  const wrongAlgorithm=[...parts];wrongAlgorithm[0]=Buffer.from(JSON.stringify({...JSON.parse(Buffer.from(parts[0],'base64url')),alg:'RSA1_5'})).toString('base64url');
  assert.equal((await login({...body,password_envelope:wrongAlgorithm.join('.')})).status,400);
  assert.equal((await login({username,password,mode:'admin'})).status,426);
  assert.equal((await login({...body,password})).status,426);
  assert.equal((await login(await loginBody({key:{...await get('/api/public/password-key'),timestamp_ms:Date.now()+15000},pass:'wrong-password'}))).status,401);
  current=await login({username,mode:'admin',password_envelope:await dartEnvelope()});assert.equal(current.status,200);
  console.log('PASS Flutter/Dart JWE decrypts in the C++ Gateway');
  console.log('PASS account/audience/context binding, timestamp window, GCM integrity, algorithm downgrade/plaintext rejection and no timestamp advance on wrong password');

  const token=await flow(),appKey=await get('/api/public/password-key');
  const appBody={username,appid,token,password_envelope:await encryptPasswordEnvelope(appKey,origin,username,['POST','/login',appid,token],{password})};
  const app=await raw('/login',{method:'POST',body:appBody,cookie:''});assert.equal(app.status,200,app.json?.retmsg);
  assert(app.json.cookie.includes('__Host-gateway_binding='));assert.equal(app.headers['set-cookie'],undefined);
  assert.equal((await login(await loginBody({key:appKey}))).status,409);
  assert.equal((await raw('/login',{method:'POST',body:appBody,cookie:''})).status,410);
  console.log('PASS App cookie contract and shared timestamp replay barrier across App and console login');

  const userCookie=cookies(current),me=await raw('/api/me',{cookie:userCookie});assert.equal(me.status,200);
  const nextPassword='New-密码-"\\-'+randomBytes(16).toString('hex');
  const changeKey=await get('/api/public/password-key');
  const change={password_envelope:await encryptPasswordEnvelope(changeKey,origin,username,['POST','/api/password'],{old_password:password,new_password:nextPassword})};
  const changed=await raw('/api/password',{method:'POST',body:change,cookie:userCookie,headers:{'X-CSRF-Token':me.json.csrf}});
  assert.equal(changed.status,200,changed.json?.error);
  assert.equal((await login(await loginBody({pass:nextPassword}))).status,200);
  console.log('PASS encrypted password creation/change and UTF-8/quote/backslash interoperability');
}finally{
  if(serviceId)await api('/api/admin/services/'+serviceId,'DELETE',{});
  if(userId)await api('/api/admin/users/'+userId,'DELETE',{});
  const value=rootCookie.match(/__Host-gateway_session=([^;]+)/)?.[1];
  if(value)await api('/api/admin/sessions/'+createHash('sha256').update(value).digest('hex'),'DELETE',{});
}
