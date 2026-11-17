import assert from 'node:assert/strict';
import {protectPasswordBody} from './password-envelope.mjs';
import http from 'node:http';
import https from 'node:https';
import {readFileSync,writeFileSync} from 'node:fs';
import {createHmac,timingSafeEqual,createHash,randomBytes} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {spawnSync} from 'node:child_process';

const origin='https://gateway.perfy576.com';
const hostname='gateway-e2e.invalid';
const credentialRecord=readFileSync('.secrets/initial-admin.txt','utf8');
const adminUsername=credentialRecord.match(/^Username: (.+)$/m)[1];
const password=credentialRecord.match(/^Password: (.+)$/m)[1];
const jar=new Map();
let csrf='', id='', secret='', otherUser='',secondId='';
const result=[];
function check(name) { result.push(name); console.log('PASS '+name); }
function cookiesFor(host) {return [...(jar.get(host) || new Map())].map(([k,v])=>`${k}=${v}`).join('; ');}
async function request(url, options={}) {
  const parsed=new URL(url,origin), host=parsed.hostname;
  options={...options,body:await protectPasswordBody(parsed.pathname,options.method||'GET',options.body,async path=>(await request(path,{jar:options.jar})).json)};
  const headers={Host:host,...options.headers};
  if(options.jar!==false) headers.Cookie=cookiesFor(host);
  let data=options.body;
  if(data!==undefined) {data=JSON.stringify(data);Object.assign(headers,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(data),'X-Gateway-Request':'1','X-CSRF-Token':csrf,Origin:origin});}
  Object.assign(headers,options.overrideHeaders);
  return new Promise((resolve,reject)=>{
    const req=https.request({hostname:'127.0.0.1',port:443,servername:'gateway.perfy576.com',path:parsed.pathname+parsed.search,method:options.method||'GET',headers},res=>{
      const chunks=[];res.on('data',chunk=>chunks.push(chunk));res.on('end',()=>{
        if(options.jar!==false) for(const cookie of res.headers['set-cookie']||[]) {
          const [pair]=cookie.split(';'),eq=pair.indexOf('='),name=pair.slice(0,eq),value=pair.slice(eq+1);
          if(!jar.has(host))jar.set(host,new Map());if(value)jar.get(host).set(name,value);else jar.get(host).delete(name);
        }
        const text=Buffer.concat(chunks).toString();let json;try{json=JSON.parse(text);}catch{}
        resolve({status:res.statusCode,headers:res.headers,text,json,url:parsed.href});
      });
    });req.on('error',reject);req.setTimeout(15000,()=>req.destroy(new Error('Request timed out')));req.end(data);
  });
}
async function admin(path,method,body) {
  const r=await request(path,{method,body});assert.equal(r.status,200,JSON.stringify(r.json));return r.json;
}
function verify(token, expectedAudience=hostname,method='GET',uri='/healthz') {
  assert.equal(typeof token,'string');const [header,payload,signature]=token.split('.');
  assert.equal(JSON.parse(Buffer.from(header,'base64url')).alg,'HS256');
  const digest=createHmac('sha256',secret).update(header+'.'+payload).digest();
  assert(timingSafeEqual(digest,Buffer.from(signature,'base64url')));
  const claims=JSON.parse(Buffer.from(payload,'base64url'));assert.equal(claims.iss,origin);assert.equal(claims.aud,expectedAudience);
  assert(claims.exp>Math.floor(Date.now()/1000));assert(claims.exp-claims.iat===60);
  assert.equal(claims.request_method,method);assert.equal(claims.request_uri_sha256,createHash('sha256').update(uri).digest('hex'));return claims;
}
const backend=http.createServer((req,res)=>{
  if(req.url==='/events') {
    res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache'});
    res.write('data: first\n\n');setTimeout(()=>res.end('data: second\n\n'),400);return;
  }
  const chunks=[];req.on('data',c=>chunks.push(c));req.on('end',()=>{
    res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({url:req.url,method:req.method,headers:req.headers,body:Buffer.concat(chunks).toString()}));
  });
});
const sockets=new Set();
backend.on('connection',socket=>{sockets.add(socket);socket.on('error',()=>{});socket.on('close',()=>sockets.delete(socket));});
const secondary=http.createServer((req,res)=>{res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({backend:'secondary',headers:req.headers}));});
secondary.on('connection',socket=>{sockets.add(socket);socket.on('error',()=>{});socket.on('close',()=>sockets.delete(socket));});
backend.on('upgrade',(req,socket)=>{
  const accept=createHash('sha1').update(req.headers['sec-websocket-key']+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+accept+'\r\n\r\n');
  socket.write(Buffer.from([0x81,0x02,0x6f,0x6b]));setTimeout(()=>socket.end(),50);
});
await new Promise(resolve=>backend.listen(19091,'127.0.0.1',resolve));
await new Promise(resolve=>secondary.listen(19092,'127.0.0.1',resolve));
try {
  let r=await request('/api/login',{method:'POST',body:{username:adminUsername,password,mode:'admin'}});assert.equal(r.status,200,JSON.stringify(r.json));
  let data=await admin('/api/me');csrf=data.csrf;assert.equal(data.user.role,'admin');check('admin login and secure host-only session');
  const cookie=r.headers['set-cookie'].join(';');assert(cookie.includes('Secure'));assert(cookie.includes('HttpOnly'));assert(cookie.includes('SameSite=Lax'));assert(!cookie.includes('Domain='));
  r=await request('/api/admin/services',{method:'POST',body:{},overrideHeaders:{Origin:'https://evil.invalid'}});assert.equal(r.status,403);check('cross-origin writes rejected');
  const created=await admin('/api/admin/services','POST',{appid:'gateway-e2e',name:'E2E 测试',host:hostname,upstream:'http://127.0.0.1:19091',enabled:true,allow_all:true,users:[],excluded_paths:['/healthz','/public/*']});id=created.id;
  secret=(await admin(`/api/admin/services/${id}/secret`,'POST',{})).secret;assert.equal(secret.length,64);check('service configuration persists and returns per-service secret');
  const secondHost='gateway-second.invalid';
  secondId=(await admin('/api/admin/services','POST',{appid:'gateway-second',name:'第二个后端',host:secondHost,upstream:'http://localhost:19092',enabled:true,allow_all:true,users:[],excluded_paths:['/']})).id;
  const secondSecret=(await admin(`/api/admin/services/${secondId}/secret`,'POST',{})).secret;assert.notEqual(secondSecret,secret);
  r=await request(`https://${secondHost}/`,{jar:false});assert.equal(r.status,200,r.text);assert.equal(r.json.backend,'secondary');
  const secondToken=r.json.headers['x-gateway-token'],parts=secondToken.split('.');
  assert(timingSafeEqual(createHmac('sha256',secondSecret).update(parts[0]+'.'+parts[1]).digest(),Buffer.from(parts[2],'base64url')));
  assert.equal(JSON.parse(Buffer.from(parts[1],'base64url')).aud,secondHost);assert.throws(()=>verify(secondToken,secondHost,'GET','/'));
  check('multiple domains select different backends and have isolated signing keys');
  r=await request(`https://${hostname}/healthz`,{jar:false,headers:{'X-Gateway-Token':'forged','X-Gateway-User':'attacker','X-Gateway-User-Info':'forged',Cookie:'app_cookie=kept; __Host-gateway_fake=removed'}});
  assert.equal(r.status,200,r.text);let claims=verify(r.json.headers['x-gateway-token']);assert.equal(claims.authenticated,false);assert.equal(claims.sub,'');assert.equal(r.json.headers['x-gateway-user'],'');
  assert(r.json.headers.cookie.startsWith('app_cookie=kept; __Host-gateway_binding=v1.'));assert.equal(r.json.headers['x-gateway-upstream'],undefined);check('public path gets signed anonymous token, spoofed headers and gateway session cookies removed');
  r=await request(`https://${hostname}/public/file.js`,{jar:false});assert.equal(r.status,200);check('prefix exemption');
  for(const path of ['/healthz-more','/publicity/file.js','/public/%2e%2e/private','/public//private','/public/../private']) {
    r=await request(`https://${hostname}${path}`,{jar:false});assert.equal(r.status,302,`${path}: ${r.status}`);
  }check('exemption boundaries and encoded traversal fail closed');
  r=await request(`https://${hostname}/private/path?x=1&y=two`);assert.equal(r.status,302);assert(r.headers.location.startsWith(origin+'/login?appid=gateway-e2e&token='));check('protected request redirects to unified login');
  const flowLogin=r.headers.location;assert(r.headers['set-cookie']);const loginRequest=new URL(flowLogin).searchParams.get('token');
  const requestClaims=JSON.parse(Buffer.from(loginRequest.split('.')[1],'base64url'));assert.equal(requestClaims.service_id,id);assert.equal(requestClaims.return_url,`https://${hostname}/private/path?x=1&y=two`);assert.equal(requestClaims.exp-requestClaims.iat,300);
  const metadata=await request('/api/public?request='+encodeURIComponent(loginRequest));assert.equal(metadata.status,200);assert.equal(metadata.json.service.host,hostname);assert.equal(metadata.json.services,undefined);
  const tokenParts=loginRequest.split('.');const altered={...requestClaims,return_url:'https://attacker.invalid/'};tokenParts[1]=Buffer.from(JSON.stringify(altered)).toString('base64url');
  r=await request('/api/public?request='+encodeURIComponent(tokenParts.join('.')));assert.equal(r.status,410);check('signed login URL binds service, return address and expiry; tampering rejected');
  r=await request(flowLogin);assert.equal(r.status,200);check('console login does not authorize business login');
  r=await request('/api/login',{method:'POST',body:{username:adminUsername,password,mode:'service',appid:'gateway-e2e',token:loginRequest}});assert.equal(r.status,200);const callback=r.json.redirect;
  const absentBinder=await request(callback,{jar:false});assert.equal(absentBinder.status,403);check('SSO callback requires original browser cookie');
  r=await request(callback);assert.equal(r.status,302,r.text);assert.equal(r.headers.location,'/private/path?x=1&y=two');
  const replay=await request(callback);assert.equal(replay.status,410);check('one-time cross-domain SSO and exact return URL');
  r=await request(`https://${hostname}/private/path?x=1&y=two`);assert.equal(r.status,200,r.text);claims=verify(r.json.headers['x-gateway-token'],hostname,'GET','/private/path?x=1&y=two');
  assert.equal(claims.authenticated,true);assert.equal(claims.username,adminUsername);assert.equal(claims.display_name,'管理员');assert.equal(r.json.url,'/private/path?x=1&y=two');assert(!r.json.headers.cookie?.includes('__Host-gateway_session'));assert(!r.json.headers.cookie?.includes('__Host-gateway_flow'));check('authenticated identity forwarded in verifiable JWT');
  r=await request(`https://${hostname}/post`,{method:'POST',body:{hello:'world'}});assert.equal(r.status,200,r.text);assert.equal(r.json.method,'POST');assert.deepEqual(JSON.parse(r.json.body),{hello:'world'});verify(r.json.headers['x-gateway-token'],hostname,'POST','/post');check('method, request body and query forwarding');
  r=await request(`https://${hostname}/post`,{method:'POST',body:{hello:'world'},jar:false});assert.equal(r.status,401);check('unauthenticated non-idempotent request does not silently lose its body');
  let firstAt=0;const t=performance.now();
  await new Promise((resolve,reject)=>{
    const req=https.request({hostname:'127.0.0.1',port:443,servername:'gateway.perfy576.com',path:'/events',headers:{Host:hostname,Cookie:cookiesFor(hostname)}},res=>{
      res.once('data',()=>{firstAt=performance.now()-t;});res.on('data',()=>{});res.on('end',resolve);
    });req.on('error',reject);req.end();
  });assert(firstAt<300,`SSE buffered for ${firstAt}ms`);check('SSE streaming reaches client before response completes');
  await new Promise((resolve,reject)=>{
    const req=https.request({hostname:'127.0.0.1',port:443,servername:'gateway.perfy576.com',path:'/ws',headers:{Host:hostname,Cookie:cookiesFor(hostname),Connection:'Upgrade',Upgrade:'websocket','Sec-WebSocket-Version':'13','Sec-WebSocket-Key':randomBytes(16).toString('base64')}},res=>reject(new Error('WebSocket failed: '+res.statusCode)));
    req.on('upgrade',(res,socket,head)=>{assert.equal(res.statusCode,101);socket.on('error',()=>{});socket.destroy();resolve();});req.on('error',reject);req.end();
  });check('WebSocket upgrade');
  const old=secret;secret=(await admin(`/api/admin/services/${id}/rotate`,'POST',{})).secret;assert.notEqual(secret,old);
  r=await request(`https://${hostname}/healthz`,{jar:false});verify(r.json.headers['x-gateway-token']);check('key rotation affects subsequent requests immediately');
  const benchStart=performance.now();let completed=0;
  await Promise.all(Array.from({length:20},async()=>{for(let i=0;i<50;i++){const response=await request(`https://${hostname}/healthz`,{jar:false});assert.equal(response.status,200);completed++;}}));
  const seconds=(performance.now()-benchStart)/1000;console.log(`SMOKE_THROUGHPUT ${completed} full TLS + auth + proxy requests in ${seconds.toFixed(2)}s (${Math.round(completed/seconds)} req/s)`);
  r=await request('/api/admin/state',{jar:false});assert.equal(r.status,401);check('admin data requires authentication');
  const username='e2e_'+randomBytes(4).toString('hex'),userPassword=randomBytes(16).toString('hex');
  await admin('/api/admin/users','POST',{username,display_name:'权限测试用户',password:userPassword,role:'user',enabled:true});
  otherUser=(await admin('/api/admin/state')).users.find(u=>u.username===username).id;
  const restricted={appid:'gateway-e2e',name:'E2E 测试',host:hostname,upstream:'http://127.0.0.1:19091',enabled:true,allow_all:false,users:[],excluded_paths:['/healthz','/public/*']};
  await admin(`/api/admin/services/${id}`,'PUT',restricted);
  jar.delete(hostname);r=await request(`https://${hostname}/member-only`);const memberRequest=new URL(r.headers.location).searchParams.get('token');
  r=await request('/api/login',{method:'POST',body:{username,password:userPassword,mode:'admin'}});assert.equal(r.status,403);
  r=await request('/api/login',{method:'POST',body:{username,password:userPassword,mode:'service',request:memberRequest}});assert.equal(r.status,403);
  check('ordinary users cannot log in to admin or access ungranted services');
  restricted.users=[otherUser];await admin(`/api/admin/services/${id}`,'PUT',restricted);
  r=await request('/api/login',{method:'POST',body:{username,password:userPassword,mode:'service',request:memberRequest}});assert.equal(r.status,200);
  r=await request(r.json.redirect);assert.equal(r.status,302);
  r=await request(`https://${hostname}/member-only`);assert.equal(r.status,200);assert.equal(verify(r.json.headers['x-gateway-token'],hostname,'GET','/member-only').sub,otherUser);
  r=await request('/api/admin/state');assert.equal(r.status,200);check('explicit business user grant preserves the independent console login');
  csrf=(await admin('/api/me')).csrf;const changedPassword=randomBytes(16).toString('hex');
  await admin(`/api/admin/users/${otherUser}`,'PUT',{username,display_name:'权限测试用户',password:changedPassword,role:'user',enabled:true});
  r=await request('/api/me');assert.equal(r.status,200);r=await request(`https://${hostname}/member-only`);assert.equal(r.status,302);
  r=await request('/api/login',{method:'POST',body:{username,password:userPassword,mode:'service',request:memberRequest}});assert.equal(r.status,401);
  check('password change invalidates every user session and rejects the old password');
  r=await request('/api/login',{method:'POST',body:{username:adminUsername,password,mode:'admin'}});assert.equal(r.status,200);csrf=(await admin('/api/me')).csrf;
  await admin(`/api/admin/users/${otherUser}`,'DELETE',{});otherUser='';
  await admin('/api/logout','POST',{});
  r=await request(`https://${hostname}/private`);assert.equal(r.status,302);check('global logout invalidates service sessions immediately');
  r=await request('/api/login',{method:'POST',body:{username:adminUsername,password,mode:'admin'}});assert.equal(r.status,200);csrf=(await admin('/api/me')).csrf;
  if(process.env.GATEWAY_TEST_RESTART==='1') {
    const restart=spawnSync('sudo',['-n','systemctl','restart','gateway'],{encoding:'utf8'});assert.equal(restart.status,0,restart.stderr);
    for(let i=0;i<30;i++){try{const health=await request('/healthz');if(health.status===200)break;}catch{}await new Promise(resolve=>setTimeout(resolve,200));}
    r=await request('/api/me');assert.equal(r.status,401);
    r=await request('/api/public?request='+encodeURIComponent(loginRequest));assert.equal(r.status,410);
    r=await request('/api/login',{method:'POST',body:{username:adminUsername,password,mode:'admin'}});assert.equal(r.status,200);csrf=(await admin('/api/me')).csrf;
    const persisted=(await admin('/api/admin/state')).services.find(s=>s.id===id);assert.equal(persisted.host,hostname);assert.deepEqual(persisted.excluded_paths,['/healthz','/public/*']);
    assert.equal((await admin(`/api/admin/services/${id}/secret`,'POST',{})).secret,secret);check('restart clears memory sessions and login requests while retaining MySQL service configuration and signing key');
  }
} finally {
  if(secondId){try{await admin(`/api/admin/services/${secondId}`,'DELETE',{});}catch(error){console.error('SECOND SERVICE CLEANUP',error.message);}}
  if(otherUser){try{await admin(`/api/admin/users/${otherUser}`,'DELETE',{});}catch(error){console.error('USER CLEANUP',error.message);}}
  if(id) {
    try {await admin(`/api/admin/services/${id}`,'DELETE',{});}catch(error){console.error('CLEANUP',error.message);}
  }
  for(const socket of sockets)socket.destroy();
  await new Promise(resolve=>backend.close(resolve));
  await new Promise(resolve=>secondary.close(resolve));
  writeFileSync('artifacts/integration-result.json',JSON.stringify({passed:result,date:new Date().toISOString()},null,2));
}
console.log(`Completed ${result.length} integration checks.`);
