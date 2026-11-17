import assert from 'node:assert/strict';
import {protectPasswordBody} from './password-envelope.mjs';
import http from 'node:http';
import {readFileSync} from 'node:fs';
import {randomBytes} from 'node:crypto';

const port=Number(process.env.GATEWAY_TEST_PORT||19090),host='gateway.perfy576.com',origin='https://'+host;
const record=readFileSync('.secrets/initial-admin.txt','utf8');
const username=record.match(/^Username: (.+)$/m)[1],password=record.match(/^Password: (.+)$/m)[1];
const admin={cookies:new Map(),csrf:''},ordinary={cookies:new Map(),csrf:''};
let original,consoleId,userId;
async function request(client,path,method='GET',body){
  body=await protectPasswordBody(path,method,body,async target=>(await request(client,target)).json);
  const payload=body===undefined?undefined:JSON.stringify(body);
  const headers={Host:host,Cookie:[...client.cookies].map(([k,v])=>k+'='+v).join('; ')};
  if(payload)Object.assign(headers,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(payload),Origin:origin,'X-Gateway-Request':'1','X-CSRF-Token':client.csrf});
  return new Promise((resolve,reject)=>{
    const req=http.request({hostname:'127.0.0.1',port,path,method,headers},res=>{
      let text='';res.on('data',part=>text+=part);res.on('end',()=>{
        for(const raw of res.headers['set-cookie']||[]){const pair=raw.split(';')[0],eq=pair.indexOf('=');client.cookies.set(pair.slice(0,eq),pair.slice(eq+1));}
        let json;try{json=JSON.parse(text);}catch{}
        resolve({status:res.statusCode,headers:res.headers,json});
      });
    });req.on('error',reject);req.setTimeout(15000,()=>req.destroy(new Error('Timeout')));req.end(payload);
  });
}
async function api(client,path,method='GET',body){const r=await request(client,path,method,body);assert.equal(r.status,200,'API failed: '+path);return r.json;}
try{
  for(let i=0;i<30;i++){
    try{if((await request(admin,'/healthz')).status===200)break;}catch{}
    if(i===29)throw new Error('Test gateway not ready');await new Promise(resolve=>setTimeout(resolve,200));
  }
  await api(admin,'/api/login','POST',{username,password,mode:'admin'});admin.csrf=(await api(admin,'/api/me')).csrf;
  let state=await api(admin,'/api/admin/state');const builtin=state.services.filter(s=>s.builtin);
  assert.equal(builtin.length,1);original=builtin[0];consoleId=original.id;
  assert.equal(original.appid,'gateway-console');assert.equal(original.host,host);assert.equal(original.enabled,true);
  const admins=state.users.filter(u=>u.role==='admin');for(const user of admins)assert(original.users.includes(user.id));
  assert.equal((await request(admin,'/api/admin/services/'+consoleId,'DELETE',{})).status,403);
  for(const op of ['secret','rotate'])assert.equal((await request(admin,'/api/admin/services/'+consoleId+'/'+op,'POST',{})).status,403);
  for(const changes of [{enabled:false},{host:'other.invalid'},{appid:'other-console'},{excluded_paths:['/*']},{users:[]}]){
    assert.equal((await request(admin,'/api/admin/services/'+consoleId,'PUT',{...original,...changes})).status,400);
  }
  assert.equal((await api(admin,'/api/me')).user.role,'admin');
  console.log('PASS built-in console persists as a protected service; delete/disable/reroute/key access and admin permission removal are rejected');

  const user='test_console_'+randomBytes(4).toString('hex'),pass=randomBytes(18).toString('hex');
  await api(admin,'/api/admin/users','POST',{username:user,display_name:'Console test (temporary)',password:pass,role:'user',enabled:true});
  userId=(await api(admin,'/api/admin/state')).users.find(u=>u.username===user).id;
  assert.equal((await request(ordinary,'/api/login','POST',{username:user,password:pass,mode:'admin'})).status,403);
  const granted={...original,cookie_max_age_hours:0.5,users:[...new Set([...original.users,userId])]};
  await api(admin,'/api/admin/services/'+consoleId,'PUT',granted);
  const login=await request(ordinary,'/api/login','POST',{username:user,password:pass,mode:'admin'});assert.equal(login.status,200);
  assert(login.headers['set-cookie'].some(c=>c.startsWith('__Host-gateway_session=')&&c.includes('Max-Age=1800')));
  const me=await api(ordinary,'/api/me');ordinary.csrf=me.csrf;assert.equal(me.user.role,'user');
  assert.equal((await request(ordinary,'/api/admin/state')).status,403);
  assert.equal((await request(ordinary,'/api/admin/users','POST',{username:'forbidden',role:'admin'})).status,403);
  console.log('PASS explicitly granted ordinary users can log into the console, while administrative APIs remain forbidden');

  await api(admin,'/api/admin/services/'+consoleId,'PUT',{...granted,cookie_max_age_hours:0});
  const refreshed=await request(ordinary,'/api/me');assert.equal(refreshed.status,200);
  assert(refreshed.headers['set-cookie'].some(c=>c.startsWith('__Host-gateway_session=')&&c.includes('Max-Age=34560000')));
  state=await api(admin,'/api/admin/state');let session=state.sessions.find(s=>s.user_id===userId);
  assert(session&&session.online&&session.expires_at===0&&session.service_id===consoleId&&session.appid==='gateway-console');
  assert.equal(state.metrics.valid_sessions,state.sessions.length);assert.equal(state.metrics.online_sessions,state.sessions.filter(s=>s.online).length);
  console.log('Waiting 61 seconds without requests from the ordinary user to verify offline-but-valid status');
  await new Promise(resolve=>setTimeout(resolve,61000));
  state=await api(admin,'/api/admin/state');session=state.sessions.find(s=>s.user_id===userId);
  assert(session&&!session.online&&session.expires_at===0,'Idle cookie must remain valid but become offline');
  assert.equal((await request(ordinary,'/api/me')).status,200);
  state=await api(admin,'/api/admin/state');session=state.sessions.find(s=>s.user_id===userId);assert(session.online);
  console.log('PASS console cookie lifetime, online/valid counts, one-minute idle transition and request-driven return online');

  await api(admin,'/api/admin/services/'+consoleId,'PUT',original);
  assert.equal((await request(ordinary,'/api/me')).status,401);assert.equal((await api(admin,'/api/me')).user.role,'admin');
  console.log('PASS revoking a console user invalidates their console session without removing administrator access');
}finally{
  if(original)await api(admin,'/api/admin/services/'+consoleId,'PUT',original);
  if(userId)await api(admin,'/api/admin/users/'+userId,'DELETE',{});
}
