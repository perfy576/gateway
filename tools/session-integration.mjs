import assert from 'node:assert/strict';
import {protectPasswordBody} from './password-envelope.mjs';
import http from 'node:http';
import {readFileSync} from 'node:fs';
import {randomBytes, createHmac} from 'node:crypto';

const port=Number(process.env.GATEWAY_TEST_PORT || 19090);
const gateway='gateway.perfy576.com', origin='https://'+gateway;
const credentials=readFileSync('.secrets/initial-admin.txt','utf8');
const username=credentials.match(/^Username: (.+)$/m)[1],password=credentials.match(/^Password: (.+)$/m)[1];
const suffix=randomBytes(4).toString('hex'),jars=new Map();
let csrf='',userId='';const ids=[];
const configs=[
  {appid:'session-a-'+suffix,name:'Session A',host:'session-a-'+suffix+'.invalid',upstream:'http://127.0.0.1:19091',cookie_max_age_hours:0.5,enabled:true,allow_all:true,users:[],excluded_paths:[]},
  {appid:'session-b-'+suffix,name:'Session B',host:'session-b-'+suffix+'.invalid',upstream:'http://127.0.0.1:19091',cookie_max_age_hours:0,enabled:true,allow_all:true,users:[],excluded_paths:[]}
];
const cookieFor=host=>[...(jars.get(host)||new Map())].map(([k,v])=>k+'='+v).join('; ');
async function request(path,{host=gateway,method='GET',body,headers={}}={}){
  body=await protectPasswordBody(path,method,body,async target=>(await request(target)).json);
  const payload=body===undefined?undefined:JSON.stringify(body);
  const requestHeaders={Host:host,Cookie:cookieFor(host),...headers};
  if(payload)Object.assign(requestHeaders,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(payload),Origin:origin,'X-Gateway-Request':'1','X-CSRF-Token':csrf});
  return new Promise((resolve,reject)=>{
    const req=http.request({hostname:'127.0.0.1',port,path,method,headers:requestHeaders},res=>{
      let text='';res.on('data',part=>text+=part);res.on('end',()=>{
        for(const raw of res.headers['set-cookie']||[]){const pair=raw.split(';')[0],eq=pair.indexOf('=');if(!jars.has(host))jars.set(host,new Map());jars.get(host).set(pair.slice(0,eq),pair.slice(eq+1));}
        let json;try{json=JSON.parse(text);}catch{}
        resolve({status:res.statusCode,headers:res.headers,json});
      });
    });req.on('error',reject);req.setTimeout(15000,()=>req.destroy(new Error('Timeout')));req.end(payload);
  });
}
async function api(path,method='GET',body){const r=await request(path,{method,body});assert.equal(r.status,200,`API ${path} failed (${r.status})`);return r.json;}
const auth=(config,headers={})=>request('/internal/auth',{host:config.host,headers:{'X-Forwarded-Host':config.host,'X-Forwarded-Uri':'/private?x=1','X-Forwarded-Method':'GET',...headers}});
async function flow(config){const response=await auth(config);assert.equal(response.status,302);return new URL(response.headers.location);}
async function browserLogin(config,login,user=username,pass=password){
  const response=await request('/api/login',{method:'POST',body:{username:user,password:pass,mode:'service',appid:config.appid,token:login.searchParams.get('token')}});
  if(response.status!==200)return response;
  assert.equal(response.headers['set-cookie'],undefined,'Business login must not issue a console cookie');
  const callback=new URL(response.json.redirect);assert.equal(callback.host,config.host);
  const result=await request(callback.pathname+callback.search,{host:config.host});assert.equal(result.status,302);
  return result;
}
function loginToken(config,secret){
  const t=Math.floor(Date.now()/1000),header=Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT',gwv:1})).toString('base64url');
  const payload=Buffer.from(JSON.stringify({iss:config.host,aud:origin+'/login',appid:config.appid,return_url:'https://'+config.host+'/private',iat:t,nbf:t-2,exp:t+300,jti:randomBytes(32).toString('hex'),ver:1,type:'sdk_login',sdk_version:'1.2.0',token_versions:[1],cookie_versions:[1],allow_verify:false})).toString('base64url');
  const key=createHmac('sha256',secret).update('gateway/sdk-login/v1').digest('hex'),data=header+'.'+payload;
  return data+'.'+createHmac('sha256',key).update(data).digest('base64url');
}
try{
  for(let attempt=0;attempt<30;attempt++){
    try{if((await request('/healthz')).status===200)break;}catch{}
    if(attempt===29)throw new Error('Test gateway did not become ready');
    await new Promise(resolve=>setTimeout(resolve,200));
  }
  await api('/api/login','POST',{username,password,mode:'admin'});const me=await api('/api/me');csrf=me.csrf;
  const metrics=async()=>(await api('/api/admin/state')).metrics;
  async function checkCounts(before, {loginSuccess=0,loginFailure=0,verificationSuccess=0,verificationFailure=0}={}) {
    const after=await metrics();
    assert.equal(after.login_success-before.login_success,loginSuccess);
    assert.equal(after.login_failure-before.login_failure,loginFailure);
    // Reading admin state itself performs a successful Cookie check.
    assert.equal(after.verification_success-before.verification_success,verificationSuccess+1);
    assert.equal(after.verification_failure-before.verification_failure,verificationFailure);
    assert.equal(after.login_requests,after.login_success+after.login_failure);
    assert.equal(after.verification_requests,after.verification_success+after.verification_failure);
    return after;
  }
  let counts=await metrics();
  assert(counts.login_success>=1,'Console sign-in must count as a successful login');
  assert.equal((await request('/api/login',{method:'POST',body:{}})).status,400);
  counts=await checkCounts(counts,{loginFailure:1});
  assert.equal((await request('/api/me',{headers:{Cookie:'__Host-gateway_session=invalid'}})).status,401);
  await checkCounts(counts,{verificationFailure:1});
  for(const config of configs)ids.push((await api('/api/admin/services','POST',config)).id);
  const a=configs[0],b=configs[1];
  for(const value of [-1,'12',true,876001]){
    const response=await request('/api/admin/services/'+ids[0],{method:'PUT',body:{...a,cookie_max_age_hours:value}});assert.equal(response.status,400);
  }
  const loginA=await flow(a),consoleCookies=cookieFor(gateway);
  assert.equal((await request(loginA.pathname+loginA.search)).status,200,'Console login must not authorize a business');
  const authorize=await request('/authorize'+loginA.search);assert.equal(authorize.status,302);assert.equal(new URL(authorize.headers.location).pathname,'/login');
  assert.equal((await auth(a,{Cookie:consoleCookies})).status,302,'Console cookie copied to a business must fail');
  counts=await metrics();
  const signedInA=await browserLogin(a,loginA);assert.equal(signedInA.status,302);
  await checkCounts(counts,{loginSuccess:1});
  console.log('PASS login and Cookie checks are counted independently; callback is not counted twice');
  assert(signedInA.headers['set-cookie'].filter(c=>/gateway_(session|binding)=/.test(c)).every(c=>c.includes('Max-Age=1800')));
  assert(cookieFor(gateway)===consoleCookies,'Business login replaced the console cookies');assert.equal((await api('/api/me')).user.id,me.user.id);
  assert.equal((await auth(a)).status,200);assert.equal((await auth(b,{Cookie:cookieFor(a.host)})).status,302);
  const loginB=await flow(b);assert.equal((await request(loginB.pathname+loginB.search)).status,200);
  await browserLogin(b,loginB);assert.equal((await auth(b)).status,200);
  let sessions=(await api('/api/admin/state')).sessions;
  assert(sessions.some(s=>s.scope==='admin'&&s.appid==='gateway-console'));
  assert(sessions.some(s=>s.appid===a.appid&&s.host===a.host&&s.expires_at-s.created_at===1800));
  assert(sessions.some(s=>s.appid===b.appid&&s.expires_at===0));
  console.log('PASS isolated console/business logins, cross-business cookie rejection, fractional hours and unlimited session metadata');

  a.cookie_max_age_hours=0;await api('/api/admin/services/'+ids[0],'PUT',a);
  let refreshed=await auth(a);assert.equal(refreshed.status,200);
  assert(refreshed.headers['x-gateway-set-session-cookie'].includes('Max-Age=34560000'));
  assert(refreshed.headers['x-gateway-set-cookie'].includes('Max-Age=34560000'));
  a.cookie_max_age_hours=0.5;await api('/api/admin/services/'+ids[0],'PUT',a);
  refreshed=await auth(a);assert.equal(refreshed.status,200);
  assert(/Max-Age=\d+/.test(refreshed.headers['x-gateway-set-session-cookie']));
  assert(!refreshed.headers['x-gateway-set-session-cookie'].includes('Max-Age=34560000'));
  console.log('PASS live cookie lifetime changes refresh both cookies without extending the login start time');

  const ordinary='session_user_'+suffix,ordinaryPassword=randomBytes(18).toString('hex');
  await api('/api/admin/users','POST',{username:ordinary,display_name:'Session test',password:ordinaryPassword,role:'user',enabled:true});
  userId=(await api('/api/admin/state')).users.find(u=>u.username===ordinary).id;
  a.allow_all=false;a.users=[userId];await api('/api/admin/services/'+ids[0],'PUT',a);
  assert.equal((await auth(a)).status,302,'Removing permission must revoke the existing admin business session');
  const deniedFlow=await flow(a);assert.equal((await browserLogin(a,deniedFlow)).status,403,'Admin role must not bypass a business allowlist');
  const credentialsA=await api('/api/admin/services/'+ids[0]+'/secret','POST',{});
  const deniedApp=await request('/login',{method:'POST',body:{username,passwd:password,appid:a.appid,token:loginToken(a,credentialsA.secret)}});
  assert.equal(deniedApp.status,403,'App login must enforce the business allowlist');assert.equal(deniedApp.json.cookie,'');
  assert.equal((await browserLogin(a,deniedFlow,ordinary,ordinaryPassword)).status,302);
  const userAuth=await auth(a);assert.equal(userAuth.status,200);assert.equal(userAuth.headers['x-gateway-user'],ordinary);
  const online=()=>request('/verify',{method:'POST',headers:{Authorization:'Bearer '+credentialsA.verification_key},body:{audience:a.host,token:userAuth.headers['x-gateway-token'],cookie:userAuth.headers['x-gateway-cookie'],method:'GET',uri:'/private?x=1'}});
  assert.equal((await online()).status,200);
  a.users=[];await api('/api/admin/services/'+ids[0],'PUT',a);
  assert.equal((await auth(a)).status,302);assert.equal((await online()).status,401);assert.equal((await auth(b)).status,200);
  console.log('PASS browser/app/online verification enforce user grants, including admin accounts; revoked grants invalidate only the affected business');

  sessions=(await api('/api/admin/state')).sessions;const bSession=sessions.find(s=>s.appid===b.appid);
  await api('/api/admin/sessions/'+bSession.id,'DELETE',{});
  assert.equal((await auth(b)).status,302);assert.equal((await api('/api/me')).user.id,me.user.id);
  console.log('PASS single-session revocation preserves the console session');

  a.allow_all=true;a.cookie_max_age_hours=3/3600;await api('/api/admin/services/'+ids[0],'PUT',a);
  await browserLogin(a,await flow(a));let short=await auth(a);assert.equal(short.status,200);
  const claims=JSON.parse(Buffer.from(short.headers['x-gateway-token'].split('.')[1],'base64url'));
  assert(claims.exp-claims.iat>0&&claims.exp-claims.iat<=3,'Access tokens must not outlive a finite business session');
  await new Promise(resolve=>setTimeout(resolve,4000));assert.equal((await auth(a)).status,302);
  console.log('PASS sub-hour expiry is enforced by the gateway and access tokens');
}finally{
  for(const id of ids)await api('/api/admin/services/'+id,'DELETE',{});
  if(userId)await api('/api/admin/users/'+userId,'DELETE',{});
}
