import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import {readFileSync} from 'node:fs';
import {spawn} from 'node:child_process';
import {createHash,createHmac} from 'node:crypto';

const origin='https://gateway.perfy576.com',host='gateway-sdk-e2e.invalid',sdk='/data/code/gateway-sdk';
const credentialRecord=readFileSync('.secrets/initial-admin.txt','utf8');
const adminUsername=credentialRecord.match(/^Username: (.+)$/m)[1];
const password=credentialRecord.match(/^Password: (.+)$/m)[1];
const jars=new Map();let csrf='',id='',secret='',verificationKey='';
const sockets=new Set();const backend=http.createServer((req,res)=>{res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({headers:req.headers,url:req.url}));});
backend.on('connection',socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));});
await new Promise(resolve=>backend.listen(19093,'127.0.0.1',resolve));
function request(url,options={}){
  const u=new URL(url,origin),headers={Host:u.hostname,...options.headers};
  if(options.jar!==false)headers.Cookie=[...(jars.get(u.hostname)||new Map())].map(([k,v])=>k+'='+v).join('; ');
  let body;
  if(options.body!==undefined){body=JSON.stringify(options.body);Object.assign(headers,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body),'X-Gateway-Request':'1','X-CSRF-Token':csrf,Origin:origin});}
  return new Promise((resolve,reject)=>{
    const req=https.request({hostname:'127.0.0.1',port:443,servername:'gateway.perfy576.com',path:u.pathname+u.search,method:options.method||'GET',headers},res=>{
      const chunks=[];res.on('data',c=>chunks.push(c));res.on('end',()=>{
        if(options.jar!==false)for(const raw of res.headers['set-cookie']||[]){const pair=raw.split(';')[0],eq=pair.indexOf('='),key=pair.slice(0,eq),value=pair.slice(eq+1);if(!jars.has(u.hostname))jars.set(u.hostname,new Map());if(value)jars.get(u.hostname).set(key,value);else jars.get(u.hostname).delete(key);}
        const text=Buffer.concat(chunks).toString();let json;try{json=JSON.parse(text);}catch{}resolve({status:res.statusCode,headers:res.headers,json,text});
      });
    });req.on('error',reject);req.setTimeout(10000,()=>req.destroy(new Error('timeout')));req.end(body);
  });
}
async function api(path,method='GET',body){const r=await request(path,{method,body});assert.equal(r.status,200,JSON.stringify(r.json));return r.json;}
async function sdkVerify(language,input,code=0){
  const executable=language==='python'?sdk+'/.venv/bin/python':sdk+'/build/gateway-sdk-verify';
  const args=language==='python'?[sdk+'/python3-sdk/examples/verify.py']:[];
  return new Promise((resolve,reject)=>{
    const child=spawn(executable,args,{env:{...process.env,GATEWAY_TOKEN_SECRET:secret,GATEWAY_VERIFICATION_KEY:verificationKey},stdio:['pipe','pipe','pipe']});
    let stdout='',stderr='';child.stdout.on('data',c=>stdout+=c);child.stderr.on('data',c=>stderr+=c);child.on('error',reject);child.on('close',status=>{
      try{assert.equal(status,code,`${language} expected ${code}, got ${status}: ${stderr}`);resolve(stdout?JSON.parse(stdout):null);}catch(error){reject(error);}
    });child.stdin.end(JSON.stringify(input));
  });
}
function input(response,path,mode='local'){return {issuer:origin,audience:host,token:response.json.headers['x-gateway-token'],cookie:response.json.headers.cookie,method:'GET',uri:path,mode};}
function sign(claims,version=1,key=secret){const header=Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT',gwv:version})).toString('base64url');const payload=Buffer.from(JSON.stringify(claims)).toString('base64url');const data=header+'.'+payload;return data+'.'+createHmac('sha256',key).update(data).digest('base64url');}
async function online(data,key=verificationKey){return request('/verify',{method:'POST',jar:false,headers:{Authorization:'Bearer '+key},body:{audience:data.audience,token:data.token,cookie:data.cookie,method:data.method,uri:data.uri}});}
async function completeBusinessLogin(loginUrl){
  const page=await request(loginUrl);assert.equal(page.status,200);
  const token=new URL(loginUrl).searchParams.get('token');
  const result=await api('/api/login','POST',{username:adminUsername,password,mode:'service',appid:'gateway-sdk-e2e',token});
  const callback=await request(result.redirect);assert.equal(callback.status,302);return callback;
}
try{
  await api('/api/login','POST',{username:adminUsername,password,mode:'admin'});csrf=(await api('/api/me')).csrf;
  id=(await api('/api/admin/services','POST',{appid:'gateway-sdk-e2e',name:'SDK integration',host,upstream:'http://127.0.0.1:19093',enabled:true,allow_all:true,users:[],excluded_paths:['/public/*']})).id;
  const credentials=await api(`/api/admin/services/${id}/secret`,'POST',{});secret=credentials.secret;verificationKey=credentials.verification_key;
  assert.notEqual(secret,verificationKey);assert.equal(credentials.token_version,1);assert.equal(credentials.cookie_version,1);
  assert.equal(verificationKey,createHmac('sha256',secret).update('gateway/verify-api/v1').digest('hex'));
  assert.match(jars.get('gateway.perfy576.com').get('__Host-gateway_session'),/^v1\.[0-9a-f]{64}$/);
  let r=await request(`https://${host}/public/ready`);assert.equal(r.status,200,r.text);
  assert(r.headers['set-cookie']?.some(c=>c.startsWith('__Host-gateway_binding=v1.')));assert(jars.get(host).has('__Host-gateway_binding'));
  const anonymous=input(r,'/public/ready');const claims=JSON.parse(Buffer.from(anonymous.token.split('.')[1],'base64url'));
  assert.equal(claims.ver,1);assert.equal(claims.cookie_version,1);assert.equal(claims.type,'gateway_access');
  assert.equal(claims.cookie_sha256,createHash('sha256').update(jars.get(host).get('__Host-gateway_binding')).digest('hex'));
  assert(!anonymous.cookie.includes('__Host-gateway_session'));assert.equal(r.json.headers['x-gateway-set-cookie'],undefined);
  for(const lang of ['python','cpp']){
    assert.equal((await sdkVerify(lang,anonymous)).verification,'local');
    assert.equal((await sdkVerify(lang,{...anonymous,mode:'online'})).verification,'online');
    await sdkVerify(lang,{...anonymous,require_authenticated:true},2);
    for(const change of [{cookie:''},{cookie:anonymous.cookie+'; '+anonymous.cookie},{cookie:'__Host-gateway_binding=v1.'+'0'.repeat(64)},{method:'POST'},{uri:'/other'}]){
      await sdkVerify(lang,{...anonymous,...change},2);
      await sdkVerify(lang,{...anonymous,...change,mode:'online'},2);
    }
    const invalid=sign({...claims,username:'attacker'},1,'f'.repeat(64));
    await sdkVerify(lang,{...anonymous,token:invalid,mode:'auto',verify_url:'https://127.0.0.1:1/verify'},2);
    const future=sign({...claims,ver:2},2);await sdkVerify(lang,{...anonymous,token:future},4);
    await sdkVerify(lang,{...anonymous,token:future,mode:'auto'},2);
    await sdkVerify(lang,{...anonymous,token:future,mode:'auto',verify_url:'https://127.0.0.1:1/verify',timeout_ms:100},3);
    await sdkVerify(lang,{...anonymous,mode:'online',verify_url:'https://127.0.0.1:1/verify',timeout_ms:100},3);
  }
  assert.equal((await online(anonymous,'wrong')).status,401);assert.equal((await online(anonymous,secret)).status,401);
  assert.equal((await online({...anonymous,audience:'another.invalid'})).status,401);
  console.log('PASS Python/C++ local and online verification, versioned anonymous cookie, tamper/binding/duplicate/method/path rejection, opt-in unknown-version fallback, HTTPS failures fail closed and independent API authentication');
  const loginKey=createHmac('sha256',secret).update('gateway/sdk-login/v1').digest('hex');
  for(const language of ['python','cpp']){
    jars.delete(host);
    const raw={operation:'checkCookie',gateway_host:origin,audience:host,appid:'gateway-sdk-e2e',token:'',cookie:'',method:'GET',uri:'/sdk-return?x=1&next=%2Fdocs'};
    const failure=await sdkVerify(language,raw);
    assert.equal(failure.result,'redictionToLogin');assert.equal(failure.allowed,false);assert.equal(failure.status,302);
    assert.match(failure.error,/^cookie_empty:/);assert.equal(failure.headers.Location,failure.redictUrl);
    const disabled=await sdkVerify(language,{...raw,redirect_on_failure:false});
    assert.equal(disabled.result,'redictionToLogin');assert.equal(disabled.status,401);assert.equal(disabled.headers.Location,undefined);assert(disabled.redictUrl);
    const bootstrap=new URL(failure.redictUrl).searchParams.get('token'),parts=bootstrap.split('.');
    assert.equal(parts[2],createHmac('sha256',loginKey).update(parts[0]+'.'+parts[1]).digest('base64url'));
    const negotiated=JSON.parse(Buffer.from(parts[1],'base64url'));
    assert.equal(negotiated.sdk_version,'1.2.0');assert.deepEqual(negotiated.token_versions,[1]);assert.deepEqual(negotiated.cookie_versions,[1]);
    assert.equal(negotiated.return_url,`https://${host}${raw.uri}`);assert.equal(negotiated.exp-negotiated.iat,300);
    const changed={...negotiated,return_url:'https://attacker.invalid/'};
    const tampered=parts[0]+'.'+Buffer.from(JSON.stringify(changed)).toString('base64url')+'.'+parts[2];
    assert.equal((await request('/login?appid=gateway-sdk-e2e&token='+tampered)).status,400);
    assert.equal((await request('/login?appid=gateway-sdk-e2e&token='+sign(changed,1,loginKey))).status,400);
    assert.equal((await request('/login?appid=gateway-sdk-e2e&token='+sign({...negotiated,exp:negotiated.iat-1},1,loginKey))).status,400);
    const future={...negotiated,token_versions:[2],cookie_versions:[2],allow_verify:false};
    assert.equal((await request('/login?appid=gateway-sdk-e2e&token='+sign(future,1,loginKey))).status,426);
    let flow=await request(failure.redictUrl);assert.equal(flow.status,302);assert.equal(new URL(flow.headers.location).hostname,host);
    flow=await request(flow.headers.location);assert.equal(flow.status,302);const loginPage=flow.headers.location;
    const metadata=await api('/api/public?request='+encodeURIComponent(new URL(loginPage).searchParams.get('token')));
    assert.equal(metadata.sdk_version,'1.2.0');assert.equal(metadata.token_version,1);assert.equal(metadata.cookie_version,1);assert.equal(metadata.online_only,false);
    flow=await completeBusinessLogin(loginPage);assert.equal(flow.headers.location,raw.uri);
    flow=await request(`https://${host}${raw.uri}`);assert.equal(flow.status,200,flow.text);
    const valid=await sdkVerify(language,{...input(flow,raw.uri),operation:'checkCookie',gateway_host:origin,appid:'gateway-sdk-e2e'});
    assert.equal(valid.result,'Ok');assert.equal(valid.allowed,true);assert.equal(valid.error,'');assert.equal(valid.redictUrl,'');assert.equal(valid.claims.client_sdk_version,'1.2.0');
    jars.delete(host);
    flow=await request('/login?appid=gateway-sdk-e2e&token='+sign({...future,allow_verify:true},1,loginKey));assert.equal(flow.status,302);
    flow=await request(flow.headers.location);assert.equal(flow.status,302);
    const onlineMetadata=await api('/api/public?request='+encodeURIComponent(new URL(flow.headers.location).searchParams.get('token')));assert.equal(onlineMetadata.online_only,true);
    flow=await completeBusinessLogin(flow.headers.location);
    flow=await request(`https://${host}${raw.uri}`);assert.equal(flow.status,200,flow.text);
    const onlineInput={...input(flow,raw.uri),operation:'checkCookie',gateway_host:origin,appid:'gateway-sdk-e2e'};
    const unsupported=await sdkVerify(language,{...onlineInput,redirect_on_failure:false});
    assert.equal(unsupported.result,'redictionToLogin');assert.match(unsupported.error,/^unsupported_version:/);assert(unsupported.redictUrl);
    const allowed=await sdkVerify(language,{...onlineInput,allow_online_fallback:true});assert.equal(allowed.result,'Ok');assert.equal(allowed.claims.online_only,true);
  }
  console.log('PASS Python/C++ checkCookie two-result contract, signed login URLs, opt-in 302, tamper/expiry/open redirect rejection, browser-bound return and protocol negotiation with online fallback');
  jars.delete(host);
  r=await request(`https://${host}/private?x=1`);assert.equal(r.status,302);
  const login=r.headers.location,loginToken=new URL(login).searchParams.get('token');
  const loginClaims=JSON.parse(Buffer.from(loginToken.split('.')[1],'base64url'));assert.equal(loginClaims.ver,1);
  r=await completeBusinessLogin(login);
  r=await request(`https://${host}/private?x=1`);assert.equal(r.status,200,r.text);const authenticated=input(r,'/private?x=1');
  for(const lang of ['python','cpp'])for(const mode of ['local','online']){
    const verified=await sdkVerify(lang,{...authenticated,mode,require_authenticated:true});assert.equal(verified.claims.username,adminUsername);assert.equal(verified.claims.authenticated,true);
  }
  const invalidVersion=sign({...JSON.parse(Buffer.from(authenticated.token.split('.')[1],'base64url')),cookie_version:2});
  for(const lang of ['python','cpp']){await sdkVerify(lang,{...authenticated,token:invalidVersion},4);await sdkVerify(lang,{...authenticated,token:invalidVersion,mode:'auto'},2);}
  const savedSession=jars.get(host).get('__Host-gateway_session'),savedBinding=jars.get(host).get('__Host-gateway_binding');
  jars.get(host).set('__Host-gateway_binding','v1.'+'0'.repeat(64));r=await request(`https://${host}/private?x=1`);assert.equal(r.status,302);jars.get(host).set('__Host-gateway_binding',savedBinding);
  jars.get(host).set('__Host-gateway_session',savedSession.replace(/^v1\./,'v2.'));r=await request(`https://${host}/private?x=1`);assert.equal(r.status,302);jars.get(host).set('__Host-gateway_session',savedSession);
  await api('/api/logout','POST',{});
  assert.equal((await online(authenticated)).status,401);
  for(const lang of ['python','cpp']){await sdkVerify(lang,{...authenticated,mode:'online'},2);assert.equal((await sdkVerify(lang,authenticated)).verification,'local');}
  console.log('PASS authenticated SDK identity, versioned login/session cookies, session-binding mismatch and unsupported session version rejected; online mode detects logout immediately while local token retains its short lifetime');
  await api('/api/login','POST',{username:adminUsername,password,mode:'admin'});csrf=(await api('/api/me')).csrf;
  const oldKey=verificationKey;await api(`/api/admin/services/${id}/rotate`,'POST',{});
  assert.equal((await online(anonymous,oldKey)).status,401);
  console.log('PASS key rotation revokes old online verification credentials');
}finally{
  if(id)await api('/api/admin/services/'+id,'DELETE',{}).catch(e=>console.error('CLEANUP',e.message));
  for(const socket of sockets)socket.destroy();await new Promise(resolve=>backend.close(resolve));
}
