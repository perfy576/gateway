import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import {readFileSync,mkdtempSync,rmSync,mkdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes,createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {spawnSync} from 'node:child_process';

const require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_MODULE || '/home/ubuntu/.npm/_npx/e41f203b7505f1fb/node_modules/playwright');
const port=Number(process.env.GATEWAY_TEST_PORT || 19090),tlsPort=Number(process.env.GATEWAY_TEST_TLS_PORT || 19445);
const gateway='gateway.perfy576.com',origin='https://'+gateway;
const record=readFileSync('.secrets/initial-admin.txt','utf8');
const username=record.match(/^Username: (.+)$/m)[1],password=record.match(/^Password: (.+)$/m)[1];
const suffix=randomBytes(4).toString('hex'),host='quick-login-'+suffix+'.invalid';
const ordinary='quick_user_'+suffix,ordinaryPassword=randomBytes(18).toString('hex');
const config={appid:'quick-login-'+suffix,name:'Quick login test',host,upstream:'http://127.0.0.1:19091',enabled:true,allow_all:true,users:[],excluded_paths:[]};
const jars=new Map(),sockets=new Set(),errors=[];
let csrf='',serviceId,userId,browser,relay,tlsDir;
const cookieFor=(jar,domain)=>[...(jar?.get(domain)||new Map())].map(([k,v])=>k+'='+v).join('; ');
async function request(path,{host:domain=gateway,method='GET',body,headers={},jar=jars,csrfToken=csrf}={}) {
  const encoded=body===undefined?undefined:Buffer.isBuffer(body)?body:Buffer.from(JSON.stringify(body));
  const requestHeaders={Host:domain,Cookie:cookieFor(jar,domain)};
  if(encoded)Object.assign(requestHeaders,{'Content-Type':'application/json','Content-Length':encoded.length,Origin:origin,'X-Gateway-Request':'1','X-CSRF-Token':csrfToken});
  Object.assign(requestHeaders,headers);
  return new Promise((resolve,reject)=>{
    const req=http.request({hostname:'127.0.0.1',port,path,method,headers:requestHeaders},res=>{
      const chunks=[];res.on('data',part=>chunks.push(part));res.on('end',()=>{
        if(jar)for(const raw of res.headers['set-cookie']||[]){
          const pair=raw.split(';')[0],eq=pair.indexOf('=');
          if(!jar.has(domain))jar.set(domain,new Map());
          if(/Max-Age=0(?:;|$)/i.test(raw))jar.get(domain).delete(pair.slice(0,eq));
          else jar.get(domain).set(pair.slice(0,eq),pair.slice(eq+1));
        }
        const data=Buffer.concat(chunks);let json;try{json=JSON.parse(data.toString());}catch{}
        resolve({status:res.statusCode,headers:res.headers,body:data,json});
      });
    });req.on('error',reject);req.setTimeout(15000,()=>req.destroy(new Error('Timeout')));req.end(encoded);
  });
}
async function api(path,method='GET',body) {
  const response=await request(path,{method,body});
  assert.equal(response.status,200,response.json?.error || path);return response.json;
}
const auth=(options={})=>request('/internal/auth',{host,headers:{'X-Forwarded-Host':host,'X-Forwarded-Uri':'/private?x=1','X-Forwarded-Method':'GET'},...options});
async function flow() {
  jars.delete(host);const response=await auth();assert.equal(response.status,302);return new URL(response.headers.location);
}
const payload=login=>({token:login.searchParams.get('token'),appid:config.appid});
const quick=(login,options={})=>request('/api/login/quick',{method:'POST',body:payload(login),...options});
const publicInfo=(login,options={})=>request('/api/public'+login.search,options);
async function consume(response) {
  assert.equal(response.status,200,response.json?.error);
  const target=new URL(response.json.redirect);
  assert.equal(target.hostname,host);
  const result=await request(target.pathname+target.search,{host});assert.equal(result.status,302);
  assert.equal(result.headers.location,'/private?x=1');return target;
}
async function browserContext(withConsole=true) {
  const context=await browser.newContext({locale:'zh-CN',ignoreHTTPSErrors:true});
  context.setDefaultTimeout(15000);
  if(withConsole)await context.addCookies([...jars.get(gateway)].map(([name,value])=>({name,value,url:origin,secure:true,httpOnly:true,sameSite:'Lax'})));
  const page=await context.newPage();page.on('pageerror',error=>errors.push(error.message));
  return {context,page};
}
async function screenshot(page,label,width,height) {
  await page.setViewportSize({width,height});
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'Horizontal overflow');
  const overlaps=await page.evaluate(()=>{
    const elements=[...document.querySelectorAll('.quick-account,#quick-login-button,#switch-account,#login-form .field,#login-form>.primary,#use-current-account')]
      .filter(node=>node.getClientRects().length).map(node=>node.getBoundingClientRect());
    return elements.some((a,i)=>elements.slice(i+1).some(b=>Math.min(a.right,b.right)>Math.max(a.left,b.left)&&Math.min(a.bottom,b.bottom)>Math.max(a.top,b.top)));
  });
  assert.equal(overlaps,false,'Login controls overlap');
  await page.screenshot({path:'artifacts/quick-login-'+label+'.png',fullPage:true});
}
try {
  await api('/api/login','POST',{username,password,mode:'admin'});csrf=(await api('/api/me')).csrf;
  const consoleCookies=cookieFor(jars,gateway);
  serviceId=(await api('/api/admin/services','POST',config)).id;
  await api('/api/admin/users','POST',{username:ordinary,display_name:'Quick test user',password:ordinaryPassword,role:'user',enabled:true});
  userId=(await api('/api/admin/state')).users.find(user=>user.username===ordinary).id;

  let login=await flow();
  assert.equal((await publicInfo(login,{jar:null})).json.quick_login,null);
  assert.equal((await quick(login,{jar:null})).status,401);
  const info=(await publicInfo(login)).json;
  assert.equal(info.quick_login.user.username,username);assert.equal(info.quick_login.permitted,true);assert.equal(info.quick_login.csrf,csrf);
  assert.equal((await quick(login,{headers:{Origin:'https://other.invalid'}})).status,403);
  assert.equal((await quick(login,{headers:{'X-CSRF-Token':'wrong'}})).status,403);
  assert.equal((await quick(login,{headers:{'X-Gateway-Request':''}})).status,403);
  assert.equal((await quick(login,{body:{...payload(login),appid:'wrong-app'}})).status,400);
  assert.equal((await quick(login,{body:{...payload(login),token:payload(login).token+'bad'}})).status,410);
  const response=await quick(login);assert.equal(response.headers['set-cookie'],undefined);
  const callback=new URL(response.json.redirect);
  assert.equal((await request(callback.pathname+callback.search,{host,jar:null})).status,403);
  await consume(response);
  assert.equal((await request(callback.pathname+callback.search,{host})).status,410);
  assert.equal((await quick(login)).status,410);
  assert.equal((await auth()).headers['x-gateway-user'],username);
  assert.equal(cookieFor(jars,gateway),consoleCookies);
  console.log('PASS quick login, explicit confirmation, CSRF, AppID/token checks, browser binding and callback replay rejection');

  login=await flow();assert.equal((await publicInfo(login)).json.quick_login.permitted,true);
  config.allow_all=false;config.users=[userId];await api('/api/admin/services/'+serviceId,'PUT',config);
  assert.equal((await publicInfo(login)).json.quick_login.permitted,false);
  assert.equal((await quick(login,{body:{...payload(login),user_id:userId}})).status,403);
  const switched=await request('/api/login',{method:'POST',body:{...payload(login),username:ordinary,password:ordinaryPassword,mode:'service'}});
  assert.equal(switched.headers['set-cookie'],undefined);await consume(switched);
  assert.equal((await auth()).headers['x-gateway-user'],ordinary);
  assert.equal((await api('/api/me')).user.username,username);assert.equal(cookieFor(jars,gateway),consoleCookies);
  console.log('PASS permission changes are rechecked, admin has no allowlist bypass, and account switching preserves the console account');

  login=await flow();config.enabled=false;await api('/api/admin/services/'+serviceId,'PUT',config);
  assert.equal((await quick(login)).status,410);
  config.enabled=true;config.allow_all=true;await api('/api/admin/services/'+serviceId,'PUT',config);
  const revokedJar=new Map();
  assert.equal((await request('/api/login',{method:'POST',body:{username,password,mode:'admin'},jar:revokedJar})).status,200);
  const revokedCsrf=(await request('/api/me',{jar:revokedJar})).json.csrf;
  const sessionId=createHash('sha256').update(revokedJar.get(gateway).get('__Host-gateway_session')).digest('hex');
  await api('/api/admin/sessions/'+sessionId,'DELETE',{});
  assert.equal((await quick(login,{jar:revokedJar,csrfToken:revokedCsrf})).status,401);
  console.log('PASS disabled services and revoked console sessions cannot use quick login');

  tlsDir=mkdtempSync(join(tmpdir(),'gateway-quick-login-'));
  const key=join(tlsDir,'relay.key'),cert=join(tlsDir,'relay.crt');
  const generated=spawnSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','1','-subj','/CN='+gateway,'-addext','subjectAltName=DNS:'+gateway+',DNS:'+host],{encoding:'utf8'});
  assert.equal(generated.status,0,'Cannot generate test TLS certificate');
  // Relay browser traffic to the selected test gateway, including business authentication.
  relay=https.createServer({key:readFileSync(key),cert:readFileSync(cert)},async(req,res)=>{
    try {
      const domain=req.headers.host;
      if(domain!==gateway&&domain!==host){res.writeHead(404);res.end();return;}
      let result;
      if(domain===host&&!req.url.startsWith('/_gateway/')){
        result=await request('/internal/auth',{host,jar:null,headers:{...req.headers,'X-Forwarded-Host':host,'X-Forwarded-Uri':req.url,'X-Forwarded-Method':req.method}});
        if(result.status===200){
          res.writeHead(200,{'Content-Type':'application/json'});
          res.end(JSON.stringify({uri:req.url,claims:JSON.parse(Buffer.from(result.headers['x-gateway-token'].split('.')[1],'base64url'))}));return;
        }
      }else{
        const chunks=[];for await(const chunk of req)chunks.push(chunk);
        const body=chunks.length?Buffer.concat(chunks):undefined;
        result=await request(req.url,{host:domain,method:req.method,headers:req.headers,body,jar:null});
      }
      res.writeHead(result.status,result.headers);res.end(result.body);
    }catch(error){res.writeHead(502);res.end(error.message);}
  });
  relay.on('connection',socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));});
  await new Promise((resolve,reject)=>{relay.once('error',reject);relay.listen(tlsPort,'127.0.0.1',resolve);});
  browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_PATH,args:['--no-sandbox',`--host-resolver-rules=MAP ${gateway} 127.0.0.1:${tlsPort}, MAP ${host} 127.0.0.1:${tlsPort}`]});
  mkdirSync('artifacts',{recursive:true});
  const anonymous=await browserContext(false);
  await anonymous.page.goto('https://'+host+'/anonymous');
  await anonymous.page.getByLabel('\u7528\u6237\u540d',{exact:true}).waitFor();
  assert.equal(await anonymous.page.locator('#quick-login').count(),0);await anonymous.context.close();

  const first=await browserContext();
  await first.page.goto('https://'+host+'/private?browser=quick');
  const quickButton=first.page.getByRole('button',{name:'\u5feb\u6377\u767b\u5f55',exact:true});
  await quickButton.waitFor();assert(await quickButton.isEnabled());
  assert(await first.page.locator('#login-form').isHidden());
  assert.equal(await first.page.locator('.quick-account .mono').textContent(),username);
  await screenshot(first.page,'desktop',1440,1000);await screenshot(first.page,'mobile',390,844);
  await screenshot(first.page,'small-mobile',320,740);
  await quickButton.click();await first.page.waitForURL('https://'+host+'/private?browser=quick');
  assert.equal(JSON.parse(await first.page.locator('body').textContent()).claims.username,username);
  assert.deepEqual((await first.context.cookies(origin)).map(({name,value})=>[name,value]).sort(),[...jars.get(gateway)].sort());
  await first.context.close();

  config.allow_all=false;await api('/api/admin/services/'+serviceId,'PUT',config);
  const second=await browserContext();await second.page.goto('https://'+host+'/private?browser=switch');
  await second.page.locator('#quick-login-button').waitFor();assert(await second.page.locator('#quick-login-button').isDisabled());
  assert((await second.page.locator('#quick-login-error').textContent()).length>0);
  await screenshot(second.page,'denied-mobile',390,844);
  await second.page.getByRole('button',{name:'\u5207\u6362\u8d26\u53f7',exact:true}).click();
  assert(await second.page.getByLabel('\u7528\u6237\u540d',{exact:true}).evaluate(node=>node===document.activeElement));
  await second.page.getByLabel('\u7528\u6237\u540d',{exact:true}).fill('discard-me');
  await second.page.getByRole('button',{name:'\u4f7f\u7528\u5f53\u524d\u8d26\u53f7',exact:true}).click();
  assert(await second.page.locator('#login-form').isHidden());
  await second.page.getByRole('button',{name:'\u5207\u6362\u8d26\u53f7',exact:true}).click();
  assert.equal(await second.page.getByLabel('\u7528\u6237\u540d',{exact:true}).inputValue(),'');
  await screenshot(second.page,'switch-mobile',390,844);
  await second.page.getByLabel('\u7528\u6237\u540d',{exact:true}).fill(ordinary);
  await second.page.getByLabel('\u5bc6\u7801',{exact:true}).fill(ordinaryPassword);
  await second.page.getByRole('button',{name:'\u767b\u5f55',exact:true}).click();
  await second.page.waitForURL('https://'+host+'/private?browser=switch');
  assert.equal(JSON.parse(await second.page.locator('body').textContent()).claims.username,ordinary);
  assert.deepEqual((await second.context.cookies(origin)).map(({name,value})=>[name,value]).sort(),[...jars.get(gateway)].sort());
  await second.page.goto(origin+'/api/me');assert.equal(JSON.parse(await second.page.locator('body').textContent()).user.username,username);
  await second.context.close();assert.deepEqual(errors,[]);
  console.log('PASS desktop/mobile quick login, anonymous fallback, disabled unauthorized button, switching accounts and unchanged Gateway identity');
}finally {
  await browser?.close();for(const socket of sockets)socket.destroy();
  if(relay?.listening)await new Promise(resolve=>relay.close(resolve));
  if(tlsDir)rmSync(tlsDir,{recursive:true,force:true});
  if(serviceId)await api('/api/admin/services/'+serviceId,'DELETE',{});
  if(userId)await api('/api/admin/users/'+userId,'DELETE',{});
}
