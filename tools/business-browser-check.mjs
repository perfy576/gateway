import assert from 'node:assert/strict';
import {protectPasswordBody} from './password-envelope.mjs';
import http from 'node:http';
import https from 'node:https';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {spawnSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_MODULE || '/home/ubuntu/.npm/_npx/e41f203b7505f1fb/node_modules/playwright');
const origin='https://gateway.perfy576.com',host='gateway-login-browser.invalid';
const credentialRecord=readFileSync('.secrets/initial-admin.txt','utf8');
const adminUsername=credentialRecord.match(/^Username: (.+)$/m)[1];
const password=credentialRecord.match(/^Password: (.+)$/m)[1];
function viaGateway(url,options={}) {
  const parsed=new URL(url),headers={...options.headers,host:parsed.hostname};
  return new Promise((resolve,reject)=>{
    const req=https.request({hostname:'127.0.0.1',port:443,servername:'gateway.perfy576.com',method:options.method||'GET',path:parsed.pathname+parsed.search,headers},res=>{
      const chunks=[];res.on('data',c=>chunks.push(c));res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body:Buffer.concat(chunks)}));
    });req.on('error',reject);req.setTimeout(15000,()=>req.destroy(new Error('Timeout')));req.end(options.body);
  });
}
const sockets=new Set();
const backend=http.createServer((req,res)=>{res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({url:req.url,headers:req.headers}));});
backend.on('connection',socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));});
await new Promise(resolve=>backend.listen(19091,'127.0.0.1',resolve));
const certificate=spawnSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout','.secrets/browser-proxy.key','-out','.secrets/browser-proxy.crt','-days','1','-subj','/CN='+host,'-addext','subjectAltName=DNS:'+host],{encoding:'utf8'});
assert.equal(certificate.status,0,'Cannot generate test TLS certificate');
// Map the synthetic test domain to a local TLS relay without changing production DNS.
const relay=https.createServer({key:readFileSync('.secrets/browser-proxy.key'),cert:readFileSync('.secrets/browser-proxy.crt')},async(req,res)=>{
  try {const response=await viaGateway(`https://${host}${req.url}`,{method:req.method,headers:req.headers});res.writeHead(response.status,response.headers);res.end(response.body);}
  catch(error){res.writeHead(502);res.end(error.message);}
});
relay.on('connection',socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));});
await new Promise(resolve=>relay.listen(19444,'127.0.0.1',resolve));
const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_PATH,args:['--no-sandbox',`--host-resolver-rules=MAP ${host} 127.0.0.1:19444`]});
let id,csrf,userId;
const admin=await browser.newContext({locale:'zh-CN',ignoreHTTPSErrors:true});
async function api(path,method='GET',body) {
  body=await protectPasswordBody(path,method,body,target=>api(target));
  const response=await admin.request.fetch(origin+path,{method,headers:{'X-Gateway-Request':'1','X-CSRF-Token':csrf || '',Origin:origin,'Content-Type':'application/json'},data:body});
  const result=await response.json();assert.equal(response.status(),200,JSON.stringify(result));return result;
}
try {
  await api('/api/login','POST',{username:adminUsername,password,mode:'admin'});csrf=(await api('/api/me')).csrf;
  id=(await api('/api/admin/services','POST',{appid:'gateway-login-browser',name:'项目文档中心',host,upstream:'http://127.0.0.1:19091',excluded_paths:[],enabled:true,allow_all:true,users:[]})).id;
  const secret=(await api(`/api/admin/services/${id}/secret`,'POST',{})).secret;
  const sdk='/data/code/gateway-sdk';
  const generated=spawnSync(sdk+'/.venv/bin/python',[sdk+'/python3-sdk/examples/verify.py'],{
    env:{...process.env,GATEWAY_TOKEN_SECRET:secret},encoding:'utf8',
    input:JSON.stringify({operation:'checkCookie',gateway_host:origin,audience:host,appid:'gateway-login-browser',token:'',cookie:'',method:'GET',uri:'/docs/project?version=2&lang=zh'})});
  assert.equal(generated.status,0,generated.stderr);const bootstrap=JSON.parse(generated.stdout);
  assert.equal(bootstrap.result,'redictionToLogin');assert.equal(bootstrap.status,302);
  const context=admin;
  context.setDefaultTimeout(30000);
  const page=await context.newPage(),errors=[];page.on('pageerror',error=>errors.push(error.message));
  await page.setViewportSize({width:1440,height:1000});
  await page.goto(bootstrap.redictUrl);await page.getByRole('heading',{name:'项目文档中心',exact:true}).waitFor();
  assert.equal(new URL(page.url()).hostname,'gateway.perfy576.com');
  assert.equal(await page.locator('select,[role="combobox"]').count(),0);assert.equal(await page.locator('input').count(),2);
  assert.equal(await page.locator('.login-target .mono').textContent(),host);assert.equal(await page.locator('.return-address').textContent(),'/docs/project?version=2&lang=zh');
  await page.screenshot({path:'artifacts/business-login-desktop.png',fullPage:true});
  await page.setViewportSize({width:390,height:844});
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));await page.screenshot({path:'artifacts/business-login-mobile.png',fullPage:true});
  assert(await page.locator('#login-form').isHidden());
  assert.equal(await page.locator('.quick-account .mono').textContent(),adminUsername);
  await page.getByRole('button',{name:'快捷登录',exact:true}).click();await page.waitForURL(`https://${host}/docs/project?version=2&lang=zh`);
  const response=JSON.parse(await page.locator('body').textContent());assert.equal(response.url,'/docs/project?version=2&lang=zh');
  const claims=JSON.parse(Buffer.from(response.headers['x-gateway-token'].split('.')[1],'base64url'));assert.equal(claims.authenticated,true);assert.equal(claims.username,adminUsername);
  assert.equal(claims.client_sdk_version,'1.2.0');assert.equal(claims.online_only,false);
  assert(!response.headers.cookie?.includes('__Host-gateway_session'));assert(response.headers.cookie?.includes('__Host-gateway_binding=v1.'));
  assert((await context.cookies('https://'+host)).some(c=>c.name==='__Host-gateway_session' && c.secure && c.httpOnly && c.sameSite==='Lax'));
  await page.reload();assert.equal(new URL(page.url()).host,host);assert.deepEqual(errors,[]);
  assert.equal((await api('/api/me')).user.username,adminUsername);
  console.log('PASS browser SDK quick login through Caddy preserves browser binding, protocol version, target URL and console identity; desktop/mobile screenshots captured');
  const switchedUsername='login_switch_'+randomBytes(4).toString('hex'),switchedPassword=randomBytes(18).toString('hex');
  await api('/api/admin/users','POST',{username:switchedUsername,display_name:'Browser switch test',password:switchedPassword,role:'user',enabled:true});
  userId=(await api('/api/admin/state')).users.find(user=>user.username===switchedUsername).id;
  await context.clearCookies({domain:host});
  await page.goto(`https://${host}/docs/project?version=2&lang=zh`);
  await page.getByRole('button',{name:'切换账号',exact:true}).click();
  await page.getByLabel('用户名',{exact:true}).fill(switchedUsername);await page.getByLabel('密码',{exact:true}).fill(switchedPassword);
  await page.getByRole('button',{name:'登录',exact:true}).click();await page.waitForURL(`https://${host}/docs/project?version=2&lang=zh`);
  const switchedResponse=JSON.parse(await page.locator('body').textContent());
  const switchedClaims=JSON.parse(Buffer.from(switchedResponse.headers['x-gateway-token'].split('.')[1],'base64url'));
  assert.equal(switchedClaims.username,switchedUsername);assert.equal((await api('/api/me')).user.username,adminUsername);assert.deepEqual(errors,[]);
  console.log('PASS switching to another business account through Caddy keeps the Gateway console account unchanged');
} finally {
  if(id)await api('/api/admin/services/'+id,'DELETE',{}).catch(error=>console.error('CLEANUP',error.message));
  if(userId)await api('/api/admin/users/'+userId,'DELETE',{}).catch(error=>console.error('CLEANUP',error.message));
  await browser.close();for(const socket of sockets)socket.destroy();await new Promise(resolve=>relay.close(resolve));await new Promise(resolve=>backend.close(resolve));
}
