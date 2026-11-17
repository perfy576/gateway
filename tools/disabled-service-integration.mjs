import assert from 'node:assert/strict';
import {protectPasswordBody} from './password-envelope.mjs';
import http from 'node:http';
import https from 'node:https';
import {randomBytes} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';

const require=createRequire(import.meta.url),{request}=require(process.env.PLAYWRIGHT_MODULE||'/home/ubuntu/.npm/_npx/e41f203b7505f1fb/node_modules/playwright');
const gateway='gateway.perfy576.com',origin='https://'+gateway,port=Number(process.env.GATEWAY_TEST_PORT||19090);
const record=readFileSync('.secrets/initial-admin.txt','utf8');
const username=record.match(/^Username: (.+)$/m)[1],password=record.match(/^Password: (.+)$/m)[1];
const suffix=randomBytes(4).toString('hex'),service={appid:'disabled-test-'+suffix,name:'停用服务测试',host:'disabled-test-'+suffix+'.invalid',upstream:'http://127.0.0.1:19091',enabled:false,allow_all:true,users:[],excluded_paths:['/*'],cookie_max_age_hours:12};
const client=await request.newContext({baseURL:origin});let id='',csrf='';
async function api(path,method='GET',data){
  data=await protectPasswordBody(path,method,data,target=>api(target));
  const response=await client.fetch(path,{method,data,headers:{Origin:origin,'X-Gateway-Request':'1','X-CSRF-Token':csrf}}).catch(()=>{throw new Error('API network failure: '+path);});
  assert.equal(response.status(),200,'API failed: '+path);return response.json();
}
async function local(path,{host=gateway,method='GET',headers={}}={}){
  return new Promise((resolve,reject)=>{
    const req=http.request({host:'127.0.0.1',port,path,method,headers:{Host:host,...headers}},res=>{
      let body='';res.on('data',chunk=>body+=chunk);res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body}));
    });req.on('error',reject);req.setTimeout(10000,()=>req.destroy(new Error('Request timeout')));req.end();
  });
}
async function caddy(method='GET'){
  return new Promise((resolve,reject)=>{
    const req=https.request({host:'127.0.0.1',port:443,servername:gateway,path:'/private?keep=1',method,headers:{Host:service.host}},res=>{
      let body='';res.on('data',chunk=>body+=chunk);res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body}));
    });req.on('error',reject);req.setTimeout(10000,()=>req.destroy(new Error('Request timeout')));req.end();
  });
}
try{
  await api('/api/login','POST',{username,password,mode:'admin'});csrf=(await api('/api/me')).csrf;
  id=(await api('/api/admin/services','POST',service)).id;
  const target=origin+'/?reason=service_disabled&appid='+service.appid;
  for(const method of ['GET','HEAD']){
    const response=await caddy(method);
    assert.equal(response.status,302);assert.equal(response.headers.location,target);
    assert.equal(response.headers['x-gateway-redirect-reason'],'service_disabled');
    assert.equal(response.headers['x-gateway-service-appid'],service.appid);
    assert.equal(response.headers['x-gateway-redirect'],target);
    assert.equal(response.headers['x-gateway-token'],undefined);
    assert.equal(response.headers['set-cookie'],undefined);
  }
  const post=await caddy('POST');assert.equal(post.status,403);
  assert.deepEqual(JSON.parse(post.body),{error:'该服务已停用',reason:'service_disabled',redirect_url:target});
  assert.equal(post.headers.location,undefined);
  const nginx=await local('/internal/nginx-auth',{host:service.host,headers:{'X-Forwarded-Host':service.host,'X-Forwarded-Uri':'/','X-Forwarded-Method':'GET'}});
  assert.equal(nginx.status,403);assert.equal(JSON.parse(nginx.body).redirect_url,target);
  assert.equal((await local('/_gateway/callback?flow=invalid',{host:service.host})).headers.location,target);
  assert.equal((await local('/internal/tls-ask?domain='+service.host)).status,200);
  assert.equal((await local('/internal/tls-ask?domain=unregistered.invalid')).status,404);
  const home=await client.get(target);assert.equal(home.status(),200);assert.equal(home.headers()['x-gateway-redirect-reason'],'service_disabled');
  const notice=await api('/api/public/notice?reason=service_disabled&appid='+service.appid);
  assert.deepEqual(notice.notice,{reason:'service_disabled',appid:service.appid,name:service.name,host:service.host});
  assert.equal((await api('/api/public/notice?reason=service_disabled&appid=unknown')).notice,null);
  assert.equal((await client.get('/?reason=service_disabled&appid=unknown')).headers()['x-gateway-redirect-reason'],undefined);
  assert.equal((await client.get('/',{headers:{'X-Gateway-Redirect-Reason':'service_disabled','X-Gateway-Service-Appid':service.appid}})).headers()['x-gateway-redirect-reason'],undefined);
  await api('/api/admin/services/'+id,'PUT',{...service,enabled:true});
  assert.equal((await api('/api/public/notice?reason=service_disabled&appid='+service.appid)).notice,null);
  assert.equal((await client.get(target)).headers()['x-gateway-redirect-reason'],undefined);
  process.stdout.write('PASS disabled services redirect GET/HEAD through Caddy with reason headers, reject writes, retain TLS, and show only verified current service status\n');
}finally{
  if(id)await api('/api/admin/services/'+id,'DELETE',{});
  await client.dispose();
}
