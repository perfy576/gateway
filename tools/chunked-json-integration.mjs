import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import {readFileSync} from 'node:fs';
import {randomBytes,createHash} from 'node:crypto';

const host='gateway.perfy576.com',origin='https://'+host;
const testPort=process.env.GATEWAY_TEST_PORT;
const record=readFileSync('.secrets/initial-admin.txt','utf8');
const username=record.match(/^Username: (.+)$/m)[1],password=record.match(/^Password: (.+)$/m)[1];
const cookies=new Map(),suffix=randomBytes(4).toString('hex');
let csrf='',userId,serviceId;
async function request(path,{method='GET',body,rawBody,chunked=false,headers={}}={}) {
  const payload=rawBody!==undefined?Buffer.from(rawBody):body===undefined?undefined:Buffer.from(JSON.stringify(body));
  const requestHeaders={Host:host,Cookie:[...cookies].map(([name,value])=>name+'='+value).join('; ')};
  if(payload){
    Object.assign(requestHeaders,{'Content-Type':'application/json',Origin:origin,'X-Gateway-Request':'1','X-CSRF-Token':csrf});
    if(chunked)Object.assign(requestHeaders,{'Transfer-Encoding':'chunked',Trailer:'X-Gateway-Test-Trailer'});
    else requestHeaders['Content-Length']=payload.length;
  }
  Object.assign(requestHeaders,headers);
  return new Promise((resolve,reject)=>{
    const req=(testPort?http:https).request({hostname:'127.0.0.1',port:Number(testPort||443),servername:host,path,method,headers:requestHeaders},res=>{
      const chunks=[];res.on('data',part=>chunks.push(part));res.on('end',()=>{
        for(const raw of res.headers['set-cookie']||[]){const pair=raw.split(';')[0],eq=pair.indexOf('=');cookies.set(pair.slice(0,eq),pair.slice(eq+1));}
        let json;try{json=JSON.parse(Buffer.concat(chunks).toString());}catch{}
        resolve({status:res.statusCode,json});
      });
    });req.on('error',reject);req.setTimeout(15000,()=>req.destroy(new Error('Timeout')));
    if(chunked&&payload){
      // Split UTF-8 characters and JSON tokens across chunks, with an HTTP trailer.
      for(let i=0;i<payload.length;i+=3)req.write(payload.subarray(i,i+3));
      req.addTrailers({'X-Gateway-Test-Trailer':'complete'});req.end();
    }else req.end(payload);
  });
}
async function api(path,method='GET',body,chunked=false) {
  const response=await request(path,{method,body,chunked});
  assert.equal(response.status,200,response.json?.error||path);return response.json;
}
try {
  await api('/api/login','POST',{username,password,mode:'admin'},true);
  csrf=(await api('/api/me')).csrf;
  assert.equal(cookies.size,2);assert.equal((await api('/api/me')).user.username,username);
  console.log('PASS chunked console login and authenticated session restoration');

  for(const chunked of [false,true]){
    for(const rawBody of ['{','[]']){
      const response=await request('/api/login',{method:'POST',rawBody,chunked});
      assert.equal(response.status,400);assert.equal(response.json.error,'\u8bf7\u6c42 JSON \u65e0\u6548');
    }
    const forbidden=await request('/api/login',{method:'POST',body:{username,password,mode:'admin'},chunked,headers:{Origin:'https://other.invalid'}});
    assert.equal(forbidden.status,403);
    const app=await request('/login',{method:'POST',body:{},chunked});
    assert.equal(app.status,400);assert.equal(app.json.result,'Failed');assert.equal(app.json.cookie,'');
    assert.equal(app.json.retmsg,'\u7f3a\u5c11\u5b57\u6bb5: appid');
    const verify=await request('/verify',{method:'POST',body:{},chunked});
    assert.equal(verify.status,400);assert.equal(verify.json.error,'\u7f3a\u5c11\u5b57\u6bb5: audience');
  }
  console.log('PASS fixed-length and chunked requests preserve JSON validation, CSRF and App/verify error contracts');

  const displayName='\u5206\u5757\u8bf7\u6c42\u6d4b\u8bd5';
  await api('/api/admin/users','POST',{username:'chunk_'+suffix,display_name:displayName,password:randomBytes(18).toString('hex'),role:'user',enabled:true},true);
  let state=await api('/api/admin/state');
  const user=state.users.find(user=>user.username==='chunk_'+suffix);userId=user.id;
  assert.equal(user.display_name,displayName);
  const service={appid:'chunk-'+suffix,name:displayName,host:'chunk-'+suffix+'.invalid',upstream:'http://127.0.0.1:19091',excluded_paths:[],users:[userId],allow_all:false,enabled:true,cookie_max_age_hours:12};
  serviceId=(await api('/api/admin/services','POST',service,true)).id;
  service.name+=' UTF-8';service.cookie_max_age_hours=0.5;
  await api('/api/admin/services/'+serviceId,'PUT',service,true);
  const secret=await api('/api/admin/services/'+serviceId+'/secret','POST',{},true);
  assert.equal(secret.appid,service.appid);assert.equal(secret.algorithm,'HS256');
  state=await api('/api/admin/state');const saved=state.services.find(service=>service.id===serviceId);
  assert.equal(saved.name,service.name);assert.equal(saved.cookie_max_age_hours,0.5);assert.deepEqual(saved.users,[userId]);
  console.log('PASS chunked administrative writes preserve multi-byte UTF-8, service policies and credential retrieval');
}finally {
  if(serviceId)await api('/api/admin/services/'+serviceId,'DELETE',{});
  if(userId)await api('/api/admin/users/'+userId,'DELETE',{});
  if(csrf&&cookies.has('__Host-gateway_session')){
    const id=createHash('sha256').update(cookies.get('__Host-gateway_session')).digest('hex');
    await api('/api/admin/sessions/'+id,'DELETE',{});
  }
}
