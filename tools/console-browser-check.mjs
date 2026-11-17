import assert from 'node:assert/strict';
import {protectPasswordBody} from './password-envelope.mjs';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {randomBytes} from 'node:crypto';

const require=createRequire(import.meta.url),{chromium,request}=require(process.env.PLAYWRIGHT_MODULE||'/home/ubuntu/.npm/_npx/e41f203b7505f1fb/node_modules/playwright');
const origin='https://gateway.perfy576.com';
const record=readFileSync('.secrets/initial-admin.txt','utf8');
const username=record.match(/^Username: (.+)$/m)[1],password=record.match(/^Password: (.+)$/m)[1];
const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_PATH,args:['--no-sandbox']});
const admin=await request.newContext(),ordinary=await browser.newContext({viewport:{width:390,height:844},locale:'zh-CN'});
let csrf='',consoleId='',userId='';
async function api(path,method='GET',data){
  data=await protectPasswordBody(path,method,data,target=>api(target));
  const r=await admin.fetch(origin+path,{method,data,headers:{Origin:origin,'X-Gateway-Request':'1','X-CSRF-Token':csrf}}).catch(()=>{throw new Error('API network failure: '+path);});
  assert.equal(r.status(),200,'API failed: '+path);return r.json();
}
try{
  await api('/api/login','POST',{username,password,mode:'admin'});csrf=(await api('/api/me')).csrf;
  const state=await api('/api/admin/state'),console=state.services.find(s=>s.builtin);consoleId=console.id;
  const user='test_console_ui_'+randomBytes(4).toString('hex'),pass=randomBytes(18).toString('hex');
  await api('/api/admin/users','POST',{username:user,display_name:'Console browser test (temporary)',password:pass,role:'user',enabled:true});
  userId=(await api('/api/admin/state')).users.find(u=>u.username===user).id;
  await api('/api/admin/services/'+consoleId,'PUT',{...console,users:[...console.users,userId]});
  const page=await ordinary.newPage();await page.goto(origin+'/admin');
  await page.getByLabel('用户名',{exact:true}).fill(user);await page.getByLabel('密码',{exact:true}).fill(pass);
  await page.getByRole('button',{name:'登录',exact:true}).click();await page.getByRole('heading',{name:'账号安全',exact:true}).waitFor();
  await page.goto(origin+'/admin#/services/new');await page.getByRole('heading',{name:'账号安全',exact:true}).waitFor();
  assert.equal(await page.locator('#service-form').count(),0);
  assert.equal(await page.getByRole('button',{name:'用户管理',exact:true}).count(),0);
  assert.equal(await page.getByRole('button',{name:'域名与服务',exact:true}).count(),0);
  assert.equal((await ordinary.request.get(origin+'/api/admin/state')).status(),403);
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  await page.screenshot({path:'artifacts/console-user-mobile.png',fullPage:true});
  const latest=(await api('/api/admin/state')).services.find(s=>s.id===consoleId);
  await api('/api/admin/services/'+consoleId,'PUT',{...latest,users:latest.users.filter(id=>id!==userId)});
  await page.reload();await page.getByRole('heading',{name:'控制台登录',exact:true}).waitFor();
  process.stdout.write('PASS ordinary console user sees only account security, admin APIs stay forbidden, and revoked console access returns to login\n');
}finally{
  if(consoleId&&userId){const latest=(await api('/api/admin/state')).services.find(s=>s.id===consoleId);await api('/api/admin/services/'+consoleId,'PUT',{...latest,users:latest.users.filter(id=>id!==userId)});}
  if(userId)await api('/api/admin/users/'+userId,'DELETE',{});
  await admin.dispose();await browser.close();
}
