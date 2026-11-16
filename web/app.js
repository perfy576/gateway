'use strict';
const app = document.querySelector('#app');
const modal = document.querySelector('#modal');
let me = null, csrfToken = '', state = null, view = 'services', search = '', toastTimer;
const titles = {services:'域名与服务', users:'用户管理', sessions:'在线会话', audit:'审计日志', account:'账号安全'};
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const icon = name => `<i data-lucide="${name}" aria-hidden="true"></i>`;
const iconButton = (name, title, action, id='') => `<button type="button" class="icon" title="${esc(title)}" aria-label="${esc(title)}" data-action="${action}" data-id="${esc(id)}">${icon(name)}</button>`;
const brand = () => `<a class="brand" href="/"><span class="brand-mark">${icon('waypoints')}</span>Gateway</a>`;
const refreshIcons = () => window.lucide?.createIcons();
const sorted = list => [...list].sort((a,b) => Number(a.id) - Number(b.id));
function toast(text, failure=false) {
  const node = document.querySelector('#toast'); node.textContent=text; node.classList.toggle('failure',failure); node.hidden=false;
  clearTimeout(toastTimer); toastTimer=setTimeout(()=>node.hidden=true,4000);
}
async function api(path, options={}) {
  const response = await fetch(path, {credentials:'same-origin', ...options, headers:{
    'Content-Type':'application/json','X-Gateway-Request':'1','X-CSRF-Token':csrfToken,...options.headers}});
  const result = await response.json();
  if (!response.ok) { const error=new Error(result.error || '请求失败'); error.status=response.status; throw error; }
  return result;
}
function field(label, name, value='', type='text', extra='') {
  return `<div class="field"><label for="f-${name}">${esc(label)}</label><input id="f-${name}" name="${name}" type="${type}" value="${esc(value)}" ${extra}></div>`;
}
function passwordField(label, name, autocomplete='current-password', minimum=1) {
  return `<div class="field"><label for="f-${name}">${esc(label)}</label><div class="password-input"><input id="f-${name}" name="${name}" type="password" autocomplete="${autocomplete}" minlength="${minimum}" maxlength="256" required>${iconButton('eye','显示密码','toggle-password',`f-${name}`)}</div></div>`;
}
function showModal(title, content, footer, submit) {
  modal.innerHTML=`<form id="dialog-form"><div class="modal-header"><h2>${esc(title)}</h2>${iconButton('x','关闭','close-modal')}</div><div class="modal-body"><div class="error" id="dialog-error"></div>${content}</div><div class="modal-footer">${footer}</div></form>`;
  modal.querySelectorAll('button').forEach(button=>{ if (!button.hasAttribute('type')) button.type='button'; });
  modal.querySelectorAll('[data-submit]').forEach(button=>button.type='submit');
  if (submit) modal.querySelector('form').addEventListener('submit',async event=>{
    event.preventDefault(); const button=event.submitter; button.disabled=true;
    try { await submit(new FormData(event.currentTarget)); } catch(error) { modal.querySelector('#dialog-error').textContent=error.message; }
    finally { button.disabled=false; }
  });
  modal.showModal(); refreshIcons();
}
function confirmAction(title, message, label, action) {
  showModal(title,`<p class="confirm-text">${esc(message)}</p>`,`<button type="button" data-action="close-modal">取消</button><button class="danger" data-submit>${esc(label)}</button>`,async()=>{await action();modal.close();});
}
async function renderLogin(admin=false) {
  const params=new URLSearchParams(location.search),request=params.get('token') || params.get('request') || '',appid=params.get('appid') || '';let data;
  if(!admin) {
    try { data=await api('/api/public?token='+encodeURIComponent(request)+'&appid='+encodeURIComponent(appid)); }
    catch(error) { app.innerHTML=`<div class="auth-page"><header class="auth-header">${brand()}</header><div class="auth-main"><h1>登录请求已失效</h1><p class="muted">${esc(error.message)}</p><a href="/">返回首页</a></div></div>`;refreshIcons();return; }
  }
  app.innerHTML=`<div class="auth-page"><header class="auth-header">${brand()}<span class="muted">${admin?'管理控制台':'统一身份认证'}</span></header><section class="auth-main"><h1>${admin?'管理后台登录':'登录'}</h1><p class="muted">${admin?'Gateway 管理员':'身份验证'}</p>${admin?'':`<div class="login-target"><span class="target-symbol">${icon('app-window')}</span><div><span class="target-caption">访问服务</span><h2>${esc(data.service.name)}</h2><p class="mono">${esc(data.service.host)}</p></div>${icon('lock-keyhole')}</div><div class="return-address mono" title="${esc(data.return_url)}">${esc(new URL(data.return_url).pathname+new URL(data.return_url).search)}</div>`}<form id="login-form"><div class="error" id="login-error"></div>${field('用户名','username','','text','autocomplete="username" maxlength="64" required')}${passwordField('密码','password')}<button class="primary" type="submit">登录 ${icon('arrow-right')}</button></form></section><footer class="auth-footer">${esc(location.host)}</footer></div>`;
  refreshIcons();
  app.querySelector('#login-form').addEventListener('submit',async event=>{
    event.preventDefault();const button=event.submitter;button.disabled=true;app.querySelector('#login-error').textContent='';
    const form=new FormData(event.currentTarget);
    try {
      const result=await api('/api/login',{method:'POST',body:JSON.stringify({username:form.get('username'),password:form.get('password'),token:request,appid,mode:admin?'admin':'service'})});
      location.href=result.redirect;
    } catch(error) { app.querySelector('#login-error').textContent=error.message;button.disabled=false; }
  });
}
async function renderHome() {
  app.innerHTML=`<div class="auth-page"><header class="auth-header">${brand()}<a class="muted" href="/admin">管理控制台 ${icon('arrow-up-right')}</a></header><section class="public-home"><span class="home-mark">${icon('waypoints')}</span><h1>Gateway</h1><p class="home-domain mono">${esc(location.host)}</p><div class="home-status"><span class="dot"></span><span id="home-status">正在连接</span></div></section><footer class="auth-footer">统一身份认证网关</footer></div>`;
  refreshIcons();try{await api('/healthz');app.querySelector('#home-status').textContent='服务运行正常';}catch{app.querySelector('#home-status').textContent='服务暂时不可用';}
}
function renderShell() {
  const admin=me.role==='admin';
  const nav=(name,svg)=>`<button data-action="navigate" data-id="${name}" class="${view===name?'active':''}">${icon(svg)}${titles[name]}</button>`;
  app.innerHTML=`<div class="shell"><aside class="sidebar">${brand()}<nav class="nav">${admin?nav('services','network')+nav('users','users')+nav('sessions','monitor')+nav('audit','list-checks'):''}${nav('account','shield-check')}</nav><div class="sidebar-bottom"><div class="userline"><span class="avatar">${esc((me.display_name || me.username).slice(0,1).toUpperCase())}</span><div><div class="username">${esc(me.display_name)}</div><small>${admin?'管理员':'用户'} · ${esc(me.username)}</small></div></div><div class="actions">${iconButton('log-out','退出所有登录','logout')}</div></div></aside><div class="content"><header class="topbar">${iconButton('menu','打开导航','menu')}<div class="breadcrumb"><span>Gateway</span><span>/</span><strong id="breadcrumb-title">${titles[view]}</strong></div><span class="online"><span class="dot"></span>运行中</span></header><section class="workspace" id="workspace"></section></div></div>`;
  app.querySelector('.topbar>button').classList.add('mobile-menu');renderView();
}
function pageHeading(action='') {
  return `<div class="page-heading"><div><h1>${titles[view]}</h1><p class="muted">${esc(location.host)}</p></div>${action}</div>`;
}
function empty(title, name='inbox', action='') { return `<div class="empty">${icon(name)}<h3>${esc(title)}</h3>${action}</div>`; }
function table(headings,rows) {
  return `<div class="table-wrap"><table><thead><tr>${headings.map(h=>`<th>${h}</th>`).join('')}</tr></thead><tbody>${rows}</tbody></table></div>`;
}
function searchTools(count) {
  return `<div class="table-tools"><div class="search">${icon('search')}<input id="search" value="${esc(search)}" placeholder="搜索${view==='services'?'域名或服务':'用户'}" aria-label="搜索"></div><div class="actions"><span class="muted">共 ${count} 项</span>${iconButton('refresh-cw','刷新','refresh')}</div></div>`;
}
function duration(seconds) {return seconds<60?`${seconds} 秒`:seconds<3600?`${Math.floor(seconds/60)} 分钟`:seconds<86400?`${Math.floor(seconds/3600)} 小时`:`${Math.floor(seconds/86400)} 天`;}
function renderServices() {
  const list=sorted(state.services).filter(s=>`${s.name} ${s.host} ${s.upstream}`.toLowerCase().includes(search.toLowerCase()));
  const add=`<button class="primary" data-action="edit-service">${icon('plus')}添加域名</button>`;
  return pageHeading(add)+`<div class="stats"><div class="stat"><label>接入域名</label><strong>${state.services.length}</strong></div><div class="stat"><label>已启用服务</label><strong>${state.services.filter(s=>s.enabled).length}</strong></div><div class="stat"><label>在线会话</label><strong>${state.sessions.length}</strong></div><div class="stat"><label>认证请求</label><strong>${state.metrics.auth_requests.toLocaleString()}</strong></div></div>`+searchTools(list.length)+(list.length?table(['服务 / 域名','后端地址','免登录路径','状态','操作'],list.map(s=>`<tr><td class="name">${esc(s.name)}<div class="subtext mono">${esc(s.host)}</div></td><td class="mono">${esc(s.upstream)}</td><td><span class="badge neutral">${s.excluded_paths.length} 条规则</span></td><td><span class="badge ${s.enabled?'':'off'}"><span class="dot" ${s.enabled?'':'hidden'}></span>${s.enabled?'已启用':'已停用'}</span></td><td><div class="actions">${iconButton('external-link','打开服务','open-service',s.id)}${iconButton('key-round','后端签名密钥','service-secret',s.id)}${iconButton('pencil','编辑服务','edit-service',s.id)}${iconButton('trash-2','删除服务','delete-service',s.id)}</div></td></tr>`).join('')):empty(search?'没有匹配的服务':'暂无接入域名','network',search?'':add))+`<div class="table-footer">进程已运行 ${duration(state.metrics.uptime_seconds)}</div>`;
}
function renderUsers() {
  const list=sorted(state.users).filter(u=>`${u.username} ${u.display_name}`.toLowerCase().includes(search.toLowerCase()));
  return pageHeading(`<button class="primary" data-action="edit-user">${icon('user-plus')}添加用户</button>`)+searchTools(list.length)+(list.length?table(['用户','角色','状态','在线会话','操作'],list.map(u=>`<tr><td class="name">${esc(u.display_name)}<div class="subtext mono">${esc(u.username)}</div></td><td><span class="badge ${u.role==='admin'?'blue':'neutral'}">${u.role==='admin'?'管理员':'普通用户'}</span></td><td><span class="badge ${u.enabled?'':'off'}">${u.enabled?'正常':'已停用'}</span></td><td>${state.sessions.filter(s=>s.user_id===u.id).length}</td><td><div class="actions">${iconButton('pencil','编辑用户','edit-user',u.id)}${iconButton('log-out','撤销用户会话','revoke-user',u.id)}</div></td></tr>`).join('')):empty('没有匹配的用户','users'));
}
function renderSessions() {
  const list=[...state.sessions].sort((a,b)=>b.created_at-a.created_at);
  return pageHeading(`<button data-action="refresh">${icon('refresh-cw')}刷新</button>`)+(list.length?table(['用户','IP 地址','登录时间','剩余有效期','操作'],list.map(s=>`<tr><td class="name">${esc(s.username)}</td><td class="mono">${esc(s.ip || '—')}</td><td>${new Date(s.created_at*1000).toLocaleString('zh-CN')}</td><td>${duration(Math.max(0,s.expires_at-Math.floor(Date.now()/1000)))}</td><td>${iconButton('log-out','撤销此用户的全部会话','revoke-user',s.user_id)}</td></tr>`).join('')):empty('暂无在线会话','monitor'));
}
const actionNames={'login.success':'登录成功','login.failed':'登录失败','logout':'退出登录','password.changed':'修改密码','service.create':'添加服务','service.update':'修改服务','service.delete':'删除服务','service.secret.read':'查看密钥','service.secret.rotate':'轮换密钥','user.create':'创建用户','user.update':'修改用户','sessions.revoke':'撤销会话'};
function renderAudit() {
  return pageHeading(`<button data-action="refresh">${icon('refresh-cw')}刷新</button>`)+(state.audit?.length?table(['时间','操作人','操作','详情','IP 地址'],state.audit.map(a=>`<tr><td>${esc(a.created_at)}</td><td>${esc(a.actor)}</td><td>${esc(actionNames[a.action] || a.action)}</td><td class="mono data-detail">${esc(a.detail || '—')}</td><td class="mono">${esc(a.ip || '—')}</td></tr>`).join('')):empty('暂无审计记录','list-checks'))+`<div class="table-footer">最近 100 条记录</div>`;
}
function renderAccount() {
  return pageHeading()+`<div class="section-title"><h2>修改密码</h2></div><form id="password-form" class="account-form"><div class="error" id="password-error"></div>${passwordField('当前密码','old_password')}${passwordField('新密码（至少 12 位）','new_password','new-password',12)}${passwordField('确认新密码','confirm_password','new-password',12)}<button class="primary" type="submit">${icon('check')}更新密码</button></form>`;
}
function renderView() {
  const node=app.querySelector('#workspace'); if (!node) return;
  node.innerHTML=({services:renderServices,users:renderUsers,sessions:renderSessions,audit:renderAudit,account:renderAccount}[view])();
  app.querySelector('#breadcrumb-title').textContent=titles[view];
  app.querySelectorAll('[data-action="navigate"]').forEach(button=>button.classList.toggle('active',button.dataset.id===view));
  const input=node.querySelector('#search');if(input) input.addEventListener('input',()=>{
    const start=input.selectionStart;search=input.value;renderView();const updated=node.querySelector('#search');updated.focus();updated.setSelectionRange(start,start);
  });
  node.querySelector('#password-form')?.addEventListener('submit',async event=>{
    event.preventDefault();const button=event.submitter, form=new FormData(event.currentTarget);button.disabled=true;
    try {
      if(form.get('new_password')!==form.get('confirm_password'))throw new Error('两次输入的新密码不一致');
      await api('/api/password',{method:'POST',body:JSON.stringify(Object.fromEntries(form))});location.href='/admin';
    }catch(error){node.querySelector('#password-error').textContent=error.message;button.disabled=false;}
  });refreshIcons();
}
async function loadState() {
  if(me.role==='admin') {
    const data=await api('/api/admin/state');state={...data,audit:state?.audit};
    if(view==='audit') state.audit=(await api('/api/admin/audit')).entries;
  }
  const data=await api('/api/me');me=data.user;csrfToken=data.csrf;
}
function serviceDialog(id) {
  const s=state.services.find(s=>s.id===id) || {appid:'',name:'',host:'',upstream:'',excluded_paths:[],users:[],enabled:true,allow_all:true};
  showModal(id?'编辑域名':'添加域名',`${field('服务名称','name',s.name,'text','maxlength="128" required')}${field('AppID','appid',s.appid,'text','pattern="[a-zA-Z0-9](?:[a-zA-Z0-9_.]|-){0,63}" maxlength="64" autocapitalize="off" autocomplete="off" required')}${field('接入域名','host',s.host,'text','placeholder="app.example.com" autocapitalize="off" maxlength="253" required')}${field('后端地址','upstream',s.upstream,'url','placeholder="http://10.0.0.8:8080" maxlength="512" required')}<div class="field"><label for="f-excluded">免登录路径</label><textarea id="f-excluded" name="excluded_paths" placeholder="/healthz&#10;/assets/*">${esc(s.excluded_paths.join('\n'))}</textarea></div><div class="switch-row"><span>启用服务</span><gw-checkbox name="enabled" toggle ${s.enabled?'checked':''}>启用</gw-checkbox></div><gw-checkbox id="allow-all" name="allow_all" ${s.allow_all?'checked':''}>允许所有已登录用户访问</gw-checkbox><div class="user-checks" ${s.allow_all?'hidden':''}>${sorted(state.users).map(u=>`<gw-checkbox name="users" value="${esc(u.id)}" ${s.users.includes(u.id)?'checked':''}>${esc(u.display_name)} · ${esc(u.username)}${u.role==='admin'?' · 管理员':''}</gw-checkbox>`).join('')}</div>`,`<button data-action="close-modal">取消</button><button class="primary" data-submit>${icon('check')}保存</button>`,async form=>{
    const data={appid:form.get('appid').trim(),name:form.get('name').trim(),host:form.get('host').trim().toLowerCase(),upstream:form.get('upstream').trim(),excluded_paths:form.get('excluded_paths').split('\n').map(x=>x.trim()).filter(Boolean),enabled:form.has('enabled'),allow_all:form.has('allow_all'),users:form.getAll('users')};
    await api('/api/admin/services'+(id?'/'+id:''),{method:id?'PUT':'POST',body:JSON.stringify(data)});modal.close();await loadState();renderView();toast('服务配置已保存');
  });
  modal.querySelector('#allow-all').addEventListener('change',event=>modal.querySelector('.user-checks').hidden=event.target.checked);
}
function userDialog(id) {
  const u=state.users.find(u=>u.id===id) || {username:'',display_name:'',role:'user',enabled:true};
  showModal(id?'编辑用户':'添加用户',`${field('用户名','username',u.username,'text','pattern="(?:[a-zA-Z0-9_.]|-)+" maxlength="64" autocomplete="off" required')}${field('显示名称','display_name',u.display_name,'text','maxlength="128" required')}<div class="field"><label id="role-label">角色</label><gw-select name="role" value="${u.role}" aria-labelledby="role-label"><gw-option value="user">普通用户</gw-option><gw-option value="admin">管理员</gw-option></gw-select></div>${field(id?'重置密码（留空保留原密码）':'初始密码（至少 12 位）','password','','password',`autocomplete="new-password" minlength="12" maxlength="256" ${id?'':'required'}`)}<gw-checkbox name="enabled" toggle ${u.enabled?'checked':''}>账号启用</gw-checkbox>`,`<button data-action="close-modal">取消</button><button class="primary" data-submit>${icon('check')}保存</button>`,async form=>{
    await api('/api/admin/users'+(id?'/'+id:''),{method:id?'PUT':'POST',body:JSON.stringify({username:form.get('username'),display_name:form.get('display_name'),role:form.get('role'),password:form.get('password'),enabled:form.has('enabled')})});
    modal.close();if(id===me.id){location.href='/admin';return;}await loadState();renderView();toast('用户已保存');
  });
}
async function secretDialog(id) {
  const s=state.services.find(s=>s.id===id),data=await api(`/api/admin/services/${id}/secret`,{method:'POST',body:'{}'});
  showModal('后端签名密钥',`<dl class="key-info"><dt>服务</dt><dd>${esc(s.name)}</dd><dt>AppID</dt><dd class="mono"><span id="appid-value">${esc(data.appid)}</span>${iconButton('copy','复制 AppID','copy-appid')}</dd><dt>算法</dt><dd class="mono">HS256 · Token v${esc(data.token_version)} · Cookie v${esc(data.cookie_version)}</dd><dt>Issuer</dt><dd class="mono">${esc(data.issuer)}</dd><dt>Audience</dt><dd class="mono">${esc(data.audience)}</dd><dt>在线校验</dt><dd class="mono">${esc(data.verify_url)}</dd></dl><h3>Secret</h3><div class="secret-value mono" id="secret-value">${esc(data.secret)}</div><h3>在线校验凭据</h3><div class="secret-value mono" id="verification-key-value">${esc(data.verification_key)}</div><p class="notice">轮换后，后端需要同步更新 Secret 和在线校验凭据。</p>`,`<button class="danger" data-action="rotate-secret" data-id="${id}" title="更换 Secret" aria-label="更换 Secret">${icon('rotate-cw')}</button><button data-action="copy-verification-key">${icon('copy')}复制校验凭据</button><button class="primary" data-action="copy-secret">${icon('copy')}复制 Secret</button>`);
}
document.addEventListener('click',async event=>{
  const button=event.target.closest('button[data-action]');if(!button)return;
  const {action,id}=button.dataset;
  try {
    if(action==='toggle-password') {const input=document.getElementById(id);input.type=input.type==='password'?'text':'password';button.innerHTML=icon(input.type==='password'?'eye':'eye-off');button.title=input.type==='password'?'显示密码':'隐藏密码';button.setAttribute('aria-label',button.title);refreshIcons();return;}
    if(action==='close-modal'){modal.close();return;}
    if(action==='menu'){app.querySelector('.shell').classList.toggle('menu-open');return;}
    if(action==='navigate'){
      view=id;search='';app.querySelector('.shell').classList.remove('menu-open');
      if(view==='audit')await loadState();renderView();return;
    }
    if(action==='refresh'){button.disabled=true;await loadState();renderView();return;}
    if(action==='edit-service'){serviceDialog(id);return;}
    if(action==='edit-user'){userDialog(id);return;}
    if(action==='service-secret'){await secretDialog(id);return;}
    if(action==='open-service'){const s=state.services.find(s=>s.id===id);window.open(`https://${s.host}/`,'_blank','noopener,noreferrer');return;}
    if(action==='copy-secret'){await navigator.clipboard.writeText(modal.querySelector('#secret-value').textContent);toast('密钥已复制');return;}
    if(action==='copy-appid'){await navigator.clipboard.writeText(modal.querySelector('#appid-value').textContent);toast('AppID 已复制');return;}
    if(action==='copy-verification-key'){await navigator.clipboard.writeText(modal.querySelector('#verification-key-value').textContent);toast('校验凭据已复制');return;}
    if(action==='rotate-secret'){
      modal.close();confirmAction('轮换签名密钥','轮换后旧密钥立即停止签发，后端需要同步更新。','确认轮换',async()=>{
        await api(`/api/admin/services/${id}/rotate`,{method:'POST',body:'{}'});await loadState();setTimeout(()=>secretDialog(id).catch(e=>toast(e.message,true)),0);
      });return;
    }
    if(action==='delete-service'){
      const s=state.services.find(s=>s.id===id);confirmAction('删除域名',`确认删除 ${s.host}？该域名将停止提供网关转发。`,'删除',async()=>{
        await api(`/api/admin/services/${id}`,{method:'DELETE',body:'{}'});await loadState();renderView();toast('服务已删除');
      });return;
    }
    if(action==='revoke-user'){
      const u=state.users.find(u=>u.id===id);confirmAction('撤销登录会话',`确认让 ${u?.username || id} 退出所有服务？`,'撤销会话',async()=>{
        await api(`/api/admin/users/${id}/revoke`,{method:'POST',body:'{}'});if(id===me.id){location.href='/admin';return;}await loadState();renderView();toast('会话已撤销');
      });return;
    }
    if(action==='logout'){
      await api('/api/logout',{method:'POST',body:'{}'});location.href='/admin';return;
    }
  }catch(error){toast(error.message,true);if(error.status===401 && me)location.href='/admin';}
  finally{if(button.isConnected)button.disabled=false;}
});
modal.addEventListener('click',event=>{if(event.target===modal){const r=modal.getBoundingClientRect();if(event.clientX<r.left||event.clientX>r.right||event.clientY<r.top||event.clientY>r.bottom)modal.close();}});
async function init() {
  if(location.pathname==='/'){await renderHome();return;}
  if(location.pathname==='/login'){await renderLogin();return;}
  try {
    const data=await api('/api/me');me=data.user;csrfToken=data.csrf;
    if(me.role!=='admin'){app.innerHTML=`<div class="auth-main"><h1>无管理后台权限</h1><a href="/">返回首页</a></div>`;return;}
    view='services';await loadState();renderShell();
  }catch(error){if(error.status===401){await renderLogin(true);return;}app.innerHTML=`<div class="auth-main"><h1>暂时无法加载</h1><p class="error">${esc(error.message)}</p><a href="/admin">重新加载</a></div>`;}
}
init().catch(error=>toast(error.message,true));
