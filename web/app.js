'use strict';
const app = document.querySelector('#app');
const modal = document.querySelector('#modal');
let me = null, csrfToken = '', state = null, view = 'services', serviceEditor = null, search = '', sessionFilter = 'all', toastTimer;
const titles = {services:'域名与服务', users:'用户管理', sessions:'有效会话', audit:'审计日志', account:'账号安全'};
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const icon = name => `<i data-lucide="${name}" aria-hidden="true"></i>`;
const iconButton = (name, title, action, id='') => `<button type="button" class="icon" title="${esc(title)}" aria-label="${esc(title)}" data-action="${action}" data-id="${esc(id)}">${icon(name)}</button>`;
const brand = () => `<a class="brand" href="/"><span class="brand-mark">${icon('waypoints')}</span>Gateway</a>`;
const refreshIcons = () => window.lucide?.createIcons();
const sorted = list => [...list].sort((a,b) => Number(a.id) - Number(b.id));
const sortedServices = list => [...list].sort((a,b) => Number(b.builtin)-Number(a.builtin) || Number(a.id)-Number(b.id));
function readRoute() {
  const route=location.hash.slice(1).split('/').filter(Boolean);
  view=me.role==='admin'&&Object.hasOwn(titles,route[0])?route[0]:(me.role==='admin'?'services':'account');
  serviceEditor=view==='services'&&route.length===2&&(route[1]==='new'||/^\d+$/.test(route[1]))?route[1]:null;
}
function navigate(route) {
  const hash='#/'+route;
  app.querySelector('.shell')?.classList.remove('menu-open');
  if(location.hash===hash){readRoute();renderView();}else location.hash=hash;
}
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
    catch(error) { app.innerHTML=`<div class="auth-page login-page"><header class="auth-header">${brand()}</header><div class="auth-main"><h1>登录请求已失效</h1><p class="muted">${esc(error.message)}</p><a href="/">返回首页</a></div></div>`;refreshIcons();return; }
  }
  const quick=data?.quick_login;
  if(quick)csrfToken=quick.csrf;
  const quickPanel=quick?`<div id="quick-login"><div class="quick-account"><span class="avatar">${icon('user-round')}</span><div><p>${esc(quick.user.display_name)}</p><p class="muted mono">${esc(quick.user.username)}</p></div></div><div class="error" id="quick-login-error" role="alert">${quick.permitted?'':'当前账号无权访问目标服务，请切换账号'}</div><button type="button" class="primary" id="quick-login-button" ${quick.permitted?'':'disabled aria-describedby="quick-login-error"'}>快捷登录 ${icon('arrow-right')}</button><button type="button" class="login-switch" id="switch-account">切换账号</button></div>`:'';
  app.innerHTML=`<div class="auth-page login-page"><header class="auth-header">${brand()}<span class="muted">${admin?'管理控制台':'统一身份认证'}</span></header><section class="auth-main"><h1>${admin?'控制台登录':'登录'}</h1><p class="muted">${admin?'Gateway 控制台':'身份验证'}</p>${admin?'':`<div class="login-target"><span class="target-symbol">${icon('app-window')}</span><div><span class="target-caption">访问服务</span><h2>${esc(data.service.name)}</h2><p class="mono">${esc(data.service.host)}</p></div>${icon('lock-keyhole')}</div><div class="return-address mono" title="${esc(data.return_url)}">${esc(new URL(data.return_url).pathname+new URL(data.return_url).search)}</div>`}${quickPanel}<form id="login-form" ${quick?'hidden':''}><div class="error" id="login-error" role="alert"></div>${field('用户名','username','','text','autocomplete="username" autocapitalize="none" spellcheck="false" enterkeyhint="next" maxlength="64" required')}${passwordField('密码','password')}<button class="primary" type="submit">登录 ${icon('arrow-right')}</button>${quick?'<button type="button" class="login-switch" id="use-current-account">使用当前账号</button>':''}</form></section><footer class="auth-footer">${esc(location.host)}</footer></div>`;
  app.querySelector('#f-password').enterKeyHint='go';
  refreshIcons();
  app.querySelector('#switch-account')?.addEventListener('click',()=>{
    app.querySelector('#quick-login').hidden=true;app.querySelector('#login-form').hidden=false;
    app.querySelector('#f-username').focus();
  });
  app.querySelector('#use-current-account')?.addEventListener('click',()=>{
    app.querySelector('#login-form').reset();app.querySelector('#login-error').textContent='';
    app.querySelector('#login-form').hidden=true;app.querySelector('#quick-login').hidden=false;
    app.querySelector(quick.permitted?'#quick-login-button':'#switch-account').focus();
  });
  app.querySelector('#quick-login-button')?.addEventListener('click',async event=>{
    const button=event.currentTarget;button.disabled=true;app.querySelector('#quick-login-error').textContent='';
    try {
      const result=await api('/api/login/quick',{method:'POST',body:JSON.stringify({token:request,appid})});
      location.href=result.redirect;
    }catch(error){app.querySelector('#quick-login-error').textContent=error.message;button.disabled=false;}
  });
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
  app.innerHTML=`<div class="auth-page"><header class="auth-header">${brand()}<a class="muted" href="/admin">管理控制台 ${icon('arrow-up-right')}</a></header><div class="home-notice" id="home-notice" role="status" hidden></div><section class="public-home"><span class="home-mark">${icon('waypoints')}</span><h1>Gateway</h1><p class="home-domain mono">${esc(location.host)}</p><div class="home-status"><span class="dot"></span><span id="home-status">正在连接</span></div></section><footer class="auth-footer">统一身份认证网关</footer></div>`;
  refreshIcons();try{await api('/healthz');app.querySelector('#home-status').textContent='网关运行正常';}catch{app.querySelector('#home-status').textContent='网关暂时不可用';}
  const params=new URLSearchParams(location.search);
  if(params.get('reason')==='service_disabled'&&params.has('appid')){
    try{
      const {notice}=await api('/api/public/notice?'+new URLSearchParams({reason:'service_disabled',appid:params.get('appid')}));
      if(notice){const node=app.querySelector('#home-notice');node.innerHTML=`${icon('circle-pause')}<div><h2>服务已停用</h2><p>${esc(notice.name)} <span class="mono">${esc(notice.host)}</span></p><p class="muted">请联系服务管理员恢复访问。</p></div>`;node.hidden=false;refreshIcons();}
    }catch{toast('暂时无法读取服务状态',true);}
  }
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
  const list=sortedServices(state.services).filter(s=>`${s.name} ${s.host} ${s.upstream}`.toLowerCase().includes(search.toLowerCase()));
  const add=`<button class="primary" data-action="edit-service">${icon('plus')}添加域名</button>`;
  const rows=list.map(s=>`<tr><td class="name">${esc(s.name)}${s.builtin?'<span class="builtin-label">内置</span>':''}<div class="subtext mono"><a class="service-domain" href="https://${esc(s.host)}/${s.builtin?'admin':''}" target="_blank" rel="noopener noreferrer">${esc(s.host)}${icon('arrow-up-right')}</a></div></td><td class="mono">${s.builtin?'内置控制台':esc(s.upstream)}</td><td>${s.cookie_max_age_hours===0?'无限':esc(Number(s.cookie_max_age_hours.toFixed(6)))+' 小时'}</td><td><span class="badge neutral">${s.builtin?'—':s.excluded_paths.length+' 条规则'}</span></td><td><button type="button" class="service-status" role="switch" aria-checked="${s.enabled}" aria-label="${esc(s.name)}启用状态" title="${s.builtin?'内置控制台始终启用':s.enabled?'停用服务':'启用服务'}" data-action="toggle-service" data-id="${esc(s.id)}" ${s.builtin?'disabled':''}><span class="status-track" aria-hidden="true"></span><span>${s.enabled?'已启用':'已停用'}</span></button></td><td><div class="actions">${s.builtin?'':iconButton('key-round','后端签名密钥','service-secret',s.id)}${iconButton('pencil','编辑服务','edit-service',s.id)}${s.builtin?'':iconButton('trash-2','删除服务','delete-service',s.id)}</div></td></tr>`).join('');
  return pageHeading(add)+`<div class="stats"><div class="stat"><label>接入域名</label><strong>${state.services.length}</strong></div><div class="stat"><label>已启用服务</label><strong>${state.services.filter(s=>s.enabled).length}</strong></div><div class="stat"><label>在线 / 有效会话</label><strong>${state.metrics.online_sessions} / ${state.metrics.valid_sessions}</strong></div><div class="stat"><label>认证请求</label><strong>${state.metrics.auth_requests.toLocaleString()}</strong></div></div>`+searchTools(list.length)+(list.length?table(['服务 / 域名','后端地址','Cookie 有效期','免登录路径','状态','操作'],rows):empty(search?'没有匹配的服务':'暂无接入域名','network',search?'':add))+`<div class="table-footer">进程已运行 ${duration(state.metrics.uptime_seconds)}</div>`;
}
function renderUsers() {
  const list=sorted(state.users).filter(u=>`${u.username} ${u.display_name}`.toLowerCase().includes(search.toLowerCase()));
  return pageHeading(`<button class="primary" data-action="edit-user">${icon('user-plus')}添加用户</button>`)+searchTools(list.length)+(list.length?table(['用户','角色','状态','在线 / 有效会话','操作'],list.map(u=>`<tr><td class="name">${esc(u.display_name)}<div class="subtext mono">${esc(u.username)}</div></td><td><span class="badge ${u.role==='admin'?'blue':'neutral'}">${u.role==='admin'?'管理员':'普通用户'}</span></td><td><span class="badge ${u.enabled?'':'off'}">${u.enabled?'正常':'已停用'}</span></td><td>${state.sessions.filter(s=>s.user_id===u.id&&s.online).length} / ${state.sessions.filter(s=>s.user_id===u.id).length}</td><td><div class="actions">${iconButton('pencil','编辑用户','edit-user',u.id)}${iconButton('log-out','撤销用户会话','revoke-user',u.id)}</div></td></tr>`).join('')):empty('没有匹配的用户','users'));
}
function clientInfo(value) {
  const app=value.app_package || '',agent=value.user_agent || '';
  return `<div class="client-info">${app?`<div class="mono">${esc(app)}</div>`:''}${agent?`<details class="${app?'subtext ':''}client-agent"><summary aria-label="User-Agent">${icon('chevron-right')}<span class="client-agent-preview">${esc(agent)}</span><span class="client-agent-label">User-Agent</span></summary><div class="client-agent-full">${esc(agent)}</div></details>`:''}${app||agent?'':'<span class="muted">未知客户端</span>'}</div>`;
}
function renderSessions() {
  const list=state.sessions.filter(s=>sessionFilter==='all'||(sessionFilter==='admin'?s.scope==='admin':s.service_id===sessionFilter)).sort((a,b)=>b.created_at-a.created_at);
  const filters=`<div class="table-tools"><div class="session-filter"><label id="session-filter-label">所属业务</label><gw-select id="session-filter" value="${esc(sessionFilter)}" aria-labelledby="session-filter-label"><gw-option value="all">全部业务</gw-option>${sortedServices(state.services).map(s=>`<gw-option value="${s.builtin?'admin':esc(s.id)}">${esc(s.name)} · ${esc(s.host)}</gw-option>`).join('')}</gw-select></div><span class="muted">在线 / 有效：${list.filter(s=>s.online).length} / ${list.length}</span></div>`;
  return pageHeading(`<button data-action="refresh">${icon('refresh-cw')}刷新</button>`)+filters+(list.length?table(['用户','所属业务 / 域名','状态','IP 地址','客户端','登录时间','最后访问','剩余有效期','操作'],list.map(s=>`<tr><td class="name">${esc(s.username)}</td><td class="name">${esc(s.service_name)}<div class="subtext mono">${esc(s.host)}</div></td><td><span class="badge ${s.online?'':'neutral'}">${s.online?'在线':'离线'}</span></td><td class="mono">${esc(s.ip || '—')}</td><td>${clientInfo(s)}</td><td>${new Date(s.created_at*1000).toLocaleString('zh-CN')}</td><td>${new Date(s.last_seen_at*1000).toLocaleString('zh-CN')}</td><td>${s.expires_at===0?'无限':duration(Math.max(0,s.expires_at-Math.floor(Date.now()/1000)))}</td><td>${iconButton('log-out','撤销此会话','revoke-session',s.id)}</td></tr>`).join('')):empty('暂无有效会话','monitor'));
}
const actionNames={'login.success':'登录成功','login.failed':'登录失败','logout':'退出登录','password.changed':'修改密码','service.create':'添加服务','service.update':'修改服务','service.delete':'删除服务','service.secret.read':'查看密钥','service.secret.rotate':'轮换密钥','user.create':'创建用户','user.update':'修改用户','sessions.revoke':'撤销用户全部会话','session.revoke':'撤销单个会话'};
function renderAudit() {
  return pageHeading(`<button data-action="refresh">${icon('refresh-cw')}刷新</button>`)+(state.audit?.length?table(['时间','操作人','操作','详情','IP 地址','客户端'],state.audit.map(a=>`<tr><td>${esc(a.created_at)}</td><td>${esc(a.actor)}</td><td>${esc(actionNames[a.action] || a.action)}</td><td class="mono data-detail">${esc(a.detail || '—')}</td><td class="mono">${esc(a.ip || '—')}</td><td>${clientInfo(a)}</td></tr>`).join('')):empty('暂无审计记录','list-checks'))+`<div class="table-footer">最近 100 条记录</div>`;
}
function renderAccount() {
  return pageHeading()+`<div class="section-title"><h2>修改密码</h2></div><form id="password-form" class="account-form"><div class="error" id="password-error"></div>${passwordField('当前密码','old_password')}${passwordField('新密码（至少 12 位）','new_password','new-password',12)}${passwordField('确认新密码','confirm_password','new-password',12)}<button class="primary" type="submit">${icon('check')}更新密码</button></form>`;
}
function renderView() {
  const node=app.querySelector('#workspace'); if (!node) return;
  node.innerHTML=serviceEditor!==null?renderServiceEditor(serviceEditor):({services:renderServices,users:renderUsers,sessions:renderSessions,audit:renderAudit,account:renderAccount}[view])();
  bindServiceEditor(node);
  node.querySelector('#session-filter')?.addEventListener('change',event=>{sessionFilter=event.target.value;renderView();});
  app.querySelector('#breadcrumb-title').textContent=serviceEditor===null?titles[view]:`${titles[view]} / ${serviceEditor==='new'?'添加域名':'编辑域名'}`;
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
function renderServiceEditor(id) {
  const s=id==='new'?{appid:'',name:'',host:'',upstream:'',excluded_paths:[],users:[],enabled:true,allow_all:true,cookie_max_age_hours:12}:state.services.find(s=>s.id===id);
  if(!s)return empty('服务不存在','network','<button data-action="service-list">返回业务列表</button>');
  const fixed=s.builtin?' readonly':'';
  const userChoices=sorted(state.users).map(u=>{
    const pinned=s.builtin&&u.role==='admin',checked=pinned||s.users.includes(u.id);
    return `${pinned?`<input type="hidden" name="users" value="${esc(u.id)}">`:''}<gw-checkbox name="users" value="${esc(u.id)}" ${checked?'checked':''} ${pinned?'disabled':''}>${esc(u.display_name)} · ${esc(u.username)}${u.role==='admin'?' · 管理员':''}${pinned?'（固定授权）':''}</gw-checkbox>`;
  }).join('');
  const connection=field('服务名称','name',s.name,'text','maxlength="128" required'+fixed)+
    field('AppID','appid',s.appid,'text','pattern="[a-zA-Z0-9](?:[a-zA-Z0-9_.]|-){0,63}" maxlength="64" autocapitalize="off" autocomplete="off" required'+fixed)+
    field('接入域名','host',s.host,'text','placeholder="app.example.com" autocapitalize="off" maxlength="253" required'+fixed)+
    field('后端地址','upstream',s.upstream,'url','placeholder="http://10.0.0.8:8080" maxlength="512" required'+fixed);
  return `<div class="service-editor"><div class="page-heading"><div class="editor-title">${iconButton('arrow-left','返回业务列表','service-list')}<div><h1>${id==='new'?'添加域名':'编辑域名'}</h1><p class="muted">${esc(s.name||location.host)}</p></div></div></div><form id="service-form" data-id="${esc(id)}"><div class="error" id="service-error" role="alert" tabindex="-1"></div><section class="editor-section"><h2>接入配置</h2><div class="editor-fields"><div class="form-grid">${connection}</div><div class="switch-row"><span>启用服务</span>${s.builtin?'<input type="hidden" name="enabled">':''}<gw-checkbox name="enabled" toggle ${s.enabled?'checked':''} ${s.builtin?'disabled':''}>启用</gw-checkbox></div></div></section><section class="editor-section"><h2>登录策略</h2><div class="editor-fields">${field('Cookie 有效期（小时，0 为无限）','cookie_max_age_hours',s.cookie_max_age_hours,'number','min="0" max="876000" step="any" required')}<div class="field" ${s.builtin?'hidden':''}><label for="f-excluded">免登录路径</label><textarea id="f-excluded" name="excluded_paths" placeholder="/healthz&#10;/assets/*"${fixed}>${esc(s.excluded_paths.join('\n'))}</textarea></div><gw-checkbox id="allow-all" name="allow_all" ${s.allow_all?'checked':''}>允许所有用户登录此业务</gw-checkbox><div class="user-checks" ${s.allow_all?'hidden':''}>${userChoices}</div></div></section><div class="editor-footer"><button type="button" data-action="service-list">取消</button><button type="submit" class="primary">${icon('check')}保存</button></div></form></div>`;
}
function bindServiceEditor(node) {
  const formNode=node.querySelector('#service-form');if(!formNode)return;
  node.querySelector('#allow-all').addEventListener('change',event=>node.querySelector('.user-checks').hidden=event.target.checked);
  formNode.addEventListener('submit',async event=>{
    event.preventDefault();const button=event.submitter,form=new FormData(formNode),id=formNode.dataset.id;
    button.disabled=true;node.querySelector('#service-error').textContent='';
    try {
    const data={appid:form.get('appid').trim(),name:form.get('name').trim(),host:form.get('host').trim().toLowerCase(),upstream:form.get('upstream').trim(),cookie_max_age_hours:Number(form.get('cookie_max_age_hours')),excluded_paths:form.get('excluded_paths').split('\n').map(x=>x.trim()).filter(Boolean),enabled:form.has('enabled'),allow_all:form.has('allow_all'),users:form.getAll('users')};
    await api('/api/admin/services'+(id==='new'?'':'/'+id),{method:id==='new'?'POST':'PUT',body:JSON.stringify(data)});
    await loadState();
    if(formNode.isConnected)navigate('services');
    toast('服务配置已保存');
    }catch(error){if(formNode.isConnected){const alert=node.querySelector('#service-error');alert.textContent=error.message;alert.focus();}if(error.status===401)location.href='/admin';}
    finally{button.disabled=false;}
  });
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
      search='';navigate(id);return;
    }
    if(action==='refresh'){button.disabled=true;await loadState();renderView();return;}
    if(action==='edit-service'){navigate('services/'+(id||'new'));return;}
    if(action==='service-list'){navigate('services');return;}
    if(action==='toggle-service'){
      const s=state.services.find(s=>s.id===id);if(!s||s.builtin)return;
      button.disabled=true;
      await api('/api/admin/services/'+id,{method:'PUT',body:JSON.stringify({...s,enabled:!s.enabled})});
      await loadState();if(view==='services'&&serviceEditor===null)renderView();toast(s.enabled?'服务已停用':'服务已启用');return;
    }
    if(action==='edit-user'){userDialog(id);return;}
    if(action==='service-secret'){await secretDialog(id);return;}
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
    if(action==='revoke-session'){
      const session=state.sessions.find(s=>s.id===id);
      confirmAction('撤销登录会话',`确认撤销 ${session.username} 在 ${session.service_name} 的此会话？`,'撤销会话',async()=>{
        await api(`/api/admin/sessions/${id}`,{method:'DELETE',body:'{}'});await loadState();renderView();toast('会话已撤销');
      });return;
    }
    if(action==='logout'){
      await api('/api/logout',{method:'POST',body:'{}'});location.href='/admin';return;
    }
  }catch(error){toast(error.message,true);if(error.status===401 && me)location.href='/admin';}
  finally{if(button.isConnected)button.disabled=false;}
});
modal.addEventListener('click',event=>{if(event.target===modal){const r=modal.getBoundingClientRect();if(event.clientX<r.left||event.clientX>r.right||event.clientY<r.top||event.clientY>r.bottom)modal.close();}});
window.addEventListener('hashchange',async()=>{
  if(!me||!state||!app.querySelector('#workspace'))return;
  readRoute();renderView();
  if(view==='audit')try{await loadState();if(view==='audit')renderView();}catch(error){toast(error.message,true);if(error.status===401)location.href='/admin';}
});
async function init() {
  if(location.pathname==='/'){await renderHome();return;}
  if(location.pathname==='/login'){await renderLogin();return;}
  try {
    const data=await api('/api/me');me=data.user;csrfToken=data.csrf;
    readRoute();await loadState();renderShell();
  }catch(error){if(error.status===401){await renderLogin(true);return;}app.innerHTML=`<div class="auth-main"><h1>暂时无法加载</h1><p class="error">${esc(error.message)}</p><a href="/admin">重新加载</a></div>`;}
}
init().catch(error=>toast(error.message,true));
let refreshingSessions=false;
setInterval(async()=>{
  if(refreshingSessions||!me||me.role!=='admin'||view!=='sessions'||document.hidden||modal.open||document.querySelector('.select-options:not([hidden])'))return;
  refreshingSessions=true;
  try{await loadState();renderView();}catch(error){if(error.status===401)location.href='/admin';}
  finally{refreshingSessions=false;}
},10000);
