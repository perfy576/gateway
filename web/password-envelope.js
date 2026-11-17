'use strict';
globalThis.GatewayPasswordEncryption = {
  async encrypt(keyResponse, audience, username, context, passwords) {
    const {jwk,timestamp_ms:timestamp} = keyResponse;
    if (!globalThis.crypto?.subtle) throw new Error('当前浏览器不支持安全密码加密，请使用 HTTPS 和新版浏览器');
    if (keyResponse.audience!==audience || !Number.isSafeInteger(timestamp) || timestamp<=0 ||
        jwk?.kty!=='RSA' || jwk.alg!=='RSA-OAEP-256' || jwk.use!=='enc' || !/^[a-f0-9]{64}$/.test(jwk.kid) ||
        jwk.e!=='AQAB' || Object.keys(jwk).some(k=>!['kty','n','e','kid','alg','use'].includes(k))) {
      throw new Error('Gateway 密码公钥无效');
    }
    const bytes = new TextEncoder();
    const b64 = value => btoa(Array.from(new Uint8Array(value), c=>String.fromCharCode(c)).join('')).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
    const rsa = await crypto.subtle.importKey('jwk',{kty:jwk.kty,n:jwk.n,e:jwk.e,ext:true},{name:'RSA-OAEP',hash:'SHA-256'},false,['encrypt']);
    if (rsa.algorithm.modulusLength<3072 || rsa.algorithm.modulusLength>8192) throw new Error('Gateway 密码公钥长度无效');
    const cek = await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const header = b64(bytes.encode(JSON.stringify({alg:'RSA-OAEP-256',enc:'A256GCM',kid:jwk.kid,typ:'gateway-password+jwe'})));
    const content = bytes.encode(JSON.stringify({audience,username,context,timestamp_ms:timestamp,passwords}));
    const encrypted = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:bytes.encode(header),tagLength:128},cek,content));
    const wrapped = await crypto.subtle.encrypt({name:'RSA-OAEP'},rsa,await crypto.subtle.exportKey('raw',cek));
    return [header,b64(wrapped),b64(iv),b64(encrypted.slice(0,-16)),b64(encrypted.slice(-16))].join('.');
  },
  async protectBody(path, method, body, get, actor) {
    if (!body || typeof body!=='object' || Array.isArray(body)) return body;
    const route=new URL(path,'https://gateway.invalid');path=route.pathname;
    let username,context,passwords;
    const result={...body};
    if (path==='/login' || path==='/api/login') {
      const password=body.passwd ?? body.password;
      if (password===undefined) return body;
      username=body.username;
      context=path==='/login'?[method,path,body.appid||route.searchParams.get('appid')||'',body.token||route.searchParams.get('token')||'']:[method,path,body.mode||'',body.appid||'',body.token||body.request||''];
      passwords={password};
    } else if (path==='/api/password') {
      if (body.old_password===undefined) return body;
      username=actor || (await get('/api/me')).user.username;
      context=[method,path];passwords={old_password:body.old_password,new_password:body.new_password};
    } else if (/^\/api\/admin\/users(?:\/\d+)?$/.test(path) && (method==='POST'||method==='PUT') && body.password!==undefined) {
      delete result.password;
      if (!body.password && method==='PUT') return result;
      username=actor || (await get('/api/me')).user.username;
      context=[method,path,body.username];passwords={password:body.password};
    } else return body;
    for (const field of ['password','passwd','old_password','new_password','confirm_password']) delete result[field];
    const key=await get('/api/public/password-key');
    result.password_envelope=await this.encrypt(key,key.audience,username,context,passwords);
    return result;
  },
};
