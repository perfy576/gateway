import {webcrypto} from 'node:crypto';
import '../web/password-envelope.js';

if (!globalThis.crypto) globalThis.crypto=webcrypto;
export const encryptPasswordEnvelope=(...args)=>globalThis.GatewayPasswordEncryption.encrypt(...args);
export const protectPasswordBody=(...args)=>globalThis.GatewayPasswordEncryption.protectBody(...args);
