import {readFileSync, writeFileSync, chmodSync} from 'node:fs';
import {randomBytes} from 'node:crypto';
import {spawnSync} from 'node:child_process';

const config = process.argv[2];
if (!config) throw new Error('Usage: node tools/init-db.mjs /path/to/mysql-admin.cnf');
const user = 'gateway_' + randomBytes(4).toString('hex');
const password = randomBytes(32).toString('hex');
const sql = `CREATE DATABASE IF NOT EXISTS gateway CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE gateway;
${readFileSync(new URL('../schema.sql', import.meta.url), 'utf8')}
CREATE USER '${user}'@'%' IDENTIFIED BY '${password}';
GRANT SELECT,INSERT,UPDATE,DELETE ON gateway.* TO '${user}'@'%';
`;
const result = spawnSync('mariadb', ['--defaults-extra-file='+config, '--connect-timeout=10'], {input:sql, encoding:'utf8'});
if (result.status !== 0) throw new Error('Database initialization failed: '+result.stderr);
const content = `DB_HOST=usw-cdb-974wtk0l.sql.tencentcdb.com
DB_PORT=21902
DB_NAME=gateway
DB_USER=${user}
DB_PASSWORD=${password}
# This TencentDB instance currently reports have_ssl=DISABLED.
DB_TLS_REQUIRED=false
GATEWAY_HOST=gateway.perfy576.com
GATEWAY_PORT=19090
GATEWAY_WEB_ROOT=/opt/gateway/web
GATEWAY_STATE_DIR=/var/lib/gateway
GATEWAY_SESSION_SECONDS=43200
GATEWAY_RESERVED_HOSTS=note.perfy576.com,agent.perfy576.com
`;
writeFileSync('.secrets/gateway.env', content, {mode:0o600, flag:'wx'});
chmodSync('.secrets/gateway.env',0o600);
console.log('Created gateway schema and a database-scoped application account. Environment file: .secrets/gateway.env');
