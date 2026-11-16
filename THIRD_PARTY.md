# Third-Party Components

| Component | Version | License | Source |
| --- | --- | --- | --- |
| Workflow | 0.11.11 | Apache-2.0 | https://github.com/sogou/workflow |
| jwt-cpp | 0.7.1 | MIT | https://github.com/Thalhammer/jwt-cpp |
| nlohmann/json | system 3.11.3 | MIT | https://github.com/nlohmann/json |
| OpenSSL | system 3.0.13 + Ubuntu security updates | Apache-2.0 | https://openssl.org |
| MariaDB Connector/C | system package | LGPL-2.1 | https://mariadb.com |
| Lucide | 0.468.0 | ISC | https://github.com/lucide-icons/lucide |

The bundled `web/lucide.min.js` retains its license header. Its full license is in `web/lucide.LICENSE`. System libraries and source dependencies retain their upstream licenses.

The independent SDK workspace `/data/code/gateway-sdk` additionally uses PyJWT (MIT) in Python and libcurl (curl license) in C++. These are declared as dependencies, not copied into the application source.
