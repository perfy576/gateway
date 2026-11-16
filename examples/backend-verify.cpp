#include "gateway_identity.h"
#include <cstdlib>
#include <iostream>

int main(int argc, char **argv) {
    if (argc!=5 || !std::getenv("GATEWAY_TOKEN_SECRET")) {
        std::cerr<<"Usage: GATEWAY_TOKEN_SECRET=<secret> backend-verify <issuer> <audience> <method> <original-uri> < token-and-cookie.txt\n";
        return 2;
    }
    try {
        GatewayVerifier verifier(std::getenv("GATEWAY_TOKEN_SECRET"),argv[1],argv[2]);
        std::string token,cookies; std::getline(std::cin,token);std::getline(std::cin,cookies);
        auto identity=verifier.verify(token,argv[3],argv[4],cookies);
        std::cout<<"authenticated="<<identity.authenticated<<" user_id="<<identity.user_id
            <<" username="<<identity.username<<" role="<<identity.role<<'\n';
    } catch (const std::exception& e) { std::cerr<<"Rejected: "<<e.what()<<'\n'; return 1; }
}
