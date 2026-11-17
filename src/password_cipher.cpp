#include "password_cipher.h"
#include "security.h"
#include <openssl/core_names.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <algorithm>
#include <stdexcept>
#include <vector>

namespace {
using json = nlohmann::json;
template<class T, auto Free> using Handle = std::unique_ptr<T, decltype(Free)>;
struct Secret {
    std::vector<unsigned char> bytes;
    explicit Secret(size_t size) : bytes(size) {}
    ~Secret() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
};
[[noreturn]] void invalid() { throw std::invalid_argument("Invalid encrypted password"); }
std::string decode(const std::string& value) {
    if (value.empty() || value.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")!=std::string::npos || value.size()%4==1) invalid();
    auto padded=value;
    for(auto& c:padded){if(c=='-')c='+';else if(c=='_')c='/';}
    while(padded.size()%4)padded+='=';
    std::string out(padded.size()/4*3,'\0');
    int size=EVP_DecodeBlock(reinterpret_cast<unsigned char*>(out.data()),reinterpret_cast<const unsigned char*>(padded.data()),padded.size());
    if(size<0)invalid();
    out.resize(size-(padded.back()=='=')-(padded.size()>1&&padded[padded.size()-2]=='='));
    if(base64url(out)!=value)invalid();
    return out;
}
std::shared_ptr<EVP_PKEY> load_key(const std::string& path) {
    int fd=open(path.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0 && errno==ENOENT){
        Handle<EVP_PKEY_CTX,EVP_PKEY_CTX_free> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,nullptr),EVP_PKEY_CTX_free);
        EVP_PKEY* generated=nullptr;
        if(!ctx||EVP_PKEY_keygen_init(ctx.get())<=0||EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(),3072)<=0||EVP_PKEY_keygen(ctx.get(),&generated)<=0)
            throw std::runtime_error("Cannot generate password encryption key");
        std::shared_ptr<EVP_PKEY> key(generated,EVP_PKEY_free);
        fd=open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if(fd<0)throw std::runtime_error("Cannot create password encryption key");
        Handle<BIO,BIO_free> out(BIO_new_fd(fd,BIO_NOCLOSE),BIO_free);
        bool written=out&&PEM_write_bio_PrivateKey(out.get(),key.get(),nullptr,nullptr,0,nullptr,nullptr)==1&&BIO_flush(out.get())==1&&fsync(fd)==0;
        close(fd);
        if(!written){unlink(path.c_str());throw std::runtime_error("Cannot persist password encryption key");}
        return key;
    }
    if(fd<0)throw std::runtime_error("Cannot open password encryption key");
    struct stat statbuf{};
    if(fstat(fd,&statbuf)!=0||!S_ISREG(statbuf.st_mode)||(statbuf.st_mode&0077)){
        close(fd);throw std::runtime_error("Password encryption key must be a private regular file (0600)");
    }
    Handle<BIO,BIO_free> in(BIO_new_fd(fd,BIO_CLOSE),BIO_free);
    if(!in){close(fd);throw std::runtime_error("Cannot read password encryption key");}
    std::shared_ptr<EVP_PKEY> key(PEM_read_bio_PrivateKey(in.get(),nullptr,nullptr,nullptr),EVP_PKEY_free);
    if(!key||EVP_PKEY_base_id(key.get())!=EVP_PKEY_RSA||EVP_PKEY_bits(key.get())<3072||EVP_PKEY_bits(key.get())>8192)
        throw std::runtime_error("Password encryption key must be RSA with 3072..8192 bits");
    return key;
}
std::string parameter(EVP_PKEY* key,const char* name){
    BIGNUM* value=nullptr;
    if(EVP_PKEY_get_bn_param(key,name,&value)!=1)throw std::runtime_error("Cannot export password public key");
    Handle<BIGNUM,BN_free> owned(value,BN_free);
    std::string bytes(BN_num_bytes(value),'\0');
    BN_bn2bin(value,reinterpret_cast<unsigned char*>(bytes.data()));
    return base64url(bytes);
}
}

PasswordCipher::PasswordCipher(const std::string& path) : key_(load_key(path)) {
    jwk_={{"kty","RSA"},{"n",parameter(key_.get(),OSSL_PKEY_PARAM_RSA_N)},{"e",parameter(key_.get(),OSSL_PKEY_PARAM_RSA_E)}};
    if(jwk_.at("e")!="AQAB")throw std::runtime_error("Password encryption key must use RSA exponent 65537");
    auto kid=sha256(jwk_.dump());
    jwk_.update({{"kid",kid},{"alg","RSA-OAEP-256"},{"use","enc"}});
}

nlohmann::json PasswordCipher::decrypt(const std::string& envelope,const std::string& audience,
    const std::string& username,const json& context,long long now_ms) const {
    if(envelope.empty()||envelope.size()>65536||std::count(envelope.begin(),envelope.end(),'.')!=4)invalid();
    std::vector<std::string> parts;
    size_t start=0;
    for(size_t i=0;i<5;++i){auto end=envelope.find('.',start);parts.push_back(envelope.substr(start,end-start));if(end==std::string::npos){start=envelope.size();break;}start=end+1;}
    if(parts.size()!=5||start!=envelope.size())invalid();
    auto head=json::parse(decode(parts[0]));
    if(!head.is_object()||head.size()!=4||head.value("alg","")!="RSA-OAEP-256"||head.value("enc","")!="A256GCM"||
       head.value("typ","")!="gateway-password+jwe"||head.value("kid","")!=jwk_.at("kid"))invalid();
    auto encrypted_key=decode(parts[1]),iv=decode(parts[2]),encrypted=decode(parts[3]),tag=decode(parts[4]);
    if(encrypted_key.size()!=static_cast<size_t>(EVP_PKEY_size(key_.get()))||iv.size()!=12||tag.size()!=16)invalid();
    Handle<EVP_PKEY_CTX,EVP_PKEY_CTX_free> rsa(EVP_PKEY_CTX_new(key_.get(),nullptr),EVP_PKEY_CTX_free);
    if(!rsa||EVP_PKEY_decrypt_init(rsa.get())<=0||EVP_PKEY_CTX_set_rsa_padding(rsa.get(),RSA_PKCS1_OAEP_PADDING)<=0||
       EVP_PKEY_CTX_set_rsa_oaep_md(rsa.get(),EVP_sha256())<=0||EVP_PKEY_CTX_set_rsa_mgf1_md(rsa.get(),EVP_sha256())<=0)invalid();
    Secret cek(EVP_PKEY_size(key_.get()));size_t key_size=cek.bytes.size();
    if(EVP_PKEY_decrypt(rsa.get(),cek.bytes.data(),&key_size,reinterpret_cast<const unsigned char*>(encrypted_key.data()),encrypted_key.size())<=0||key_size!=32)invalid();
    Handle<EVP_CIPHER_CTX,EVP_CIPHER_CTX_free> aes(EVP_CIPHER_CTX_new(),EVP_CIPHER_CTX_free);
    Secret plaintext(encrypted.size()+16);int length=0,total=0;
    if(!aes||EVP_DecryptInit_ex(aes.get(),EVP_aes_256_gcm(),nullptr,cek.bytes.data(),reinterpret_cast<const unsigned char*>(iv.data()))!=1||
       EVP_DecryptUpdate(aes.get(),nullptr,&length,reinterpret_cast<const unsigned char*>(parts[0].data()),parts[0].size())!=1||
       EVP_DecryptUpdate(aes.get(),plaintext.bytes.data(),&length,reinterpret_cast<const unsigned char*>(encrypted.data()),encrypted.size())!=1)invalid();
    total=length;
    if(EVP_CIPHER_CTX_ctrl(aes.get(),EVP_CTRL_GCM_SET_TAG,tag.size(),tag.data())!=1||EVP_DecryptFinal_ex(aes.get(),plaintext.bytes.data()+total,&length)!=1)invalid();
    auto data=json::parse(plaintext.bytes.begin(),plaintext.bytes.begin()+total+length);
    if(!data.is_object()||data.size()!=5||data.value("audience","")!=audience||data.value("username","")!=username||
       data.at("context")!=context||!data.at("timestamp_ms").is_number_integer()||!data.at("passwords").is_object())invalid();
    auto timestamp=data.at("timestamp_ms").get<long long>();
    if(timestamp<now_ms-120000||timestamp>now_ms+30000)invalid();
    return data;
}
