#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;
using json = nlohmann::json;
using namespace std::chrono;

static long long now_ms() { return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count(); }
static std::string uuid() {
    unsigned char b[16]; RAND_bytes(b, sizeof(b)); b[6]=(b[6]&0x0f)|0x40; b[8]=(b[8]&0x3f)|0x80;
    std::ostringstream o; o<<std::hex<<std::setfill('0');
    for(int i=0;i<16;i++){ o<<std::setw(2)<<static_cast<int>(b[i]); if(i==3||i==5||i==7||i==9)o<<'-'; }
    return o.str();
}
static std::string b64(const unsigned char* data, size_t n) {
    std::string out(4*((n+2)/3),'\0'); int len=EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()),data,static_cast<int>(n)); out.resize(len); return out;
}
static std::vector<unsigned char> unb64(const std::string& s) {
    std::vector<unsigned char> out(3*(s.size()/4)+3); int n=EVP_DecodeBlock(out.data(),reinterpret_cast<const unsigned char*>(s.data()),static_cast<int>(s.size()));
    if(n<0) throw std::runtime_error("bad_base64"); size_t padding=0; while(padding<s.size()&&s[s.size()-1-padding]=='=')++padding; n-=static_cast<int>(padding); out.resize(std::max(0,n)); return out;
}
static std::string sha256(const std::string& s) { unsigned char hash[SHA256_DIGEST_LENGTH]; SHA256(reinterpret_cast<const unsigned char*>(s.data()),s.size(),hash); std::ostringstream o; o<<std::hex<<std::setfill('0'); for(auto c:hash)o<<std::setw(2)<<static_cast<int>(c); return o.str(); }

struct Account { std::string vpa,name; double balance; };
struct Packet { std::string id,cipher; int ttl=5; long long created=0; };
struct Device { std::string id; bool internet=false; std::map<std::string,Packet> packets; };
struct Tx { long long id; std::string sender,receiver,status,bridge,hash; double amount; int hops; long long settled,signedAt; };

class App {
    EVP_PKEY* key=nullptr;
    std::vector<Account> accounts{{"alice@demo","Alice",5000},{"bob@demo","Bob",1000},{"carol@demo","Carol",2500},{"dave@demo","Dave",500}};
    std::vector<Device> devices{{"phone-alice",false,{}},{"phone-stranger1",false,{}},{"phone-stranger2",false,{}},{"phone-stranger3",false,{}},{"phone-bridge",true,{}}};
    std::vector<Tx> txs; std::set<std::string> seen; long long nextTx=1;
    std::string publicPem;
    Account* account(const std::string& id) { for(auto& a:accounts)if(a.vpa==id)return &a; return nullptr; }
    std::string encrypt(const json& payload) {
        unsigned char aes[32],iv[12]; if(RAND_bytes(aes,sizeof(aes))!=1||RAND_bytes(iv,sizeof(iv))!=1)throw std::runtime_error("crypto_random_failure");
        const std::string cleartext=payload.dump(); EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new(); std::vector<unsigned char> cipher(cleartext.size()+16); int n=0,total=0;
        EVP_EncryptInit_ex(ctx,EVP_aes_256_gcm(),nullptr,nullptr,nullptr); EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_IVLEN,sizeof(iv),nullptr); EVP_EncryptInit_ex(ctx,nullptr,nullptr,aes,iv);
        EVP_EncryptUpdate(ctx,cipher.data(),&n,reinterpret_cast<const unsigned char*>(cleartext.data()),static_cast<int>(cleartext.size())); total=n; EVP_EncryptFinal_ex(ctx,cipher.data()+total,&n); total+=n; unsigned char tag[16]; EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_GET_TAG,sizeof(tag),tag); EVP_CIPHER_CTX_free(ctx); cipher.resize(total);
        EVP_PKEY_CTX* pctx=EVP_PKEY_CTX_new(key,nullptr); EVP_PKEY_encrypt_init(pctx); EVP_PKEY_CTX_set_rsa_padding(pctx,RSA_PKCS1_OAEP_PADDING); EVP_PKEY_CTX_set_rsa_oaep_md(pctx,EVP_sha256()); size_t keylen=0; EVP_PKEY_encrypt(pctx,nullptr,&keylen,aes,sizeof(aes)); std::vector<unsigned char> wrapped(keylen); EVP_PKEY_encrypt(pctx,wrapped.data(),&keylen,aes,sizeof(aes)); wrapped.resize(keylen); EVP_PKEY_CTX_free(pctx);
        std::vector<unsigned char> blob=wrapped; blob.insert(blob.end(),iv,iv+sizeof(iv)); blob.insert(blob.end(),tag,tag+sizeof(tag)); blob.insert(blob.end(),cipher.begin(),cipher.end()); return b64(blob.data(),blob.size());
    }
    json decrypt(const std::string& encoded) {
        auto blob=unb64(encoded); EVP_PKEY_CTX* pctx=EVP_PKEY_CTX_new(key,nullptr); EVP_PKEY_decrypt_init(pctx); EVP_PKEY_CTX_set_rsa_padding(pctx,RSA_PKCS1_OAEP_PADDING); EVP_PKEY_CTX_set_rsa_oaep_md(pctx,EVP_sha256()); size_t klen=0;
        if(EVP_PKEY_decrypt(pctx,nullptr,&klen,blob.data(),EVP_PKEY_get_size(key))<=0){EVP_PKEY_CTX_free(pctx);throw std::runtime_error("decryption_failed");} std::vector<unsigned char> aes(klen);
        if(blob.size()<EVP_PKEY_get_size(key)+28||EVP_PKEY_decrypt(pctx,aes.data(),&klen,blob.data(),EVP_PKEY_get_size(key))<=0){EVP_PKEY_CTX_free(pctx);throw std::runtime_error("decryption_failed");} EVP_PKEY_CTX_free(pctx);
        size_t offset=EVP_PKEY_get_size(key); const unsigned char* iv=blob.data()+offset; const unsigned char* tag=iv+12; const unsigned char* ciphertext=tag+16; int clen=static_cast<int>(blob.size()-offset-28);
        EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new(); std::vector<unsigned char> plain(clen+1); int n=0,total=0;
        EVP_DecryptInit_ex(ctx,EVP_aes_256_gcm(),nullptr,nullptr,nullptr); EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_IVLEN,12,nullptr); EVP_DecryptInit_ex(ctx,nullptr,nullptr,aes.data(),iv); EVP_DecryptUpdate(ctx,plain.data(),&n,ciphertext,clen); total=n; EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_TAG,16,const_cast<unsigned char*>(tag)); int ok=EVP_DecryptFinal_ex(ctx,plain.data()+total,&n); EVP_CIPHER_CTX_free(ctx); if(ok<=0)throw std::runtime_error("decryption_failed"); plain.resize(total+n); return json::parse(plain.begin(),plain.end());
    }
    json ingest(const Packet& p,const std::string& bridge,int hops) {
        std::string hash=sha256(p.cipher); if(seen.count(hash)) return {{"outcome","DUPLICATE_DROPPED"},{"packetHash",hash},{"reason",nullptr},{"transactionId",nullptr}}; seen.insert(hash);
        json ins; try {ins=decrypt(p.cipher);}catch(...){return {{"outcome","INVALID"},{"packetHash",hash},{"reason","decryption_failed"},{"transactionId",nullptr}};}
        long long signedAt=ins.value("signedAt",0LL), age=(now_ms()-signedAt)/1000;
        if(age>86400||age < -300)return {{"outcome","INVALID"},{"packetHash",hash},{"reason",age>86400?"stale_packet":"future_dated"},{"transactionId",nullptr}};
        std::string from=ins.value("senderVpa",""),to=ins.value("receiverVpa",""); double amount=ins.value("amount",0.0); Account* a=account(from); Account* b=account(to);
        if(!a||!b||amount<=0)return {{"outcome","INVALID"},{"packetHash",hash},{"reason","invalid_payment"},{"transactionId",nullptr}};
        std::string status="SETTLED"; if(a->balance<amount)status="REJECTED"; else {a->balance-=amount;b->balance+=amount;}
        long long id=nextTx++; txs.push_back({id,from,to,status,bridge,hash,amount,hops,now_ms(),signedAt});
        return {{"outcome",status},{"packetHash",hash},{"reason",nullptr},{"transactionId",id}};
    }
    json do_request(const std::string& method,const std::string& target,const std::string& body,const http::request<http::string_body>& req) {
        if(target=="/"&&method=="GET"){std::ifstream f("/app/public/index.html");if(!f)f.open("public/index.html");std::ostringstream s;s<<f.rdbuf();return json{{"__html",s.str()}};}
        if(target=="/api/server-key"&&method=="GET")return {{"publicKey",publicPem},{"algorithm","RSA-2048 / OAEP-SHA256"},{"hybridScheme","RSA-OAEP encrypts an AES-256-GCM session key"}};
        if(target=="/api/accounts"&&method=="GET"){json out=json::array();for(auto&a:accounts)out.push_back({{"vpa",a.vpa},{"holderName",a.name},{"balance",a.balance}});return out;}
        if(target=="/api/transactions"&&method=="GET"){json out=json::array();for(auto it=txs.rbegin();it!=txs.rend()&&out.size()<20;++it)out.push_back({{"id",it->id},{"senderVpa",it->sender},{"receiverVpa",it->receiver},{"amount",it->amount},{"status",it->status},{"bridgeNodeId",it->bridge},{"hopCount",it->hops},{"settledAt",it->settled}});return out;}
        if(target=="/api/mesh/state"&&method=="GET"){json ds=json::array();for(auto&d:devices){json ids=json::array();for(auto&kv:d.packets)ids.push_back(kv.first.substr(0,8));ds.push_back({{"deviceId",d.id},{"hasInternet",d.internet},{"packetCount",d.packets.size()},{"packetIds",ids}});}return {{"devices",ds},{"idempotencyCacheSize",seen.size()}};}
        if(target=="/api/demo/send"&&method=="POST"){json j=json::parse(body); std::string from=j.value("senderVpa",""),to=j.value("receiverVpa",""); double amount=j.value("amount",0.0); int ttl=j.value("ttl",5); std::string pin=j.value("pin",""); if(!account(from)||!account(to)||from==to||amount<=0||pin.size()<4)return {{"error","invalid_payment_request"}};
            json instr={{"senderVpa",from},{"receiverVpa",to},{"amount",amount},{"pinHash",sha256(pin)},{"nonce",uuid()},{"signedAt",now_ms()}}; Packet p{uuid(),encrypt(instr),ttl,now_ms()};std::string start=j.value("startDevice","phone-alice");auto d=std::find_if(devices.begin(),devices.end(),[&](auto&x){return x.id==start;});if(d==devices.end())return {{"error","unknown_device"}};d->packets[p.id]=p;return {{"packetId",p.id},{"ciphertextPreview",p.cipher.substr(0,64)+"..."},{"ttl",p.ttl},{"injectedAt",start}};}
        if(target=="/api/mesh/gossip"&&method=="POST"){std::vector<std::pair<size_t,Packet>> snapshot;for(size_t i=0;i<devices.size();++i)for(auto&kv:devices[i].packets)snapshot.push_back({i,kv.second});int transfers=0;for(auto&entry:snapshot){auto p=entry.second;if(p.ttl<=0)continue;for(size_t i=0;i<devices.size();++i){if(i==entry.first||devices[i].packets.count(p.id))continue;Packet copy=p;copy.ttl--;devices[i].packets[p.id]=copy;transfers++;}}json counts=json::object();for(auto&d:devices)counts[d.id]=d.packets.size();return {{"transfers",transfers},{"deviceCounts",counts}};}
        if(target=="/api/mesh/flush"&&method=="POST"){json results=json::array();int count=0;for(auto&d:devices)if(d.internet)for(auto&kv:d.packets){auto p=kv.second;results.push_back({{"bridgeNode",d.id},{"packetId",p.id.substr(0,8)},{"outcome",ingest(p,d.id,5-p.ttl).at("outcome")},{"reason",""},{"transactionId",nullptr}});count++;}return {{"uploadsAttempted",count},{"results",results}};}
        if(target=="/api/mesh/reset"&&method=="POST"){for(auto&d:devices)d.packets.clear();seen.clear();return {{"status","mesh and idempotency cache cleared"}};}
        if(target=="/api/bridge/ingest"&&method=="POST"){json j=json::parse(body);Packet p{j.value("packetId",""),j.value("ciphertext",""),j.value("ttl",0),j.value("createdAt",0LL)};return ingest(p,req["X-Bridge-Node-Id"].empty()?"unknown":std::string(req["X-Bridge-Node-Id"]),req["X-Hop-Count"].empty()?0:std::stoi(std::string(req["X-Hop-Count"])));}
        return {{"error","not_found"}};
    }
public:
    App(){EVP_PKEY_CTX* c=EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,nullptr);EVP_PKEY_keygen_init(c);EVP_PKEY_CTX_set_rsa_keygen_bits(c,2048);EVP_PKEY_keygen(c,&key);EVP_PKEY_CTX_free(c);BIO* b=BIO_new(BIO_s_mem());PEM_write_bio_PUBKEY(b,key);char* data=nullptr;long n=BIO_get_mem_data(b,&data);publicPem=b64(reinterpret_cast<unsigned char*>(data),static_cast<size_t>(n));BIO_free(b);}
    ~App(){if(key)EVP_PKEY_free(key);}
    http::response<http::string_body> handle(const http::request<http::string_body>& req){http::response<http::string_body> res;res.version(req.version());res.keep_alive(false);res.set(http::field::server,"upi-mesh-cpp");auto target=std::string(req.target());try{json out=do_request(std::string(req.method_string()),target,req.body(),req);if(out.is_object()&&out.contains("__html")){res.result(http::status::ok);res.set(http::field::content_type,"text/html; charset=utf-8");res.body()=out["__html"].get<std::string>();}else{res.result(target=="/api/unknown"?http::status::not_found:http::status::ok);res.set(http::field::content_type,"application/json");res.body()=out.dump();}}catch(const std::exception&e){res.result(http::status::bad_request);res.set(http::field::content_type,"application/json");res.body()=json{{"error",e.what()}}.dump();}res.prepare_payload();return res;}
};

int main(){try{unsigned short port=8080;if(const char* p=std::getenv("PORT"))port=static_cast<unsigned short>(std::stoi(p));net::io_context ioc{1};tcp::acceptor acceptor{ioc,{net::ip::make_address("0.0.0.0"),port}};App app;std::cout<<"UPI mesh C++ server listening on 0.0.0.0:"<<port<<std::endl;for(;;){tcp::socket socket{ioc};acceptor.accept(socket);beast::flat_buffer buffer;http::request<http::string_body> req;beast::error_code ec;http::read(socket,buffer,req,ec);if(!ec){auto res=app.handle(req);http::write(socket,res,ec);}socket.shutdown(tcp::socket::shutdown_send,ec);}}catch(const std::exception&e){std::cerr<<"fatal: "<<e.what()<<std::endl;return 1;}return 0;}
