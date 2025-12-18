#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <microhttpd.h>
#include <cjose/cjose.h>
#include <jansson.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

// 核心配置（按需修改）
#define PORT        9999
#define REDIRECT_URI "https://192.168.3.210:8443/oidc/callback"
#define PRIV_KEY    "./private.key"
#define ISSUER      "http://192.168.3.84:9999"
#define USER_ID     "user123"
#define CLIENT_ID   "incus-client"
#define EXP_SEC     3600

// 授权码结构体（简化）
typedef struct {
    char code[33];
    char nonce[64];
    time_t ctime;
} AuthCode;

static AuthCode *auth_codes = NULL;
static int ac_count = 0;

// 生成32位随机授权码
static void gen_auth_code(char *code) {
    const char cs[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    srand(time(NULL)^getpid());
    for(int i=0; i<32; i++) code[i] = cs[rand()%62];
    code[32] = '\0';
}

// 保存授权码
static void save_auth_code(const char *code, const char *nonce) {
    auth_codes = realloc(auth_codes, (ac_count+1)*sizeof(AuthCode));
    strcpy(auth_codes[ac_count].code, code);
    strcpy(auth_codes[ac_count].nonce, nonce ?: "");
    auth_codes[ac_count].ctime = time(NULL);
    ac_count++;
}

// 查找nonce
static char* find_nonce(const char *code) {
    time_t now = time(NULL);
    for(int i=0; i<ac_count; i++) {
        if(!strcmp(auth_codes[i].code, code) && (now-auth_codes[i].ctime)<=300) {
            return strdup(auth_codes[i].nonce);
        }
    }
    return NULL;
}

// 清理过期授权码
static void clean_expired() {
    time_t now = time(NULL);
    int new_cnt = 0;
    for(int i=0; i<ac_count; i++) {
        if((now-auth_codes[i].ctime)<=300) {
            if(new_cnt != i) auth_codes[new_cnt] = auth_codes[i];
            new_cnt++;
        }
    }
    ac_count = new_cnt;
    auth_codes = realloc(auth_codes, ac_count*sizeof(AuthCode));
}

// 加载RSA私钥
static EVP_PKEY* load_key() {
    FILE *fp = fopen(PRIV_KEY, "r");
    if(!fp) return NULL;
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return pkey;
}

// Base64URL编码
static char* b64url(const uint8_t *data, size_t len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_write(b64, data, len);
    BIO_flush(b64);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(mem, &bptr);
    char *buf = malloc(bptr->length+1);
    memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = 0;

    for(size_t i=0; i<bptr->length; i++) {
        if(buf[i]=='+') buf[i]='-';
        else if(buf[i]=='/') buf[i]='_';
        else if(buf[i]=='=') { buf[i]=0; break; }
    }
    BIO_free_all(b64);
    return buf;
}

// 生成JWT
static char* gen_jwt(const char *type, const char *nonce) {
    EVP_PKEY *pkey = load_key();
    if(!pkey) return NULL;

    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    const BIGNUM *n, *e, *d;
    RSA_get0_key(rsa, &n, &e, &d);

    uint8_t *nd = malloc(BN_num_bytes(n)), *ed = malloc(BN_num_bytes(e)), *dd = malloc(BN_num_bytes(d));
    BN_bn2bin(n, nd); BN_bn2bin(e, ed); BN_bn2bin(d, dd);

    cjose_jwk_rsa_keyspec spec = {
        .e=ed, .elen=BN_num_bytes(e), .n=nd, .nlen=BN_num_bytes(n),
        .d=dd, .dlen=BN_num_bytes(d), .p=NULL, .plen=0
    };

    cjose_err err;
    cjose_jwk_t *jwk = cjose_jwk_create_RSA_spec(&spec, &err);
    free(nd); free(ed); free(dd);

    time_t now = time(NULL);
    json_t *claims = json_object();
    json_object_set_new(claims, "iss", json_string(ISSUER));
    json_object_set_new(claims, "sub", json_string(USER_ID));
    json_object_set_new(claims, "aud", json_string(CLIENT_ID));
    json_object_set_new(claims, "iat", json_integer(now));
    json_object_set_new(claims, "exp", json_integer(now+EXP_SEC));

    if(!strcmp(type, "id_token")) {
        json_object_set_new(claims, "nonce", json_string(nonce));
        json_object_set_new(claims, "preferred_username", json_string(USER_ID));
    } else {
        json_object_set_new(claims, "scope", json_string("openid"));
    }

    char *payload = json_dumps(claims, JSON_COMPACT);
    cjose_header_t *hdr = cjose_header_new(&err);
    cjose_header_set(hdr, "alg", "RS256", &err);
    cjose_jws_t *jws = cjose_jws_sign(jwk, hdr, (uint8_t*)payload, strlen(payload), &err);
    
    const char *jwt_raw;
    char *jwt = cjose_jws_export(jws, &jwt_raw, &err) ? strdup(jwt_raw) : NULL;

    free(payload);
    cjose_header_release(hdr);
    cjose_jws_release(jws);
    cjose_jwk_release(jwk);
    RSA_free(rsa);
    EVP_PKEY_free(pkey);
    return jwt;
}

// 解析表单参数
static char* parse_param(const char *form, const char *key) {
    char k[64];
    snprintf(k, sizeof(k), "%s=", key);
    const char *p = strstr(form, k);
    if(!p) return NULL;
    p += strlen(k);
    const char *e = strchr(p, '&');
    if(!e) e = p + strlen(p);
    char *v = malloc(e-p+1);
    strncpy(v, p, e-p);
    v[e-p] = '\0';
    return v;
}

// 连接信息结构体
typedef struct {
    char *post;
    size_t len;
} ConnInfo;

static void free_conn(void *cls) {
    ConnInfo *info = cls;
    if(info) { free(info->post); free(info); }
}

// 处理授权请求
static enum MHD_Result handle_auth(struct MHD_Connection *conn) {
    const char *uri = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "redirect_uri");
    if(uri && strcmp(uri, REDIRECT_URI)) {
        const char *err = "{\"error\":\"invalid redirect_uri\"}";
        struct MHD_Response *r = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(r, "Content-Type", "application/json");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_BAD_REQUEST, r);
        MHD_destroy_response(r);
        return ret;
    }

    clean_expired();
    char code[33];
    gen_auth_code(code);
    const char *nonce = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "nonce");
    save_auth_code(code, nonce);

    char redirect[1024];
    const char *state = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "state");
    snprintf(redirect, sizeof(redirect), state ? "%s?code=%s&state=%s" : "%s?code=%s", REDIRECT_URI, code, state);
    
    struct MHD_Response *r = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(r, "Location", redirect);
    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_FOUND, r);
    MHD_destroy_response(r);
    return ret;
}

// 处理Token请求
static enum MHD_Result handle_token(struct MHD_Connection *conn, const char *upload, size_t *ul_len, void **cls) {
    ConnInfo *info = *cls;
    if(!info) {
        info = malloc(sizeof(ConnInfo));
        info->post = NULL;
        info->len = 0;
        *cls = info;
        return MHD_YES;
    }

    if(*ul_len > 0) {
        info->post = realloc(info->post, info->len + *ul_len + 1);
        memcpy(info->post + info->len, upload, *ul_len);
        info->len += *ul_len;
        info->post[info->len] = '\0';
        *ul_len = 0;
        return MHD_YES;
    }

    char *code = parse_param(info->post, "code");
    if(!code) goto err_invalid;

    char *nonce = find_nonce(code);
    if(!nonce) goto err_invalid_code;

    char *id_token = gen_jwt("id_token", nonce);
    char *access_token = gen_jwt("access_token", NULL);

    json_t *resp = json_object();
    json_object_set_new(resp, "access_token", json_string(access_token));
    json_object_set_new(resp, "token_type", json_string("Bearer"));
    json_object_set_new(resp, "expires_in", json_integer(EXP_SEC));
    json_object_set_new(resp, "id_token", json_string(id_token));

    char *json = json_dumps(resp, JSON_COMPACT);
    struct MHD_Response *r = MHD_create_response_from_buffer(strlen(json), json, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(r, "Content-Type", "application/json");
    MHD_queue_response(conn, MHD_HTTP_OK, r);

    MHD_destroy_response(r);
    json_decref(resp);
    free(json);
    free(code); free(nonce); free(id_token); free(access_token);
    free_conn(info);
    *cls = NULL;
    return MHD_YES;

err_invalid:
    {
        const char *err = "{\"error\":\"invalid request\"}";
        struct MHD_Response *r = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(r, "Content-Type", "application/json");
        MHD_queue_response(conn, MHD_HTTP_BAD_REQUEST, r);
        MHD_destroy_response(r);
        free(code);
        free_conn(info);
        *cls = NULL;
        return MHD_YES;
    }

err_invalid_code:
    {
        const char *err = "{\"error\":\"invalid code\"}";
        struct MHD_Response *r = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(r, "Content-Type", "application/json");
        MHD_queue_response(conn, MHD_HTTP_BAD_REQUEST, r);
        MHD_destroy_response(r);
        free(code); free(nonce);
        free_conn(info);
        *cls = NULL;
        return MHD_YES;
    }
}

// 处理发现端点
static enum MHD_Result handle_wellknown(struct MHD_Connection *conn) {
    json_t *cfg = json_object();
    json_object_set_new(cfg, "issuer", json_string(ISSUER));
    char auth_ep[256], token_ep[256], jwks_ep[256];
    snprintf(auth_ep, sizeof(auth_ep), "%s/authorize", ISSUER);
    snprintf(token_ep, sizeof(token_ep), "%s/token", ISSUER);
    snprintf(jwks_ep, sizeof(jwks_ep), "%s/jwks", ISSUER);
    json_object_set_new(cfg, "authorization_endpoint", json_string(auth_ep));
    json_object_set_new(cfg, "token_endpoint", json_string(token_ep));
    json_object_set_new(cfg, "jwks_uri", json_string(jwks_ep));
    json_object_set_new(cfg, "response_types_supported", json_pack("[s]", "code"));
    json_object_set_new(cfg, "id_token_signing_alg_values_supported", json_pack("[s]", "RS256"));

    char *json = json_dumps(cfg, JSON_COMPACT);
    struct MHD_Response *r = MHD_create_response_from_buffer(strlen(json), json, MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(r, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, r);
    MHD_destroy_response(r);
    json_decref(cfg);
    return ret;
}

// 处理JWKS端点
static enum MHD_Result handle_jwks(struct MHD_Connection *conn) {
    EVP_PKEY *pkey = load_key();
    if(!pkey) return MHD_NO;

    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    const BIGNUM *n, *e;
    RSA_get0_key(rsa, &n, &e, NULL);

    uint8_t *nd = malloc(BN_num_bytes(n)), *ed = malloc(BN_num_bytes(e));
    BN_bn2bin(n, nd); BN_bn2bin(e, ed);
    char *n64 = b64url(nd, BN_num_bytes(n));
    char *e64 = b64url(ed, BN_num_bytes(e));

    json_t *jwks = json_object();
    json_t *keys = json_array();
    json_t *key = json_object();
    json_object_set_new(key, "kty", json_string("RSA"));
    json_object_set_new(key, "alg", json_string("RS256"));
    json_object_set_new(key, "use", json_string("sig"));
    json_object_set_new(key, "n", json_string(n64));
    json_object_set_new(key, "e", json_string(e64));
    json_array_append_new(keys, key);
    json_object_set_new(jwks, "keys", keys);

    char *json = json_dumps(jwks, JSON_COMPACT);
    struct MHD_Response *r = MHD_create_response_from_buffer(strlen(json), json, MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(r, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, r);

    MHD_destroy_response(r);
    free(nd); free(ed); free(n64); free(e64);
    RSA_free(rsa); EVP_PKEY_free(pkey);
    json_decref(jwks);
    return ret;
}

// 主请求处理器
static enum MHD_Result handler(void *cls, struct MHD_Connection *conn,
                               const char *url, const char *method,
                               const char *version, const char *upload,
                               size_t *ul_len, void **con_cls) {
    // 跨域处理
    if(!strcmp(method, "OPTIONS")) {
        struct MHD_Response *r = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(r, "Access-Control-Allow-Origin", "*");
        MHD_add_response_header(r, "Access-Control-Allow-Methods", "GET,POST,OPTIONS");
        MHD_add_response_header(r, "Access-Control-Allow-Headers", "Content-Type");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, r);
        MHD_destroy_response(r);
        return ret;
    }

    // 路由
    if(!strcmp(url, "/authorize") && !strcmp(method, "GET")) {
        return handle_auth(conn);
    } else if(!strcmp(url, "/token") && !strcmp(method, "POST")) {
        return handle_token(conn, upload, ul_len, con_cls);
    } else if(!strcmp(url, "/.well-known/openid-configuration") && !strcmp(method, "GET")) {
        return handle_wellknown(conn);
    } else if(!strcmp(url, "/jwks") && !strcmp(method, "GET")) {
        return handle_jwks(conn);
    } else {
        const char *err = "{\"error\":\"not found\"}";
        struct MHD_Response *r = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(r, "Content-Type", "application/json");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_NOT_FOUND, r);
        MHD_destroy_response(r);
        return ret;
    }
}

int main() {
    OpenSSL_add_all_algorithms();
    struct MHD_Daemon *d = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, PORT,
                                            NULL, NULL, &handler, NULL,
                                            MHD_OPTION_CONNECTION_TIMEOUT, 30,
                                            MHD_OPTION_END);
    if(!d) { fprintf(stderr, "启动失败\n"); return 1; }

    printf("OIDC服务器运行在端口 %d，按回车停止...\n", PORT);
    getchar();

    MHD_stop_daemon(d);
    EVP_cleanup();
    free(auth_codes);
    return 0;
}
