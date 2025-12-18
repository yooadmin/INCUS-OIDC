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
#include <openssl/core_names.h>

// 核心配置（按需修改）
#define PORT        9999
#define REDIRECT_URI "https://192.168.3.210:8443/oidc/callback"
#define PRIV_KEY    "./private.key"
#define ISSUER      "http://192.168.3.84:9999"
#define USER_ID     "user123"
#define CLIENT_ID   "incus-client"
#define EXP_SEC     3600
#define AUTH_CODE_EXPIRE 300  // 授权码过期时间（秒）

// 授权码结构体（简化）
typedef struct {
    char code[33];
    char nonce[64];
    time_t ctime;
} AuthCode;

static AuthCode *auth_codes = NULL;
static int ac_count = 0;

// 工具函数：生成32位随机授权码
static void gen_auth_code(char *code) {
    const char cs[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    static int seed_inited = 0;
    if (!seed_inited) { srand(time(NULL)^getpid()); seed_inited = 1; }
    for(int i=0; i<32; i++) code[i] = cs[rand()%62];
    code[32] = '\0';
}

// 工具函数：清理过期授权码（内联调用）
static void clean_expired_auth_codes() {
    time_t now = time(NULL);
    int new_cnt = 0;
    for(int i=0; i<ac_count; i++) {
        if((now - auth_codes[i].ctime) <= AUTH_CODE_EXPIRE) {
            if(new_cnt != i) auth_codes[new_cnt] = auth_codes[i];
            new_cnt++;
        }
    }
    ac_count = new_cnt;
    auth_codes = realloc(auth_codes, ac_count * sizeof(AuthCode));
}

// 工具函数：加载RSA私钥（适配OpenSSL 3.0+）
static EVP_PKEY* load_rsa_priv_key() {
    FILE *fp = fopen(PRIV_KEY, "r");
    if(!fp) return NULL;
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return pkey;
}

// 工具函数：从EVP_PKEY提取RSA参数（适配OpenSSL 3.0+）
static int get_rsa_params(EVP_PKEY *pkey, BIGNUM **n, BIGNUM **e, BIGNUM **d) {
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, n) != 1) return 0;
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, e) != 1) return 0;
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, d) != 1) return 0;
    return 1;
}

// 工具函数：Base64URL编码（简化逻辑）
static char* base64url_encode(const uint8_t *data, size_t len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_write(b64, data, len);
    BIO_flush(b64);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(mem, &bptr);
    char *buf = malloc(bptr->length + 1);
    memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = '\0';

    // Base64URL转换
    char *p = buf;
    while (*p) {
        if (*p == '+') *p = '-';
        else if (*p == '/') *p = '_';
        else if (*p == '=') { *p = '\0'; break; }
        p++;
    }

    BIO_free_all(b64);
    return buf;
}

// 工具函数：生成JWT（合并ID/Access Token逻辑，适配OpenSSL 3.0+）
static char* generate_jwt(const char *nonce) {
    EVP_PKEY *pkey = load_rsa_priv_key();
    if(!pkey) return NULL;

    // 提取RSA参数（OpenSSL 3.0+ 新接口）
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    if (!get_rsa_params(pkey, &n, &e, &d)) {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    // 转换BIGNUM到二进制数组
    int n_len = BN_num_bytes(n);
    int e_len = BN_num_bytes(e);
    int d_len = BN_num_bytes(d);
    uint8_t *n_bin = malloc(n_len);
    uint8_t *e_bin = malloc(e_len);
    uint8_t *d_bin = malloc(d_len);
    BN_bn2bin(n, n_bin);
    BN_bn2bin(e, e_bin);
    BN_bn2bin(d, d_bin);

    // 构建CJOSE的RSA密钥规格
    cjose_jwk_rsa_keyspec spec = {
        .e = e_bin, .elen = e_len,
        .n = n_bin, .nlen = n_len,
        .d = d_bin, .dlen = d_len,
        .p = NULL, .plen = 0
    };

    cjose_err err;
    cjose_jwk_t *jwk = cjose_jwk_create_RSA_spec(&spec, &err);
    
    // 释放临时二进制数组
    free(n_bin);
    free(e_bin);
    free(d_bin);
    BN_free(n);
    BN_free(e);
    BN_free(d);

    if (!jwk) {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    // 构建Claims
    time_t now = time(NULL);
    json_t *claims = json_pack("{s:s, s:s, s:s, s:i, s:i}",
        "iss", ISSUER, "sub", USER_ID, "aud", CLIENT_ID,
        "iat", (json_int_t)now, "exp", (json_int_t)(now + EXP_SEC));
    
    if (nonce) {  // ID Token包含nonce和用户名
        json_object_set_new(claims, "nonce", json_string(nonce));
        json_object_set_new(claims, "preferred_username", json_string(USER_ID));
    } else {      // Access Token包含scope
        json_object_set_new(claims, "scope", json_string("openid"));
    }

    char *payload = json_dumps(claims, JSON_COMPACT);
    cjose_header_t *hdr = cjose_header_new(&err);
    cjose_header_set(hdr, "alg", "RS256", &err);
    cjose_jws_t *jws = cjose_jws_sign(jwk, hdr, (uint8_t*)payload, strlen(payload), &err);
    
    const char *jwt_raw;
    char *jwt = cjose_jws_export(jws, &jwt_raw, &err) ? strdup(jwt_raw) : NULL;

    // 资源释放
    free(payload);
    cjose_header_release(hdr);
    cjose_jws_release(jws);
    cjose_jwk_release(jwk);
    EVP_PKEY_free(pkey);
    json_decref(claims);

    return jwt;
}

// 工具函数：解析POST参数（简化）
static char* parse_form_param(const char *form, const char *key) {
    if (!form || !key) return NULL;
    char *k = malloc(strlen(key) + 2);
    sprintf(k, "%s=", key);
    const char *p = strstr(form, k);
    free(k);
    if(!p) return NULL;

    p += strlen(key) + 1;
    const char *e = strchr(p, '&');
    if(!e) e = p + strlen(p);
    char *v = malloc(e - p + 1);
    strncpy(v, p, e - p);
    v[e - p] = '\0';
    return v;
}

// 工具函数：快速构建JSON响应
static enum MHD_Result send_json_response(struct MHD_Connection *conn, int status, const char *json) {
    struct MHD_Response *r = MHD_create_response_from_buffer(strlen(json), (void*)json, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(r, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(conn, status, r);
    MHD_destroy_response(r);
    return ret;
}

// 连接信息结构体（简化）
typedef struct {
    char *post_data;
    size_t len;
} ConnData;

// 资源释放函数（统一）
static void free_conn_data(void *cls) {
    ConnData *data = cls;
    if (data) { free(data->post_data); free(data); }
}

// 处理授权请求（/authorize）
static enum MHD_Result handle_authorize(struct MHD_Connection *conn) {
    // 校验redirect_uri
    const char *uri = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "redirect_uri");
    if(uri && strcmp(uri, REDIRECT_URI)) {
        return send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"invalid redirect_uri\"}");
    }

    // 生成并保存授权码
    clean_expired_auth_codes();
    char code[33];
    gen_auth_code(code);
    const char *nonce = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "nonce");
    
    auth_codes = realloc(auth_codes, (ac_count+1)*sizeof(AuthCode));
    strcpy(auth_codes[ac_count].code, code);
    strcpy(auth_codes[ac_count].nonce, nonce ?: "");
    auth_codes[ac_count].ctime = time(NULL);
    ac_count++;

    // 构建重定向URL
    char redirect[1024];
    const char *state = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "state");
    snprintf(redirect, sizeof(redirect), 
             state ? "%s?code=%s&state=%s" : "%s?code=%s", 
             REDIRECT_URI, code, state);
    
    struct MHD_Response *r = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(r, "Location", redirect);
    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_FOUND, r);
    MHD_destroy_response(r);
    return ret;
}

// 处理Token请求（/token）
static enum MHD_Result handle_token(struct MHD_Connection *conn, const char *upload, size_t *ul_len, void **con_cls) {
    ConnData *data = *con_cls;
    if(!data) {
        data = calloc(1, sizeof(ConnData));  // 初始化为0
        *con_cls = data;
        return MHD_YES;
    }

    // 接收POST数据
    if(*ul_len > 0) {
        data->post_data = realloc(data->post_data, data->len + *ul_len + 1);
        memcpy(data->post_data + data->len, upload, *ul_len);
        data->len += *ul_len;
        data->post_data[data->len] = '\0';
        *ul_len = 0;
        return MHD_YES;
    }

    // 解析授权码
    char *code = parse_form_param(data->post_data, "code");
    if(!code) {
        free_conn_data(data);
        *con_cls = NULL;
        return send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"invalid request\"}");
    }

    // 查找nonce并校验授权码
    char *nonce = NULL;
    time_t now = time(NULL);
    for(int i=0; i<ac_count; i++) {
        if(!strcmp(auth_codes[i].code, code) && (now - auth_codes[i].ctime) <= AUTH_CODE_EXPIRE) {
            nonce = strdup(auth_codes[i].nonce);
            break;
        }
    }
    free(code);

    if(!nonce) {
        free_conn_data(data);
        *con_cls = NULL;
        return send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"invalid code\"}");
    }

    // 生成Token
    char *id_token = generate_jwt(nonce);
    char *access_token = generate_jwt(NULL);
    if (!id_token || !access_token) {
        free(nonce); free(id_token); free(access_token);
        free_conn_data(data);
        *con_cls = NULL;
        return send_json_response(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"token generate failed\"}");
    }

    // 构建响应
    char resp[2048];
    snprintf(resp, sizeof(resp), 
             "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":%d,\"id_token\":\"%s\"}",
             access_token, EXP_SEC, id_token);
    
    enum MHD_Result ret = send_json_response(conn, MHD_HTTP_OK, resp);
    
    // 资源释放
    free(nonce); free(id_token); free(access_token);
    free_conn_data(data);
    *con_cls = NULL;
    return ret;
}

// 处理OIDC发现端点
static enum MHD_Result handle_wellknown(struct MHD_Connection *conn) {
    char auth_ep[256], token_ep[256], jwks_ep[256];
    snprintf(auth_ep, sizeof(auth_ep), "%s/authorize", ISSUER);
    snprintf(token_ep, sizeof(token_ep), "%s/token", ISSUER);
    snprintf(jwks_ep, sizeof(jwks_ep), "%s/jwks", ISSUER);

    char resp[1024];
    snprintf(resp, sizeof(resp),
             "{\"issuer\":\"%s\",\"authorization_endpoint\":\"%s\",\"token_endpoint\":\"%s\",\"jwks_uri\":\"%s\",\"response_types_supported\":[\"code\"],\"id_token_signing_alg_values_supported\":[\"RS256\"]}",
             ISSUER, auth_ep, token_ep, jwks_ep);
    
    return send_json_response(conn, MHD_HTTP_OK, resp);
}

// 处理JWKS端点（适配OpenSSL 3.0+）
static enum MHD_Result handle_jwks(struct MHD_Connection *conn) {
    EVP_PKEY *pkey = load_rsa_priv_key();
    if(!pkey) return send_json_response(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"load key failed\"}");

    // 提取RSA公钥参数（n和e）
    BIGNUM *n = NULL, *e = NULL;
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) ||
        !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e)) {
        EVP_PKEY_free(pkey);
        return send_json_response(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"get rsa params failed\"}");
    }

    // 转换为二进制并Base64URL编码
    int n_len = BN_num_bytes(n);
    int e_len = BN_num_bytes(e);
    uint8_t *n_bin = malloc(n_len);
    uint8_t *e_bin = malloc(e_len);
    BN_bn2bin(n, n_bin);
    BN_bn2bin(e, e_bin);

    char *n64 = base64url_encode(n_bin, n_len);
    char *e64 = base64url_encode(e_bin, e_len);

    // 构建JWKS响应
    char jwks[1024];
    snprintf(jwks, sizeof(jwks),
             "{\"keys\":[{\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"%s\",\"e\":\"%s\"}]}",
             n64, e64);
    
    enum MHD_Result ret = send_json_response(conn, MHD_HTTP_OK, jwks);

    // 释放资源
    free(n_bin);
    free(e_bin);
    free(n64);
    free(e64);
    BN_free(n);
    BN_free(e);
    EVP_PKEY_free(pkey);
    return ret;
}

// 主请求处理器（路由简化）
static enum MHD_Result request_handler(void *cls, struct MHD_Connection *conn,
                               const char *url, const char *method,
                               const char *version, const char *upload,
                               size_t *ul_len, void **con_cls) {
    // OPTIONS跨域处理
    if(!strcmp(method, "OPTIONS")) {
        struct MHD_Response *r = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(r, "Access-Control-Allow-Origin", "*");
        MHD_add_response_header(r, "Access-Control-Allow-Methods", "GET,POST,OPTIONS");
        MHD_add_response_header(r, "Access-Control-Allow-Headers", "Content-Type");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, r);
        MHD_destroy_response(r);
        return ret;
    }

    // 路由分发
    if(!strcmp(url, "/authorize") && !strcmp(method, "GET")) {
        return handle_authorize(conn);
    } else if(!strcmp(url, "/token") && !strcmp(method, "POST")) {
        return handle_token(conn, upload, ul_len, con_cls);
    } else if(!strcmp(url, "/.well-known/openid-configuration") && !strcmp(method, "GET")) {
        return handle_wellknown(conn);
    } else if(!strcmp(url, "/jwks") && !strcmp(method, "GET")) {
        return handle_jwks(conn);
    }

    // 404响应
    return send_json_response(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"not found\"}");
}

int main() {
    // OpenSSL 3.0+ 初始化
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    OpenSSL_add_all_algorithms();

    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_SELECT_INTERNALLY, PORT,
        NULL, NULL, &request_handler, NULL,
        MHD_OPTION_CONNECTION_TIMEOUT, 30,
        MHD_OPTION_END
    );

    if(!daemon) { fprintf(stderr, "服务器启动失败\n"); return 1; }
    printf("OIDC服务器运行在端口 %d（按回车停止）\n", PORT);
    getchar();

    // 清理资源
    MHD_stop_daemon(daemon);
    EVP_cleanup();
    free(auth_codes);
    return 0;
}
