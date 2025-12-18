#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <microhttpd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/core_names.h>  // 必须包含：OpenSSL 3.0 参数宏定义

// 核心配置（按需修改）
#define PORT        9999
#define REDIRECT_URI "https://192.168.3.210:8443/oidc/callback"
#define PRIV_KEY    "./private.key"
#define ISSUER      "http://192.168.3.84:9999"
#define USER_ID     "user123"
#define CLIENT_ID   "incus-client"
#define EXP_SEC     3600
#define AUTH_CODE_EXPIRE 300  // 授权码过期时间（秒）

// 授权码结构体
typedef struct {
    char code[33];   // 32位授权码
    char nonce[64];  // 随机数
    time_t ctime;    // 创建时间
} AuthCode;

static AuthCode *auth_codes = NULL;
static int ac_count = 0;

// ===================== 基础工具函数 =====================
// 生成32位随机授权码
static void gen_auth_code(char *code) {
    const char cs[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    static int seed_inited = 0;
    if (!seed_inited) { srand(time(NULL)^getpid()); seed_inited = 1; }
    for(int i=0; i<32; i++) code[i] = cs[rand()%62];
    code[32] = '\0';
}

// 清理过期授权码
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

// Base64URL编码（JWT专用）
static char* base64url_encode(const unsigned char *data, size_t len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // 不换行
    BIO *mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    
    BIO_write(b64, data, len);
    BIO_flush(b64);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(mem, &bptr);
    char *buf = malloc(bptr->length + 1);
    memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = '\0';

    // Base64 → Base64URL转换
    char *p = buf;
    while (*p) {
        if (*p == '+') *p = '-';
        else if (*p == '/') *p = '_';
        else if (*p == '=') { *p = '\0'; break; } // 移除填充
        p++;
    }

    BIO_free_all(b64);
    return buf;
}

// 加载RSA私钥（OpenSSL 3.0+兼容）
static EVP_PKEY* load_rsa_priv_key() {
    FILE *fp = fopen(PRIV_KEY, "r");
    if(!fp) { perror("fopen private.key"); return NULL; }
    
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if(!pkey) { ERR_print_errors_fp(stderr); }
    return pkey;
}

// RSA-SHA256签名（生成JWT签名部分）
static char* rsa_sign(const char *data, EVP_PKEY *pkey) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(!ctx) return NULL;

    if(EVP_SignInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
       EVP_SignUpdate(ctx, data, strlen(data)) != 1) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    unsigned int sig_len;
    unsigned char sig[4096];
    if(EVP_SignFinal(ctx, sig, &sig_len, pkey) != 1) {
        EVP_MD_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    EVP_MD_CTX_free(ctx);

    // 签名结果Base64URL编码
    return base64url_encode(sig, sig_len);
}

// 生成JWT（ID Token/Access Token）
static char* generate_jwt(const char *nonce) {
    EVP_PKEY *pkey = load_rsa_priv_key();
    if(!pkey) return NULL;

    // 1. JWT Header（固定RS256）
    char header[] = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
    char *hdr_b64 = base64url_encode((unsigned char*)header, strlen(header));

    // 2. JWT Payload
    time_t now = time(NULL);
    char payload[512];
    if (nonce) { // ID Token（含nonce）
        snprintf(payload, sizeof(payload),
            "{\"iss\":\"%s\",\"sub\":\"%s\",\"aud\":\"%s\",\"iat\":%ld,\"exp\":%ld,\"nonce\":\"%s\",\"preferred_username\":\"%s\"}",
            ISSUER, USER_ID, CLIENT_ID, (long)now, (long)(now+EXP_SEC), nonce, USER_ID);
    } else { // Access Token（含scope）
        snprintf(payload, sizeof(payload),
            "{\"iss\":\"%s\",\"sub\":\"%s\",\"aud\":\"%s\",\"iat\":%ld,\"exp\":%ld,\"scope\":\"openid\"}",
            ISSUER, USER_ID, CLIENT_ID, (long)now, (long)(now+EXP_SEC));
    }
    char *pay_b64 = base64url_encode((unsigned char*)payload, strlen(payload));

    // 3. 拼接Header.Payload用于签名
    char sig_data[1024];
    snprintf(sig_data, sizeof(sig_data), "%s.%s", hdr_b64, pay_b64);
    
    // 4. RSA签名并Base64URL编码
    char *sig_b64 = rsa_sign(sig_data, pkey);
    if(!sig_b64) {
        free(hdr_b64); free(pay_b64);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    // 5. 拼接最终JWT
    char *jwt = malloc(strlen(hdr_b64) + strlen(pay_b64) + strlen(sig_b64) + 3);
    snprintf(jwt, strlen(hdr_b64)+strlen(pay_b64)+strlen(sig_b64)+3,
             "%s.%s.%s", hdr_b64, pay_b64, sig_b64);

    // 释放临时资源
    free(hdr_b64); free(pay_b64); free(sig_b64);
    EVP_PKEY_free(pkey);
    return jwt;
}

// 解析POST表单参数（简化版）
static char* parse_form_param(const char *form, const char *key) {
    if(!form || !key) return NULL;
    char *k = malloc(strlen(key)+2);
    sprintf(k, "%s=", key);
    const char *p = strstr(form, k);
    free(k);
    if(!p) return NULL;

    p += strlen(key)+1;
    const char *e = strchr(p, '&');
    if(!e) e = p + strlen(p);
    
    char *v = malloc(e-p+1);
    strncpy(v, p, e-p);
    v[e-p] = '\0';
    return v;
}

// 发送JSON响应
static enum MHD_Result send_json(struct MHD_Connection *conn, int status, const char *json) {
    struct MHD_Response *resp = MHD_create_response_from_buffer(
        strlen(json), (void*)json, MHD_RESPMEM_PERSISTENT
    );
    MHD_add_response_header(resp, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(conn, status, resp);
    MHD_destroy_response(resp);
    return ret;
}

// ===================== 连接数据管理 =====================
typedef struct {
    char *post_data;
    size_t len;
} ConnData;

static void free_conn_data(void *cls) {
    ConnData *data = cls;
    if(data) { free(data->post_data); free(data); }
}

// ===================== 路由处理函数 =====================
// 处理/authorize（授权码发放）
static enum MHD_Result handle_authorize(struct MHD_Connection *conn) {
    // 校验redirect_uri
    const char *uri = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "redirect_uri");
    if(uri && strcmp(uri, REDIRECT_URI)) {
        return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"invalid redirect_uri\"}");
    }

    // 生成授权码
    clean_expired_auth_codes();
    char code[33];
    gen_auth_code(code);
    const char *nonce = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "nonce");

    // 保存授权码
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

    // 发送重定向响应
    struct MHD_Response *resp = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(resp, "Location", redirect);
    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_FOUND, resp);
    MHD_destroy_response(resp);
    return ret;
}

// 处理/token（Token兑换）
static enum MHD_Result handle_token(struct MHD_Connection *conn, const char *upload, size_t *ul_len, void **con_cls) {
    ConnData *data = *con_cls;
    if(!data) {
        data = calloc(1, sizeof(ConnData));
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
        return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"missing code\"}");
    }

    // 查找并校验授权码
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
        return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"invalid/expired code\"}");
    }

    // 生成Token
    char *id_token = generate_jwt(nonce);
    char *access_token = generate_jwt(NULL);
    if(!id_token || !access_token) {
        free(nonce); free(id_token); free(access_token);
        free_conn_data(data);
        *con_cls = NULL;
        return send_json(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"token generate failed\"}");
    }

    // 构建响应
    char resp[2048];
    snprintf(resp, sizeof(resp),
        "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":%d,\"id_token\":\"%s\"}",
        access_token, EXP_SEC, id_token);

    enum MHD_Result ret = send_json(conn, MHD_HTTP_OK, resp);

    // 清理资源
    free(nonce); free(id_token); free(access_token);
    free_conn_data(data);
    *con_cls = NULL;
    return ret;
}

// 处理/.well-known/openid-configuration（OIDC发现）
static enum MHD_Result handle_wellknown(struct MHD_Connection *conn) {
    char auth_ep[256], token_ep[256], jwks_ep[256];
    snprintf(auth_ep, sizeof(auth_ep), "%s/authorize", ISSUER);
    snprintf(token_ep, sizeof(token_ep), "%s/token", ISSUER);
    snprintf(jwks_ep, sizeof(jwks_ep), "%s/jwks", ISSUER);

    char resp[1024];
    snprintf(resp, sizeof(resp),
        "{\"issuer\":\"%s\",\"authorization_endpoint\":\"%s\",\"token_endpoint\":\"%s\",\"jwks_uri\":\"%s\",\"response_types_supported\":[\"code\"],\"id_token_signing_alg_values_supported\":[\"RS256\"]}",
        ISSUER, auth_ep, token_ep, jwks_ep);

    return send_json(conn, MHD_HTTP_OK, resp);
}

// 处理/jwks（公钥暴露，适配OpenSSL 3.0+，无废弃接口）
static enum MHD_Result handle_jwks(struct MHD_Connection *conn) {
    EVP_PKEY *pkey = load_rsa_priv_key();
    if(!pkey) return send_json(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"load key failed\"}");

    // OpenSSL 3.0+ 推荐接口：直接提取RSA参数（无需RSA*结构体）
    BIGNUM *n = NULL, *e = NULL;
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) ||
        !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e)) {
        EVP_PKEY_free(pkey);
        ERR_print_errors_fp(stderr);
        return send_json(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"get rsa params failed\"}");
    }

    // BIGNUM转二进制并Base64URL编码
    int n_len = BN_num_bytes(n);
    int e_len = BN_num_bytes(e);
    unsigned char *n_bin = malloc(n_len);
    unsigned char *e_bin = malloc(e_len);
    BN_bn2bin(n, n_bin);
    BN_bn2bin(e, e_bin);

    char *n_b64 = base64url_encode(n_bin, n_len);
    char *e_b64 = base64url_encode(e_bin, e_len);

    // 构建JWKS响应
    char jwks[1024];
    snprintf(jwks, sizeof(jwks),
        "{\"keys\":[{\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"%s\",\"e\":\"%s\"}]}",
        n_b64, e_b64);

    enum MHD_Result ret = send_json(conn, MHD_HTTP_OK, jwks);

    // 清理资源（必须释放BIGNUM）
    free(n_bin); free(e_bin);
    free(n_b64); free(e_b64);
    BN_free(n);
    BN_free(e);
    EVP_PKEY_free(pkey);
    return ret;
}

// ===================== 主请求处理器 =====================
static enum MHD_Result request_handler(void *cls, struct MHD_Connection *conn,
                               const char *url, const char *method,
                               const char *version, const char *upload,
                               size_t *ul_len, void **con_cls) {
    // OPTIONS跨域处理
    if(!strcmp(method, "OPTIONS")) {
        struct MHD_Response *resp = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
        MHD_add_response_header(resp, "Access-Control-Allow-Methods", "GET,POST,OPTIONS");
        MHD_add_response_header(resp, "Access-Control-Allow-Headers", "Content-Type");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
        MHD_destroy_response(resp);
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

    // 404
    return send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"not found\"}");
}

// ===================== 主函数 =====================
int main() {
    // OpenSSL初始化（3.0+兼容）
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    OpenSSL_add_all_algorithms();

    // 启动MHD服务器
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
    free(auth_codes);
    EVP_cleanup();
    return 0;
}
