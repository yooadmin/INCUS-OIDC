#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <microhttpd.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <unistd.h>

// 核心配置
#define PORT            9999
#define REDIRECT_URI    "https://192.168.3.210:8443/oidc/callback"
#define ISSUER          "http://192.168.3.84:9999"
#define USER_ID         "user123"
#define CLIENT_ID       "incus-client"
#define EXP_SEC         3600
#define AUTH_CODE_EXPIRE 300
#define RSA_KEY_BITS    2048

// 全局变量
static EVP_PKEY *g_rsa_pkey = NULL;

// 授权码结构体
typedef struct {
    char code[33];
    char nonce[64];
    time_t ctime;
} AuthCode;

static AuthCode *auth_codes = NULL;
static int ac_count = 0;

// 连接数据结构体
typedef struct {
    char *post_data;
    size_t len;
} ConnData;

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
    // 计算输出长度
    size_t encoded_len = ((len + 2) / 3) * 4;
    char *buf = malloc(encoded_len + 1);
    if (!buf) return NULL;

    // 使用EVP_EncodeBlock进行Base64编码
    int out_len = EVP_EncodeBlock((unsigned char*)buf, data, len);
    
    // 移除换行符（如果有的话）
    while (out_len > 0 && (buf[out_len-1] == '\n' || buf[out_len-1] == '\r')) {
        out_len--;
    }
    buf[out_len] = '\0';

    // Base64转Base64URL
    char *p = buf;
    while (*p) {
        if (*p == '+') *p = '-';
        else if (*p == '/') *p = '_';
        else if (*p == '=') { *p = '\0'; break; }
        p++;
    }

    return buf;
}

// 内存生成RSA密钥对
static int generate_rsa_key_in_memory() {
    if (g_rsa_pkey) return 0;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        fprintf(stderr, "RSA密钥生成失败 - 无法创建上下文\n");
        return -1;
    }

    if (EVP_PKEY_keygen_init(ctx) != 1) {
        fprintf(stderr, "RSA密钥生成失败 - 初始化失败\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    // 设置RSA密钥位数
    int key_bits = RSA_KEY_BITS;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_RSA_BITS, &key_bits),
        OSSL_PARAM_END
    };
    if (EVP_PKEY_CTX_set_params(ctx, params) != 1) {
        fprintf(stderr, "RSA密钥生成失败 - 无法设置密钥位数\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_keygen(ctx, &g_rsa_pkey) != 1) {
        fprintf(stderr, "RSA密钥生成失败\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    printf("✅ 内存生成RSA-%d密钥对成功\n", RSA_KEY_BITS);
    return 0;
}

// RSA-SHA256签名
static char* rsa_sign(const char *data) {
    if (!g_rsa_pkey) return NULL;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(!ctx || EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, g_rsa_pkey) != 1 ||
       EVP_DigestSignUpdate(ctx, data, strlen(data)) != 1) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    size_t sig_len;
    unsigned char sig[4096];
    if(EVP_DigestSignFinal(ctx, NULL, &sig_len) != 1 ||
       EVP_DigestSignFinal(ctx, sig, &sig_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    EVP_MD_CTX_free(ctx);

    return base64url_encode(sig, sig_len);
}

// 生成JWT
static char* generate_jwt(const char *nonce) {
    if (!g_rsa_pkey && generate_rsa_key_in_memory() != 0) return NULL;

    // JWT Header
    char header[] = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
    char *hdr_b64 = base64url_encode((unsigned char*)header, strlen(header));

    // JWT Payload
    time_t now = time(NULL);
    char payload[512];
    if (nonce) {
        snprintf(payload, sizeof(payload),
            "{\"iss\":\"%s\",\"sub\":\"%s\",\"aud\":\"%s\",\"iat\":%ld,\"exp\":%ld,\"nonce\":\"%s\",\"preferred_username\":\"%s\"}",
            ISSUER, USER_ID, CLIENT_ID, (long)now, (long)(now+EXP_SEC), nonce, USER_ID);
    } else {
        snprintf(payload, sizeof(payload),
            "{\"iss\":\"%s\",\"sub\":\"%s\",\"aud\":\"%s\",\"iat\":%ld,\"exp\":%ld,\"scope\":\"openid\"}",
            ISSUER, USER_ID, CLIENT_ID, (long)now, (long)(now+EXP_SEC));
    }
    char *pay_b64 = base64url_encode((unsigned char*)payload, strlen(payload));

    // 拼接签名数据
    char sig_data[1024];
    snprintf(sig_data, sizeof(sig_data), "%s.%s", hdr_b64, pay_b64);
    
    // 签名并拼接JWT
    char *sig_b64 = rsa_sign(sig_data);
    if(!sig_b64) {
        free(hdr_b64); free(pay_b64);
        return NULL;
    }

    char *jwt = malloc(strlen(hdr_b64) + strlen(pay_b64) + strlen(sig_b64) + 3);
    snprintf(jwt, strlen(hdr_b64)+strlen(pay_b64)+strlen(sig_b64)+3,
             "%s.%s.%s", hdr_b64, pay_b64, sig_b64);

    free(hdr_b64); free(pay_b64); free(sig_b64);
    return jwt;
}

// 解析表单参数
static char* parse_form_param(const char *form, const char *key) {
    if(!form || !key) return NULL;
    
    char k[strlen(key)+2];
    sprintf(k, "%s=", key);
    const char *p = strstr(form, k);
    if(!p) return NULL;

    p += strlen(key)+1;
    const char *e = strchr(p, '&') ?: (p + strlen(p));
    
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

// 释放连接数据
static void free_conn_data(ConnData *data) {
    if(data) {
        free(data->post_data);
        free(data);
    }
}

// 处理授权码请求
static enum MHD_Result handle_authorize(struct MHD_Connection *conn) {
    const char *uri = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "redirect_uri");
    if(uri && strcmp(uri, REDIRECT_URI)) {
        return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"invalid redirect_uri\"}");
    }

    clean_expired_auth_codes();
    char code[33];
    gen_auth_code(code);
    const char *nonce = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "nonce");
    const char *state = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "state");

    // 保存授权码
    auth_codes = realloc(auth_codes, (ac_count+1)*sizeof(AuthCode));
    strcpy(auth_codes[ac_count].code, code);
    strcpy(auth_codes[ac_count].nonce, nonce ?: "");
    auth_codes[ac_count].ctime = time(NULL);
    ac_count++;

    // 构建重定向URL
    char redirect[1024];
    snprintf(redirect, sizeof(redirect),
             state ? "%s?code=%s&state=%s" : "%s?code=%s",
             REDIRECT_URI, code, state);

    struct MHD_Response *resp = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(resp, "Location", redirect);
    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_FOUND, resp);
    MHD_destroy_response(resp);
    return ret;
}

// 处理Token兑换
static enum MHD_Result handle_token(struct MHD_Connection *conn, const char *upload, size_t *ul_len, void **con_cls) {
    ConnData *data = *con_cls;
    if(!data) {
        *con_cls = calloc(1, sizeof(ConnData));
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

    // 解析并校验授权码
    char *code = parse_form_param(data->post_data, "code");
    if(!code) {
        free_conn_data(data);
        *con_cls = NULL;
        return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"missing code\"}");
    }

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

// 处理OIDC发现配置
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

// 处理JWKS公钥暴露
static enum MHD_Result handle_jwks(struct MHD_Connection *conn) {
    if (!g_rsa_pkey && generate_rsa_key_in_memory() != 0) {
        return send_json(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"load key failed\"}");
    }

    // 提取RSA公钥参数
    BIGNUM *n = NULL, *e = NULL;
    if (!EVP_PKEY_get_bn_param(g_rsa_pkey, OSSL_PKEY_PARAM_RSA_N, &n) ||
        !EVP_PKEY_get_bn_param(g_rsa_pkey, OSSL_PKEY_PARAM_RSA_E, &e)) {
        ERR_print_errors_fp(stderr);
        return send_json(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"get rsa params failed\"}");
    }

    // BIGNUM转Base64URL
    int n_len = BN_num_bytes(n), e_len = BN_num_bytes(e);
    unsigned char *n_bin = malloc(n_len), *e_bin = malloc(e_len);
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

    // 清理资源
    free(n_bin); free(e_bin);
    free(n_b64); free(e_b64);
    BN_free(n);
    BN_free(e);
    return ret;
}

// 主请求处理器
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

    // 404响应
    return send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"not found\"}");
}

// 主函数
int main() {
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    // 生成RSA密钥
    if (generate_rsa_key_in_memory() != 0) {
        fprintf(stderr, "❌ RSA密钥生成失败\n");
        return 1;
    }

    // 启动服务器
    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_SELECT_INTERNALLY, PORT,
        NULL, NULL, &request_handler, NULL,
        MHD_OPTION_CONNECTION_TIMEOUT, 30,
        MHD_OPTION_END
    );

    if(!daemon) { fprintf(stderr, "❌ 服务器启动失败\n"); return 1; }
    printf("✅ OIDC服务器运行在端口 %d（按回车停止）\n", PORT);
    getchar();

    // 清理资源
    MHD_stop_daemon(daemon);
    free(auth_codes);
    if (g_rsa_pkey) EVP_PKEY_free(g_rsa_pkey);
    
    return 0;
}
