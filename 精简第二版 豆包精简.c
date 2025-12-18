#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <microhttpd.h>
#include <cjose/cjose.h>
#include <jansson.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

// 核心配置
#define OIDC_SERVER_PORT   9999
#define REDIRECT_URI       "https://192.168.3.210:8443/oidc/callback"
#define PRIVATE_KEY_PATH   "./private.key"
#define ISSUER             "http://192.168.3.84:9999"
#define USER_ID            "user123"
#define CLIENT_ID          "incus-client"
#define TOKEN_EXPIRE_SEC   3600
#define OIDC_SCOPES        "openid"

// 错误处理宏
#define CHECK(expr, msg) do { if (!(expr)) { fprintf(stderr, "%s\n", msg); goto cleanup; } } while(0)

// 授权码结构
typedef struct {
    char *code;
    char *nonce;
    time_t created_at;
} auth_code_nonce_t;

static auth_code_nonce_t *auth_code_list = NULL;
static int auth_code_count = 0;

// 生成32位随机授权码
static char* generate_auth_code() {
    static char code[33];
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    srand(time(NULL) ^ getpid());
    for (int i = 0; i < 32; i++) code[i] = charset[rand() % (sizeof(charset)-1)];
    code[32] = '\0';
    return strdup(code);
}

// 保存授权码和nonce
static void save_auth_code_nonce(const char *code, const char *nonce) {
    auth_code_nonce_t *new_entry = malloc(sizeof(auth_code_nonce_t));
    if (!new_entry) return;
    
    new_entry->code = strdup(code);
    new_entry->nonce = nonce ? strdup(nonce) : strdup("");
    new_entry->created_at = time(NULL);
    
    auth_code_list = realloc(auth_code_list, (auth_code_count + 1) * sizeof(auth_code_nonce_t));
    if (auth_code_list) {
        auth_code_list[auth_code_count++] = *new_entry;
    }
    free(new_entry);
}

// 查找nonce
static char* find_nonce_by_auth_code(const char *code) {
    if (!code || auth_code_count == 0) return NULL;
    
    time_t now = time(NULL);
    for (int i = 0; i < auth_code_count; i++) {
        if (strcmp(auth_code_list[i].code, code) == 0 && (now - auth_code_list[i].created_at) <= 300) {
            return strdup(auth_code_list[i].nonce);
        }
    }
    return NULL;
}

// 清理过期授权码
static void cleanup_expired_auth_codes() {
    time_t now = time(NULL);
    int new_count = 0;
    
    for (int i = 0; i < auth_code_count; i++) {
        if (now - auth_code_list[i].created_at <= 300) {
            if (new_count != i) auth_code_list[new_count] = auth_code_list[i];
            new_count++;
        } else {
            free(auth_code_list[i].code);
            free(auth_code_list[i].nonce);
        }
    }
    
    if (new_count < auth_code_count) {
        auth_code_list = realloc(auth_code_list, new_count * sizeof(auth_code_nonce_t));
        auth_code_count = new_count;
    }
}

// 加载RSA私钥
static cjose_jwk_t* load_rsa_private_key() {
    FILE *fp = fopen(PRIVATE_KEY_PATH, "r");
    if (!fp) return NULL;

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) return NULL;

    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if (!rsa) { EVP_PKEY_free(pkey); return NULL; }

    const BIGNUM *n, *e, *d;
    RSA_get0_key(rsa, &n, &e, &d);

    size_t n_len = BN_num_bytes(n), e_len = BN_num_bytes(e), d_len = BN_num_bytes(d);
    uint8_t *n_data = malloc(n_len), *e_data = malloc(e_len), *d_data = malloc(d_len);
    BN_bn2bin(n, n_data); BN_bn2bin(e, e_data); BN_bn2bin(d, d_data);

    cjose_jwk_rsa_keyspec spec = {
        .e = e_data, .elen = e_len, .n = n_data, .nlen = n_len,
        .d = d_data, .dlen = d_len, .p = NULL, .plen = 0,
        .q = NULL, .qlen = 0, .dp = NULL, .dplen = 0,
        .dq = NULL, .dqlen = 0, .qi = NULL, .qilen = 0
    };

    cjose_err err;
    cjose_jwk_t *jwk = cjose_jwk_create_RSA_spec(&spec, &err);

    free(n_data); free(e_data); free(d_data);
    RSA_free(rsa); EVP_PKEY_free(pkey);
    return jwk;
}

// Base64URL编码
static char *base64url_encode(const uint8_t *data, size_t len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);

    BIO_write(b64, data, len);
    BIO_flush(b64);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(bmem, &bptr);
    char *buff = malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;

    for (size_t i = 0; i < bptr->length; i++) {
        if (buff[i] == '+') buff[i] = '-';
        else if (buff[i] == '/') buff[i] = '_';
        else if (buff[i] == '=') { buff[i] = 0; break; }
    }

    BIO_free_all(b64);
    return buff;
}

// 生成JWT
static char* generate_jwt(const char* token_type, const char* nonce) {
    cjose_err err;
    char *jwt_str = NULL, *payload_json = NULL;
    cjose_jwk_t *key = load_rsa_private_key();
    CHECK(key, "Failed to load private key");

    time_t now = time(NULL);
    json_t *claims = json_object();
    json_object_set_new(claims, "iss", json_string(ISSUER));
    json_object_set_new(claims, "sub", json_string(USER_ID));
    json_object_set_new(claims, "aud", json_string(CLIENT_ID));
    json_object_set_new(claims, "iat", json_integer(now));
    json_object_set_new(claims, "exp", json_integer(now + TOKEN_EXPIRE_SEC));

    if (strcmp(token_type, "id_token") == 0) {
        char username[64];
        snprintf(username, 64, "user_%s", USER_ID);
        json_object_set_new(claims, "nonce", json_string(nonce ?: ""));
        json_object_set_new(claims, "preferred_username", json_string(username));
    } else {
        json_object_set_new(claims, "scope", json_string(OIDC_SCOPES));
    }

    payload_json = json_dumps(claims, JSON_COMPACT);
    json_decref(claims);
    CHECK(payload_json, "Failed to serialize claims");

    cjose_header_t *header = cjose_header_new(&err);
    cjose_header_set(header, "alg", "RS256", &err);
    
    cjose_jws_t *jws = cjose_jws_sign(key, header, (uint8_t*)payload_json, strlen(payload_json), &err);
    cjose_header_release(header);
    CHECK(jws, "Failed to sign JWT");

    const char *jwt_raw = NULL;
    if (cjose_jws_export(jws, &jwt_raw, &err)) jwt_str = strdup(jwt_raw);

cleanup:
    free(payload_json);
    if (jws) cjose_jws_release(jws);
    if (key) cjose_jwk_release(key);
    return jwt_str;
}

// 解析表单参数
static char* parse_form_param(const char *form_data, const char *param) {
    if (!form_data || !param) return NULL;
    
    char key[32];
    snprintf(key, sizeof(key), "%s=", param);
    const char *pos = strstr(form_data, key);
    if (!pos) return NULL;
    
    pos += strlen(key);
    const char *end = strchr(pos, '&');
    if (!end) end = pos + strlen(pos);
    
    size_t len = end - pos;
    char *val = malloc(len + 1);
    strncpy(val, pos, len);
    val[len] = '\0';
    return val;
}

// 连接状态结构
typedef struct {
    char *post_data;
    size_t post_data_size;
} conn_info_t;

static void free_conn_info(void *cls) {
    conn_info_t *info = (conn_info_t*)cls;
    if (info) { free(info->post_data); free(info); }
}

// 处理授权请求
static enum MHD_Result handle_authorize(struct MHD_Connection *conn) {
    const char *req_redirect_uri = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "redirect_uri");
    if (req_redirect_uri && strcmp(req_redirect_uri, REDIRECT_URI) != 0) {
        const char *err = "{\"error\":\"invalid_redirect_uri\"}";
        struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Content-Type", "application/json");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_BAD_REQUEST, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    cleanup_expired_auth_codes();
    char *auth_code = generate_auth_code();
    const char *nonce = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "nonce");
    save_auth_code_nonce(auth_code, nonce);

    char redirect_url[1024];
    const char *state = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "state");
    if (state) {
        snprintf(redirect_url, sizeof(redirect_url), "%s?code=%s&state=%s", REDIRECT_URI, auth_code, state);
    } else {
        snprintf(redirect_url, sizeof(redirect_url), "%s?code=%s", REDIRECT_URI, auth_code);
    }

    struct MHD_Response *resp = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(resp, MHD_HTTP_HEADER_LOCATION, redirect_url);
    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_FOUND, resp);
    MHD_destroy_response(resp);
    free(auth_code);
    return ret;
}

// 处理Token请求
static enum MHD_Result handle_token(struct MHD_Connection *conn, const char *upload_data, 
                                   size_t *upload_data_size, void **con_cls) {
    conn_info_t *info = (conn_info_t*)*con_cls;
    if (!info) {
        info = malloc(sizeof(conn_info_t));
        info->post_data = NULL;
        info->post_data_size = 0;
        *con_cls = info;
        return MHD_YES;
    }

    if (*upload_data_size > 0) {
        info->post_data = realloc(info->post_data, info->post_data_size + *upload_data_size + 1);
        memcpy(info->post_data + info->post_data_size, upload_data, *upload_data_size);
        info->post_data_size += *upload_data_size;
        info->post_data[info->post_data_size] = '\0';
        *upload_data_size = 0;
        return MHD_YES;
    }

    char *code = parse_form_param(info->post_data, "code");
    if (!code) {
        const char *err = "{\"error\":\"invalid_request\"}";
        struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Content-Type", "application/json");
        MHD_queue_response(conn, MHD_HTTP_BAD_REQUEST, resp);
        MHD_destroy_response(resp);
        free(code);
        free_conn_info(info);
        *con_cls = NULL;
        return MHD_YES;
    }

    char *nonce = find_nonce_by_auth_code(code);
    if (!nonce) {
        const char *err = "{\"error\":\"invalid_code\"}";
        struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Content-Type", "application/json");
        MHD_queue_response(conn, MHD_HTTP_BAD_REQUEST, resp);
        MHD_destroy_response(resp);
        free(code); free(nonce);
        free_conn_info(info);
        *con_cls = NULL;
        return MHD_YES;
    }

    char *id_token = generate_jwt("id_token", nonce);
    char *access_token = generate_jwt("access_token", NULL);
    
    json_t *resp_json = json_object();
    json_object_set_new(resp_json, "access_token", json_string(access_token));
    json_object_set_new(resp_json, "token_type", json_string("Bearer"));
    json_object_set_new(resp_json, "expires_in", json_integer(TOKEN_EXPIRE_SEC));
    json_object_set_new(resp_json, "id_token", json_string(id_token));

    char *json_str = json_dumps(resp_json, JSON_COMPACT);
    struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(json_str), (void*)json_str, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(resp, "Content-Type", "application/json");
    MHD_queue_response(conn, MHD_HTTP_OK, resp);
    
    MHD_destroy_response(resp);
    json_decref(resp_json);
    free(json_str);
    free(code); free(nonce); free(id_token); free(access_token);
    free_conn_info(info);
    *con_cls = NULL;
    
    return MHD_YES;
}

// 处理发现端点
static enum MHD_Result handle_well_known(struct MHD_Connection *conn) {
    char config[1024];
    snprintf(config, sizeof(config),
        "{\"issuer\":\"%s\",\"authorization_endpoint\":\"%s/authorize\","
        "\"token_endpoint\":\"%s/token\",\"jwks_uri\":\"%s/jwks\","
        "\"response_types_supported\":[\"code\"],"
        "\"subject_types_supported\":[\"public\"],"
        "\"id_token_signing_alg_values_supported\":[\"RS256\"],"
        "\"scopes_supported\":[\"%s\"],"
        "\"claims_supported\":[\"iss\",\"sub\",\"aud\",\"iat\",\"exp\",\"preferred_username\"]}",
        ISSUER, ISSUER, ISSUER, ISSUER, OIDC_SCOPES);

    struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(config), (void*)config, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(resp, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);
    return ret;
}

// 处理JWKS端点
static enum MHD_Result handle_jwks(struct MHD_Connection *conn) {
    FILE *fp = fopen(PRIVATE_KEY_PATH, "r");
    if (!fp) return MHD_NO;

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) return MHD_NO;

    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if (!rsa) { EVP_PKEY_free(pkey); return MHD_NO; }

    const BIGNUM *n, *e;
    RSA_get0_key(rsa, &n, &e, NULL);
    
    size_t n_len = BN_num_bytes(n), e_len = BN_num_bytes(e);
    uint8_t *n_bytes = malloc(n_len), *e_bytes = malloc(e_len);
    BN_bn2bin(n, n_bytes); BN_bn2bin(e, e_bytes);

    char *n_b64 = base64url_encode(n_bytes, n_len);
    char *e_b64 = base64url_encode(e_bytes, e_len);
    
    json_t *jwks = json_object();
    json_t *keys = json_array();
    json_t *key = json_object();
    
    json_object_set_new(key, "kty", json_string("RSA"));
    json_object_set_new(key, "alg", json_string("RS256"));
    json_object_set_new(key, "use", json_string("sig"));
    json_object_set_new(key, "kid", json_string("demo-key-1"));
    json_object_set_new(key, "n", json_string(n_b64));
    json_object_set_new(key, "e", json_string(e_b64));
    
    json_array_append_new(keys, key);
    json_object_set_new(jwks, "keys", keys);
    
    char *json_str = json_dumps(jwks, JSON_COMPACT);
    struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(json_str), (void*)json_str, MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(resp, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
    
    MHD_destroy_response(resp);
    free(n_bytes); free(e_bytes); free(n_b64); free(e_b64);
    RSA_free(rsa); EVP_PKEY_free(pkey); json_decref(jwks);
    
    return ret;
}

// 主请求处理器
static enum MHD_Result request_handler(void *cls, struct MHD_Connection *conn,
                                       const char *url, const char *method,
                                       const char *version, const char *upload_data,
                                       size_t *upload_data_size, void **con_cls) {
    // 处理跨域
    if (strcmp(method, "OPTIONS") == 0) {
        struct MHD_Response *resp = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
        MHD_add_response_header(resp, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        MHD_add_response_header(resp, "Access-Control-Allow-Headers", "Content-Type, Authorization");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    // 路由
    if (strcmp(url, "/authorize") == 0 && strcmp(method, "GET") == 0) {
        return handle_authorize(conn);
    } else if (strcmp(url, "/token") == 0 && strcmp(method, "POST") == 0) {
        return handle_token(conn, upload_data, upload_data_size, con_cls);
    } else if (strcmp(url, "/.well-known/openid-configuration") == 0 && strcmp(method, "GET") == 0) {
        return handle_well_known(conn);
    } else if (strcmp(url, "/jwks") == 0 && strcmp(method, "GET") == 0) {
        return handle_jwks(conn);
    } else {
        const char *err = "{\"error\":\"not_found\"}";
        struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Content-Type", "application/json");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_NOT_FOUND, resp);
        MHD_destroy_response(resp);
        return ret;
    }
}

int main() {
    OpenSSL_add_all_algorithms();

    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_SELECT_INTERNALLY, OIDC_SERVER_PORT,
        NULL, NULL, &request_handler, NULL,
        MHD_OPTION_LISTENING_ADDRESS_REUSE, 1,
        MHD_OPTION_CONNECTION_TIMEOUT, 30,
        MHD_OPTION_END
    );

    if (!daemon) {
        fprintf(stderr, "Failed to start server\n");
        return EXIT_FAILURE;
    }

    printf("OIDC Server running on port %d\nPress Enter to stop...\n", OIDC_SERVER_PORT);
    getchar();
    
    MHD_stop_daemon(daemon);
    EVP_cleanup();
    
    // 清理授权码列表
    for (int i = 0; i < auth_code_count; i++) {
        free(auth_code_list[i].code);
        free(auth_code_list[i].nonce);
    }
    free(auth_code_list);

    return EXIT_SUCCESS;
}
