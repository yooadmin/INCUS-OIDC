#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
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

// ========== 替换为你的配置参数 ==========
#define OIDC_SERVER_IP     "192.168.3.84"
#define OIDC_SERVER_PORT   9999
#define REDIRECT_URI       "https://192.168.3.210:8443/oidc/callback" // 原回调地址
#define PRIVATE_KEY_PATH   "./private.key"  // RSA私钥路径
#define ISSUER             "http://192.168.3.84:9999" // 与oidc.issuer一致
#define USER_ID            "user123"        // 固定用户ID
#define CLIENT_ID          "incus-client"   // 与oidc.client.id一致
#define TOKEN_EXPIRE_SEC   3600             // Token有效期1小时
#define OIDC_SCOPES        "openid"         // 与oidc.scopes一致
// ========================================

// 错误处理宏
#define CJOSE_CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "cjose error at %s:%d\n", __FILE__, __LINE__); \
        goto cleanup; \
    } \
} while(0)

// 授权码和nonce的关联结构
typedef struct {
    char *code;
    char *nonce;
    time_t created_at;
} auth_code_nonce_t;

// 存储授权码和nonce的列表
static auth_code_nonce_t *auth_code_list = NULL;
static int auth_code_count = 0;

// 生成随机授权码（优化随机性）
static char* generate_auth_code() {
    static char code[33];
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    unsigned char rand_buf[32];
    
    // 优先使用/dev/urandom获取安全随机数
    FILE *urandom = fopen("/dev/urandom", "r");
    if (urandom) {
        fread(rand_buf, 1, 32, urandom);
        fclose(urandom);
    } else {
        // 降级方案（仅测试用）
        srand(time(NULL) ^ getpid() ^ (unsigned long)pthread_self());
        for (int i = 0; i < 32; i++) {
            rand_buf[i] = (unsigned char)rand();
        }
    }
    
    // 生成32位授权码
    for (int i = 0; i < 32; i++) {
        code[i] = charset[rand_buf[i] % (sizeof(charset) - 1)];
    }
    code[32] = '\0';
    return strdup(code);
}

// 保存授权码和nonce的关联
static void save_auth_code_nonce(const char *code, const char *nonce) {
    // 分配新的关联结构
    auth_code_nonce_t *new_entry = (auth_code_nonce_t *)malloc(sizeof(auth_code_nonce_t));
    if (!new_entry) {
        fprintf(stderr, "Failed to allocate memory for auth_code_nonce_t\n");
        return;
    }
    
    // 保存授权码和nonce
    new_entry->code = strdup(code);
    new_entry->nonce = strdup(nonce);
    new_entry->created_at = time(NULL);
    
    // 扩展数组
    auth_code_list = (auth_code_nonce_t *)realloc(auth_code_list, (auth_code_count + 1) * sizeof(auth_code_nonce_t));
    if (!auth_code_list) {
        fprintf(stderr, "Failed to reallocate auth_code_list\n");
        free(new_entry->code);
        free(new_entry->nonce);
        free(new_entry);
        return;
    }
    
    // 添加新条目
    auth_code_list[auth_code_count] = *new_entry;
    auth_code_count++;
    
    free(new_entry);
}

// 根据授权码查找关联的nonce
static char* find_nonce_by_auth_code(const char *code) {
    if (!code || auth_code_count == 0) {
        return NULL;
    }
    
    // 遍历列表查找匹配的授权码
    for (int i = 0; i < auth_code_count; i++) {
        if (strcmp(auth_code_list[i].code, code) == 0) {
            // 检查授权码是否过期（5分钟过期）
            if (time(NULL) - auth_code_list[i].created_at > 300) {
                return NULL;
            }
            return strdup(auth_code_list[i].nonce);
        }
    }
    
    return NULL;
}

// 清理过期的授权码
static void cleanup_expired_auth_codes() {
    time_t now = time(NULL);
    int new_count = 0;
    
    for (int i = 0; i < auth_code_count; i++) {
        // 保留未过期的授权码
        if (now - auth_code_list[i].created_at <= 300) {
            if (new_count != i) {
                auth_code_list[new_count] = auth_code_list[i];
            }
            new_count++;
        } else {
            // 释放过期条目的内存
            free(auth_code_list[i].code);
            free(auth_code_list[i].nonce);
        }
    }
    
    // 调整数组大小
    if (new_count < auth_code_count) {
        auth_code_list = (auth_code_nonce_t *)realloc(auth_code_list, new_count * sizeof(auth_code_nonce_t));
        auth_code_count = new_count;
    }
}

// 加载RSA私钥（使用OpenSSL直接加载PEM格式）
static cjose_jwk_t* load_rsa_private_key() {
    FILE *fp = fopen(PRIVATE_KEY_PATH, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open private key: %s\n", PRIVATE_KEY_PATH);
        return NULL;
    }

    // 使用OpenSSL加载PEM私钥
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) {
        fprintf(stderr, "Failed to read private key with OpenSSL\n");
        return NULL;
    }

    // 获取RSA密钥指针
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if (!rsa) {
        fprintf(stderr, "Failed to get RSA key from EVP_PKEY\n");
        EVP_PKEY_free(pkey);
        return NULL;
    }

    // 提取RSA参数
    const BIGNUM *n, *e, *d;
    RSA_get0_key(rsa, &n, &e, &d);

    // 转换为字节数组
    size_t n_len = BN_num_bytes(n);
    size_t e_len = BN_num_bytes(e);
    size_t d_len = BN_num_bytes(d);

    uint8_t *n_data = malloc(n_len);
    uint8_t *e_data = malloc(e_len);
    uint8_t *d_data = malloc(d_len);

    BN_bn2bin(n, n_data);
    BN_bn2bin(e, e_data);
    BN_bn2bin(d, d_data);

    // 创建RSA密钥规范
    cjose_jwk_rsa_keyspec spec = {
        .e = e_data,
        .elen = e_len,
        .n = n_data,
        .nlen = n_len,
        .d = d_data,
        .dlen = d_len,
        .p = NULL, // 可选参数
        .plen = 0,
        .q = NULL,
        .qlen = 0,
        .dp = NULL,
        .dplen = 0,
        .dq = NULL,
        .dqlen = 0,
        .qi = NULL,
        .qilen = 0
    };

    cjose_err err;
    cjose_jwk_t *jwk = cjose_jwk_create_RSA_spec(&spec, &err);

    // 释放资源
    free(n_data);
    free(e_data);
    free(d_data);
    RSA_free(rsa);
    EVP_PKEY_free(pkey);

    if (!jwk) {
        fprintf(stderr, "Failed to create JWK from RSA key: %s\n", err.message);
    }

    return jwk;
}

// 生成preferred_username（与oidc.claim对应）
static char* get_preferred_username(const char* user_id) {
    // 模拟动态用户名（可替换为数据库查询）
    char *username = malloc(64);
    snprintf(username, 64, "user_%s", user_id); // 示例：user_user123
    return username;
}

// 生成JWT Token（适配配置）
static char* generate_jwt(const char* token_type, const char* nonce) {
    cjose_err err;
    char *jwt_str = NULL;
    char *preferred_username = NULL;
    char *payload_json = NULL;

    cjose_jwk_t *key = load_rsa_private_key();
    CJOSE_CHECK(key != NULL);

    time_t now = time(NULL);
    json_t *claims = json_object();
    // 核心Claims（适配配置）
    json_object_set_new(claims, "iss", json_string(ISSUER));          // 与oidc.issuer一致
    json_object_set_new(claims, "sub", json_string(USER_ID));
    json_object_set_new(claims, "aud", json_string(CLIENT_ID));       // 与oidc.client.id一致
    json_object_set_new(claims, "iat", json_integer(now));
    json_object_set_new(claims, "exp", json_integer(now + TOKEN_EXPIRE_SEC));

    if (strcmp(token_type, "id_token") == 0) {
        // 使用提供的nonce值（客户端期望字符串类型）
        const char *nonce_value = nonce ? nonce : "";
        json_object_set_new(claims, "nonce", json_string(nonce_value));
        json_object_set_new(claims, "token_type", json_string("id_token"));
        // 适配oidc.claim=preferred_username
        preferred_username = get_preferred_username(USER_ID);
        json_object_set_new(claims, "preferred_username", json_string(preferred_username));
    } else {
        json_object_set_new(claims, "scope", json_string(OIDC_SCOPES)); // 与oidc.scopes一致
        json_object_set_new(claims, "token_type", json_string("access_token"));
    }

    // 将claims转换为JSON字符串
    payload_json = json_dumps(claims, JSON_COMPACT);
    json_decref(claims);
    if (!payload_json) {
        fprintf(stderr, "Failed to serialize claims to JSON\n");
        goto cleanup;
    }

    // 创建JWS头部
    cjose_header_t *header = cjose_header_new(&err);
    if (!header) {
        fprintf(stderr, "Failed to create JWS header: %s\n", err.message);
        goto cleanup;
    }
    cjose_header_set(header, "alg", "RS256", &err);
    if (!header) {
        fprintf(stderr, "Failed to set header algorithm: %s\n", err.message);
        goto cleanup;
    }

    // 签名JWS
    cjose_jws_t *jws = cjose_jws_sign(
        key,
        header,
        (const uint8_t*)payload_json,
        strlen(payload_json),
        &err
    );
    cjose_header_release(header);
    
    if (!jws) {
        fprintf(stderr, "Failed to sign JWT: %s\n", err.message);
        goto cleanup;
    }

    // 导出JWT字符串
    const char *jwt_raw = NULL;
    if (!cjose_jws_export(jws, &jwt_raw, &err)) {
        fprintf(stderr, "Failed to export JWT: %s\n", err.message);
        goto cleanup;
    }
    jwt_str = strdup(jwt_raw);

cleanup:
    if (preferred_username) free(preferred_username);
    if (payload_json) free(payload_json);
    if (jws) cjose_jws_release(jws);
    if (key) cjose_jwk_release(key);
    return jwt_str;
}

// 处理授权端点
static enum MHD_Result handle_authorize(struct MHD_Connection *conn) {
    // 校验redirect_uri（适配配置）
    const char *req_redirect_uri = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "redirect_uri");
    if (req_redirect_uri && strcmp(req_redirect_uri, REDIRECT_URI) != 0) {
        const char *err = "{\"error\":\"invalid_redirect_uri\"}";
        struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Content-Type", "application/json");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_BAD_REQUEST, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    // 清理过期的授权码
    cleanup_expired_auth_codes();
    
    // 生成授权码
    char *auth_code = generate_auth_code();
    
    // 获取客户端提供的nonce参数
    const char *req_nonce = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "nonce");
    if (!req_nonce) {
        req_nonce = "";
    }
    
    // 保存授权码和nonce的关联
    save_auth_code_nonce(auth_code, req_nonce);
    
    char redirect_url[1024];
    const char *req_state = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "state");
    
    // 优化state参数处理：无state时不拼接
    if (req_state) {
        snprintf(redirect_url, sizeof(redirect_url),
                "%s?code=%s&state=%s",
                REDIRECT_URI, 
                auth_code,
                req_state);
    } else {
        snprintf(redirect_url, sizeof(redirect_url),
                "%s?code=%s",
                REDIRECT_URI, 
                auth_code);
    }

    struct MHD_Response *resp = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(resp, MHD_HTTP_HEADER_LOCATION, redirect_url);
    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_FOUND, resp);
    MHD_destroy_response(resp);
    free(auth_code);
    return ret;
}

// 定义调试用的参数遍历回调函数
static enum MHD_Result debug_post_params(void *cls, enum MHD_ValueKind kind, const char *key, const char *value) {
    printf("DEBUG: All POST parameters: key='%s', value='%s'\n", key, value);
    return MHD_YES;
}

// 定义连接状态结构
struct connection_info_struct {
    char *post_data;
    size_t post_data_size;
};

// 释放连接状态
static void free_connection_info(void *cls) {
    struct connection_info_struct *con_info = (struct connection_info_struct *)cls;
    if (con_info) {
        if (con_info->post_data) {
            free(con_info->post_data);
        }
        free(con_info);
    }
}

// 解析表单数据中的code参数
static char* parse_code_from_form_data(const char *form_data) {
    if (!form_data) return NULL;
    
    // 查找code参数
    const char *code_pos = strstr(form_data, "code=");
    if (!code_pos) return NULL;
    
    // 定位值的开始位置
    code_pos += 5; // "code="的长度
    
    // 查找值的结束位置（&或字符串结束）
    const char *end_pos = strchr(code_pos, '&');
    if (!end_pos) {
        end_pos = code_pos + strlen(code_pos);
    }
    
    // 提取code值
    size_t code_len = end_pos - code_pos;
    char *code = (char *)malloc(code_len + 1);
    if (!code) return NULL;
    
    strncpy(code, code_pos, code_len);
    code[code_len] = '\0';
    
    return code;
}

// 处理令牌端点 - 修复POST参数解析
static enum MHD_Result handle_token(struct MHD_Connection *conn, const char *upload_data, size_t *upload_data_size, void **con_cls) {
    struct connection_info_struct *con_info = NULL;
    char *auth_code = NULL;
    
    // 初始化连接状态
    if (*con_cls == NULL) {
        con_info = (struct connection_info_struct *)malloc(sizeof(struct connection_info_struct));
        if (!con_info) {
            return MHD_NO;
        }
        
        con_info->post_data = NULL;
        con_info->post_data_size = 0;
        *con_cls = con_info;
        
        // 设置连接结束时的资源释放回调
        MHD_add_response_header(MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT), "Content-Type", "application/json");
        MHD_queue_response(conn, MHD_HTTP_OK, NULL);
        
        return MHD_YES;
    }
    
    con_info = (struct connection_info_struct *)*con_cls;
    
    // 接收POST数据
    if (*upload_data_size > 0) {
        // 重新分配内存以容纳新数据
        char *new_data = (char *)realloc(con_info->post_data, con_info->post_data_size + *upload_data_size + 1);
        if (!new_data) {
            free_connection_info(con_info);
            *con_cls = NULL;
            return MHD_NO;
        }
        
        con_info->post_data = new_data;
        memcpy(con_info->post_data + con_info->post_data_size, upload_data, *upload_data_size);
        con_info->post_data_size += *upload_data_size;
        con_info->post_data[con_info->post_data_size] = '\0';
        
        // 标记数据已处理
        *upload_data_size = 0;
        
        return MHD_YES;
    }
    
    // 所有数据接收完成，解析参数
    if (con_info->post_data && con_info->post_data_size > 0) {
        printf("DEBUG: Received POST data: '%s'\n", con_info->post_data);
        
        // 解析code参数
        auth_code = parse_code_from_form_data(con_info->post_data);
        
        if (auth_code) {
            printf("DEBUG: Found 'code' parameter with value: '%s'\n", auth_code);
        } else {
            printf("DEBUG: No 'code' parameter found in POST data\n");
        }
    } else {
        printf("DEBUG: No POST data received\n");
    }
    
    // 检查授权码是否存在
    if (!auth_code || strlen(auth_code) == 0) {
        const char *err = "{\"error\":\"invalid_request\",\"error_description\":\"Missing authorization code\"}";
        struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Content-Type", "application/json");
        MHD_queue_response(conn, MHD_HTTP_BAD_REQUEST, resp);
        MHD_destroy_response(resp);
        goto cleanup;
    }

    // 根据授权码查找关联的nonce
    char *nonce = find_nonce_by_auth_code(auth_code);
    if (!nonce) {
        const char *err = "{\"error\":\"invalid_request\",\"error_description\":\"Invalid or expired authorization code\"}";
        struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Content-Type", "application/json");
        MHD_queue_response(conn, MHD_HTTP_BAD_REQUEST, resp);
        MHD_destroy_response(resp);
        goto cleanup;
    }

    // 生成Token
    char *id_token = generate_jwt("id_token", nonce);
    char *access_token = generate_jwt("access_token", NULL);
    if (!id_token || !access_token) {
        const char *err = "{\"error\":\"server_error\",\"error_description\":\"Failed to generate token\"}";
        struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Content-Type", "application/json");
        MHD_queue_response(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, resp);
        MHD_destroy_response(resp);
        goto cleanup;
    }

    // 构造响应
    json_t *resp_json = json_object();
    json_object_set_new(resp_json, "access_token", json_string(access_token));
    json_object_set_new(resp_json, "token_type", json_string("Bearer"));
    json_object_set_new(resp_json, "expires_in", json_integer(TOKEN_EXPIRE_SEC));
    json_object_set_new(resp_json, "id_token", json_string(id_token));

    char *json_str = json_dumps(resp_json, JSON_INDENT(2));
    json_decref(resp_json);

    struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(json_str), (void*)json_str, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(resp, "Content-Type", "application/json");
    MHD_add_response_header(resp, "Cache-Control", "no-store");
    MHD_add_response_header(resp, "Pragma", "no-cache");
    MHD_queue_response(conn, MHD_HTTP_OK, resp);
    
    MHD_destroy_response(resp);
    free(json_str);

cleanup:
    // 释放资源
    if (auth_code) free(auth_code);
    if (nonce) free(nonce);
    if (id_token) free(id_token);
    if (access_token) free(access_token);
    free_connection_info(con_info);
    *con_cls = NULL;
    
    return MHD_YES;
}

// 处理OIDC发现端点（适配配置）
static enum MHD_Result handle_well_known(struct MHD_Connection *conn) {
    char config[2048];
    snprintf(config, sizeof(config),
             "{"
             "\"issuer\":\"%s\","
             "\"authorization_endpoint\":\"%s/authorize\","
             "\"token_endpoint\":\"%s/token\","
             "\"jwks_uri\":\"%s/jwks\","
             "\"response_types_supported\":[\"code\"],"
             "\"subject_types_supported\":[\"public\"],"
             "\"id_token_signing_alg_values_supported\":[\"RS256\"],"
             "\"scopes_supported\":[\"%s\"]," // 与oidc.scopes一致
             "\"claims_supported\":[\"iss\",\"sub\",\"aud\",\"iat\",\"exp\",\"preferred_username\"]" // 与oidc.claim一致
             "}",
             ISSUER, ISSUER, ISSUER, ISSUER, OIDC_SCOPES);

    struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(config), (void*)config, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(resp, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);
    return ret;
}

// 处理JWKS端点
static enum MHD_Result handle_jwks(struct MHD_Connection *conn) {
    cjose_err err;
    char *jwks_json = NULL;
    json_t *jwks = json_object();
    json_t *keys = json_array();
    json_t *key = json_object();
    
    // 加载与签名相同的RSA私钥
    cjose_jwk_t *rsa_key = load_rsa_private_key();
    if (!rsa_key) {
        json_decref(jwks);
        json_decref(keys);
        json_decref(key);
        return MHD_NO;
    }
    
    // 从RSA密钥中提取公钥信息（使用OpenSSL直接获取）
    FILE *fp = fopen(PRIVATE_KEY_PATH, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open private key: %s\n", PRIVATE_KEY_PATH);
        cjose_jwk_release(rsa_key);
        json_decref(jwks);
        json_decref(keys);
        json_decref(key);
        return MHD_NO;
    }
    
    // 使用OpenSSL加载PEM私钥
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) {
        fprintf(stderr, "Failed to read private key with OpenSSL\n");
        cjose_jwk_release(rsa_key);
        json_decref(jwks);
        json_decref(keys);
        json_decref(key);
        return MHD_NO;
    }
    
    // 获取RSA密钥指针
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if (!rsa) {
        fprintf(stderr, "Failed to get RSA key from EVP_PKEY\n");
        EVP_PKEY_free(pkey);
        cjose_jwk_release(rsa_key);
        json_decref(jwks);
        json_decref(keys);
        json_decref(key);
        return MHD_NO;
    }
    
    // 提取RSA公钥参数n和e
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    RSA_get0_key(rsa, &n, &e, NULL);
    
    // 将BIGNUM转换为字节数组
    size_t n_len = BN_num_bytes(n);
    size_t e_len = BN_num_bytes(e);
    
    uint8_t *n_bytes = malloc(n_len);
    uint8_t *e_bytes = malloc(e_len);
    if (!n_bytes || !e_bytes) {
        fprintf(stderr, "Failed to allocate memory for RSA params\n");
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        cjose_jwk_release(rsa_key);
        json_decref(jwks);
        json_decref(keys);
        json_decref(key);
        return MHD_NO;
    }
    
    BN_bn2bin(n, n_bytes);
    BN_bn2bin(e, e_bytes);
    
    // 自定义Base64URL编码函数
    char *base64url_encode(const uint8_t *data, size_t len) {
        BIO *bmem, *b64;
        BUF_MEM *bptr;
        
        b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // 不添加换行符
        bmem = BIO_new(BIO_s_mem());
        b64 = BIO_push(b64, bmem);
        
        // 写入数据
        BIO_write(b64, data, len);
        BIO_flush(b64);
        
        // 获取结果
        BIO_get_mem_ptr(bmem, &bptr);
        char *buff = (char *)malloc(bptr->length + 1);
        memcpy(buff, bptr->data, bptr->length);
        buff[bptr->length] = 0;
        
        // 转换为Base64URL（替换+为-，/为_，去除=）
        for (size_t i = 0; i < bptr->length; i++) {
            switch (buff[i]) {
                case '+': buff[i] = '-'; break;
                case '/': buff[i] = '_'; break;
                case '=': buff[i] = 0; break; // 遇到=直接终止字符串
            }
        }
        
        BIO_free_all(b64);
        return buff;
    }
    
    // 将n和e转换为Base64URL编码
    char *n_b64url = base64url_encode(n_bytes, n_len);
    char *e_b64url = base64url_encode(e_bytes, e_len);
    
    free(n_bytes);
    free(e_bytes);
    RSA_free(rsa);
    EVP_PKEY_free(pkey);
    
    if (!n_b64url || !e_b64url) {
        fprintf(stderr, "Failed to encode RSA params\n");
        if (n_b64url) free(n_b64url);
        if (e_b64url) free(e_b64url);
        cjose_jwk_release(rsa_key);
        json_decref(jwks);
        json_decref(keys);
        json_decref(key);
        return MHD_NO;
    }
    
    // 构建JWK
    json_object_set_new(key, "kty", json_string("RSA"));
    json_object_set_new(key, "alg", json_string("RS256"));
    json_object_set_new(key, "use", json_string("sig"));
    json_object_set_new(key, "kid", json_string("demo-key-1"));
    json_object_set_new(key, "n", json_string(n_b64url));
    json_object_set_new(key, "e", json_string(e_b64url));
    
    // 构建JWKS
    json_array_append_new(keys, key);
    json_object_set_new(jwks, "keys", keys);
    
    // 转换为JSON字符串
    jwks_json = json_dumps(jwks, JSON_COMPACT);
    if (!jwks_json) {
        fprintf(stderr, "Failed to serialize JWKS\n");
        free(n_b64url);
        free(e_b64url);
        cjose_jwk_release(rsa_key);
        json_decref(jwks);
        return MHD_NO;
    }
    
    // 创建响应
    struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(jwks_json), (void*)jwks_json, MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(resp, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);
    
    // 释放资源
    free(n_b64url);
    free(e_b64url);
    cjose_jwk_release(rsa_key);
    json_decref(jwks);
    
    return ret;
}

// 主请求处理器
static enum MHD_Result request_handler(void *cls, struct MHD_Connection *conn,
                                       const char *url, const char *method,
                                       const char *version, const char *upload_data,
                                       size_t *upload_data_size, void **con_cls) {
    // 处理跨域OPTIONS请求
    if (strcmp(method, "OPTIONS") == 0) {
        struct MHD_Response *resp = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
        MHD_add_response_header(resp, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        MHD_add_response_header(resp, "Access-Control-Allow-Headers", "Content-Type, Authorization");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    // 路由分发
    if (strcmp(url, "/authorize") == 0 && strcmp(method, "GET") == 0) {
        return handle_authorize(conn);
    } else if (strcmp(url, "/token") == 0 && strcmp(method, "POST") == 0) {
        return handle_token(conn, upload_data, upload_data_size, con_cls);
    } else if (strcmp(url, "/.well-known/openid-configuration") == 0 && strcmp(method, "GET") == 0) {
        return handle_well_known(conn);
    } else if (strcmp(url, "/jwks") == 0 && strcmp(method, "GET") == 0) {
        return handle_jwks(conn);
    } else {
        const char *not_found = "{\"error\":\"not_found\",\"error_description\":\"Resource not found\"}";
        struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(not_found), (void*)not_found, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Content-Type", "application/json");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_NOT_FOUND, resp);
        MHD_destroy_response(resp);
        return ret;
    }
}

int main() {
    // 初始化OpenSSL（避免内存泄漏）
    OpenSSL_add_all_algorithms();

    // 启动MHD服务器
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;  // 监听所有接口
    addr.sin_port = htons(OIDC_SERVER_PORT);

    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_SELECT_INTERNALLY,
        OIDC_SERVER_PORT,
        NULL, NULL,
        &request_handler, NULL,
        MHD_OPTION_SOCK_ADDR, &addr,
        MHD_OPTION_LISTENING_ADDRESS_REUSE, 1,
        MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)30,  // 设置30秒连接超时
        MHD_OPTION_END
    );

    if (!daemon) {
        fprintf(stderr, "Failed to start OIDC server on %s:%d\n", OIDC_SERVER_IP, OIDC_SERVER_PORT);
        return EXIT_FAILURE;
    }

    printf("=== OIDC Server (适配你的配置) ===\n");
    printf("运行地址: http://%s:%d\n", OIDC_SERVER_IP, OIDC_SERVER_PORT);
    printf("配置匹配项:\n");
    printf("  - oidc.issuer: %s\n", ISSUER);
    printf("  - oidc.client.id: %s\n", CLIENT_ID);
    printf("  - oidc.scopes: %s\n", OIDC_SCOPES);
    printf("  - oidc.claim: preferred_username\n");
    printf("端点:\n");
    printf("  - 授权: /authorize\n");
    printf("  - 令牌: /token\n");
    printf("  - 发现: /.well-known/openid-configuration\n");
    printf("按Enter停止服务...\n");

    getchar();
    
    // 停止服务器并清理资源
    MHD_stop_daemon(daemon);
    EVP_cleanup();
    printf("服务已停止\n");
    return EXIT_SUCCESS;
}
