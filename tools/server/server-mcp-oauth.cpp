#include "server-mcp-oauth.h"

#include <cpp-httplib/httplib.h>

#include <chrono>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>

#ifndef _WIN32
#include <sys/stat.h>
#include <sys/types.h>
#endif

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <openssl/rand.h>
#include <openssl/sha.h>
#endif

static std::string url_encode(const std::string & input) {
    std::ostringstream encoded;
    encoded << std::hex << std::uppercase;
    for (char c : input) {
        if (isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' || c == '~') {
            encoded << c;
        } else {
            encoded << '%' << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
        }
    }
    encoded << std::dec;
    return encoded.str();
}

static std::string url_decode(const std::string & input) {
    std::string result;
    for (size_t i = 0; i < input.size(); i++) {
        if (input[i] == '%' && i + 2 < input.size()) {
            std::string hex = input.substr(i + 1, 2);
            char c = static_cast<char>(std::stoi(hex, nullptr, 16));
            result += c;
            i += 2;
        } else if (input[i] == '+') {
            result += ' ';
        } else {
            result += input[i];
        }
    }
    return result;
}

static std::string sha256(const std::string & input) {
#ifdef _WIN32
    BYTE hash[32];
    HCRYPTPROV hProv;
    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return "";
    }
    HCRYPTHASH hHash;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }
    if (!CryptHashData(hHash, reinterpret_cast<const BYTE *>(input.c_str()), static_cast<DWORD>(input.size()), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    DWORD hash_len = sizeof(hash);
    std::string result;
    if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hash_len, 0)) {
        std::ostringstream oss;
        oss << std::hex << std::nouppercase;
        for (DWORD i = 0; i < hash_len; i++) {
            oss << std::setfill('0') << std::setw(2) << static_cast<int>(hash[i]);
        }
        result = oss.str();
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
#else
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(input.c_str()), input.size(), hash);
    std::ostringstream oss;
    oss << std::hex << std::nouppercase;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        oss << std::setfill('0') << std::setw(2) << static_cast<int>(hash[i]);
    }
    return oss.str();
#endif
}

static std::string sha256_raw(const std::string & input) {
#ifdef _WIN32
    BYTE hash[32];
    HCRYPTPROV hProv;
    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return "";
    }
    HCRYPTHASH hHash;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }
    if (!CryptHashData(hHash, reinterpret_cast<const BYTE *>(input.c_str()), static_cast<DWORD>(input.size()), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    DWORD hash_len = sizeof(hash);
    if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hash_len, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return std::string(reinterpret_cast<char *>(hash), hash_len);
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return "";
#else
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(input.c_str()), input.size(), hash);
    return std::string(reinterpret_cast<char *>(hash), SHA256_DIGEST_LENGTH);
#endif
}

static std::string base64url_encode(const std::string & input) {
    const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string result;
    int32_t val = 0;
    int32_t bits_left = 0;
    for (unsigned char c : input) {
        val = (val << 8) | c;
        bits_left += 8;
        while (bits_left >= 6) {
            bits_left -= 6;
            result += table[(val >> bits_left) & 0x3F];
        }
    }
    if (bits_left > 0) {
        result += table[(val << (6 - bits_left)) & 0x3F];
    }
    return result;
}

static std::string random_bytes_string(size_t len) {
    std::string result(len, '\0');
#ifdef _WIN32
    HCRYPTPROV hProv;
    if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, len, reinterpret_cast<BYTE *>(result.data()));
        CryptReleaseContext(hProv, 0);
    }
#else
    RAND_bytes(reinterpret_cast<unsigned char *>(result.data()), len);
#endif
    return result;
}

static std::string parse_query_param(const std::string & query, const std::string & key) {
    std::string search = key + "=";
    size_t pos = query.find(search);
    if (pos == std::string::npos) return "";
    pos += search.size();
    size_t end = query.find('&', pos);
    if (end == std::string::npos) end = query.size();
    return url_decode(query.substr(pos, end - pos));
}

static bool ensure_parent_directory(const std::string & path) {
    size_t pos = std::string::npos;
    for (int i = static_cast<int>(path.size()) - 1; i >= 0; i--) {
        if (path[i] == '/' || path[i] == '\\') {
            pos = static_cast<size_t>(i);
            break;
        }
    }
    if (pos == std::string::npos || pos == 0) return true;
    std::string dir = path.substr(0, pos);
#ifdef _WIN32
    return CreateDirectoryA(dir.c_str(), nullptr) != 0 || GetLastError() == ERROR_ALREADY_EXISTS;
#else
    struct stat st;
    if (stat(dir.c_str(), &st) == 0) return true;
    return mkdir(dir.c_str(), 0700) == 0;
#endif
}

static bool set_file_permissions(const std::string & path) {
#ifdef _WIN32
    (void)path;
    return true;
#else
    return chmod(path.c_str(), S_IRUSR | S_IWUSR) == 0;
#endif
}

static bool check_file_permissions_safe(const std::string & path) {
#ifdef _WIN32
    (void)path;
    return true;
#else
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return false;
    return (st.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) == 0;
#endif
}

bool mcp_oauth_session::load_token(const std::string & /*cache_key*/, const std::string & store_path) {
    if (store_path.empty()) return false;
    if (!check_file_permissions_safe(store_path)) {
        SRV_WRN("MCP token file '%s' has overly permissive permissions - tokens may be exposed\n", store_path.c_str());
    }
    std::ifstream f(store_path);
    if (!f) return false;
    try {
        json j = json::parse(f);
        current_token.access_token  = j.value("access_token", std::string{});
        current_token.token_type    = j.value("token_type", "Bearer");
        current_token.expires_in    = j.value("expires_in", 0);
        current_token.expires_at    = j.value("expires_at", 0);
        current_token.refresh_token = j.value("refresh_token", std::string{});
        current_token.scope         = j.value("scope", std::string{});
        current_token.resource      = j.value("resource", std::string{});
        client_id                   = j.value("client_id", client_id);
        client_secret               = j.value("client_secret", client_secret);
        token_loaded = !current_token.access_token.empty();
        return token_loaded;
    } catch (...) {
        return false;
    }
}

bool mcp_oauth_session::save_token(const std::string & /*cache_key*/, const std::string & store_path) {
    if (store_path.empty()) return false;
    if (!ensure_parent_directory(store_path)) {
        SRV_ERR("MCP token store: cannot create directory for '%s'\n", store_path.c_str());
        return false;
    }
    json j = {
        {"access_token",  current_token.access_token},
        {"token_type",    current_token.token_type},
        {"expires_in",    current_token.expires_in},
        {"expires_at",    current_token.expires_at},
        {"refresh_token", current_token.refresh_token},
        {"scope",         current_token.scope},
        {"resource",      current_token.resource},
        {"client_id",     client_id},
        {"client_secret", client_secret},
    };
    std::ofstream f(store_path, std::ios::trunc);
    if (!f.good()) return false;
    f << j.dump(2);
    f.close();
    set_file_permissions(store_path);
    return true;
}

bool mcp_oauth_session::discover_resource_metadata(const std::string & mcp_server_url) {
    try {
        auto [cli, parts] = common_http_client(mcp_server_url + "/.well-known/oauth-protected-resource");
        cli.set_connection_timeout(10, 0);
        cli.set_read_timeout(10, 0);
        cli.set_write_timeout(10, 0);
        auto res = cli.Get("/.well-known/oauth-protected-resource");
        if (!res || res->status != 200) return false;
        json prm = json::parse(res->body);
        if (prm.contains("authorization_servers") && prm["authorization_servers"].is_array()) {
            auto servers = prm["authorization_servers"];
            if (!servers.empty() && servers[0].is_string()) {
                authorization_endpoint = servers[0].get<std::string>();
                return true;
            }
        }
        return false;
    } catch (...) {
        return false;
    }
}

bool mcp_oauth_session::discover_authorization_server() {
    if (authorization_endpoint.empty()) return false;
    try {
        auto [cli, parts] = common_http_client(authorization_endpoint);
        cli.set_connection_timeout(10, 0);
        cli.set_read_timeout(10, 0);
        cli.set_write_timeout(10, 0);
        auto res = cli.Get("/.well-known/oauth-authorization-server");
        if (!res || res->status != 200) return false;
        json as = json::parse(res->body);
        authorization_endpoint  = as.value("authorization_endpoint", authorization_endpoint);
        token_endpoint          = as.value("token_endpoint", std::string{});
        registration_endpoint   = as.value("registration_endpoint", std::string{});
        return !token_endpoint.empty();
    } catch (...) {
        return false;
    }
}

bool mcp_oauth_session::dynamic_client_registration() {
    if (registration_endpoint.empty()) return false;
    try {
        auto [cli, parts] = common_http_client(registration_endpoint);
        cli.set_connection_timeout(10, 0);
        cli.set_read_timeout(10, 0);
        cli.set_write_timeout(10, 0);
        json reg_req = {
            {"token_endpoint_auth_method", "none"},
            {"grant_types", json::array({"authorization_code", "refresh_token"})},
            {"response_types", json::array({"code"})},
        };
        if (!redirect_uri.empty()) {
            reg_req["redirect_uris"] = json::array({redirect_uri});
        }
        auto res = cli.Post(
            parts.path.empty() ? "/" : parts.path,
            safe_json_to_str(reg_req),
            "application/json"
        );
        if (!res || res->status != 201) return false;
        json reg_resp = json::parse(res->body);
        client_id     = reg_resp.value("client_id", std::string{});
        client_secret = reg_resp.value("client_secret", std::string{});
        return !client_id.empty();
    } catch (...) {
        return false;
    }
}

std::string mcp_oauth_session::start_authorization(const std::string & redirect_uri, const std::string & state) {
    code_verifier = generate_code_verifier();
    std::string challenge = generate_code_challenge(code_verifier);
    std::string auth_url = authorization_endpoint + "?"
        + "response_type=code"
        + "&client_id=" + url_encode(client_id)
        + "&redirect_uri=" + url_encode(redirect_uri)
        + "&scope=openid"
        + "&state=" + url_encode(state)
        + "&code_challenge=" + url_encode(challenge)
        + "&code_challenge_method=S256";
    if (!current_token.resource.empty()) {
        auth_url += "&resource=" + url_encode(current_token.resource);
    }
    return auth_url;
}

bool mcp_oauth_session::exchange_code(const std::string & code, const std::string & redirect_uri) {
    if (token_endpoint.empty() || code_verifier.empty()) return false;
    try {
        auto [cli, parts] = common_http_client(token_endpoint);
        cli.set_connection_timeout(15, 0);
        cli.set_read_timeout(15, 0);
        cli.set_write_timeout(15, 0);
        std::string body = std::string("grant_type=authorization_code")
            + "&code=" + url_encode(code)
            + "&redirect_uri=" + url_encode(redirect_uri)
            + "&client_id=" + url_encode(client_id)
            + "&code_verifier=" + url_encode(code_verifier);
        if (!current_token.resource.empty()) {
            body += "&resource=" + url_encode(current_token.resource);
        }
        auto res = cli.Post(
            parts.path.empty() ? "/" : parts.path,
            body,
            "application/x-www-form-urlencoded"
        );
        if (!res || res->status != 200) return false;
        json tok = json::parse(res->body);
        current_token.access_token  = tok.value("access_token", std::string{});
        current_token.token_type    = tok.value("token_type", "Bearer");
        current_token.expires_in    = tok.value("expires_in", 0);
        current_token.expires_at    = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()
            + current_token.expires_in;
        current_token.refresh_token = tok.value("refresh_token", std::string{});
        current_token.scope         = tok.value("scope", std::string{});
        current_token.resource      = tok.value("resource", current_token.resource);
        return !current_token.access_token.empty();
    } catch (...) {
        return false;
    }
}

bool mcp_oauth_session::refresh() {
    if (token_endpoint.empty() || current_token.refresh_token.empty()) return false;
    std::lock_guard<std::mutex> lock(mutex);
    try {
        auto [cli, parts] = common_http_client(token_endpoint);
        cli.set_connection_timeout(15, 0);
        cli.set_read_timeout(15, 0);
        cli.set_write_timeout(15, 0);
        std::string body = std::string("grant_type=refresh_token")
            + "&refresh_token=" + url_encode(current_token.refresh_token)
            + "&client_id=" + url_encode(client_id);
        if (!current_token.resource.empty()) {
            body += "&resource=" + url_encode(current_token.resource);
        }
        auto res = cli.Post(
            parts.path.empty() ? "/" : parts.path,
            body,
            "application/x-www-form-urlencoded"
        );
        if (!res || res->status != 200) return false;
        json tok = json::parse(res->body);
        current_token.access_token  = tok.value("access_token", current_token.access_token);
        current_token.expires_in    = tok.value("expires_in", current_token.expires_in);
        current_token.expires_at    = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()
            + current_token.expires_in;
        current_token.refresh_token = tok.value("refresh_token", current_token.refresh_token);
        current_token.resource      = tok.value("resource", current_token.resource);
        return !current_token.access_token.empty();
    } catch (...) {
        return false;
    }
}

bool mcp_oauth_session::is_token_valid() const {
    if (current_token.access_token.empty()) return false;
    if (current_token.expires_at == 0) return true;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return now < (current_token.expires_at - 60);
}

std::string mcp_oauth_session::get_authorization_header() const {
    if (current_token.access_token.empty()) return "";
    return current_token.token_type + " " + current_token.access_token;
}

std::string mcp_oauth_session::generate_code_verifier() {
    return base64url_encode(random_bytes_string(32));
}

std::string mcp_oauth_session::generate_code_challenge(const std::string & verifier) {
    return base64url_encode(sha256_raw(verifier));
}

std::string mcp_oauth_session::generate_state() {
    return base64url_encode(random_bytes_string(16));
}
