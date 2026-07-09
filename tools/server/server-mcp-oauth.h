#pragma once

#include "server-common.h"
#include "http.h"

#include <mutex>
#include <string>
#include <unordered_map>

struct mcp_oauth_token {
    std::string access_token;
    std::string token_type;
    int64_t     expires_in = 0;
    int64_t     expires_at = 0;
    std::string refresh_token;
    std::string scope;
    std::string resource;
};

struct mcp_oauth_session {
    std::string client_id;
    std::string client_secret;
    std::string authorization_endpoint;
    std::string token_endpoint;
    std::string registration_endpoint;
    std::string resource_metadata_url;
    std::string code_verifier;
    std::string redirect_uri;

    std::mutex mutex;
    mcp_oauth_token current_token;
    bool token_loaded = false;

    bool load_token(const std::string & cache_key, const std::string & store_path);
    bool save_token(const std::string & cache_key, const std::string & store_path);

    bool discover_resource_metadata(const std::string & mcp_server_url);
    bool discover_authorization_server();
    bool dynamic_client_registration();

    std::string start_authorization(const std::string & redirect_uri, const std::string & state);
    bool exchange_code(const std::string & code, const std::string & redirect_uri);
    bool refresh();

    bool is_token_valid() const;
    std::string get_authorization_header() const;

    static std::string generate_code_verifier();
    static std::string generate_code_challenge(const std::string & verifier);
    static std::string generate_state();
};
