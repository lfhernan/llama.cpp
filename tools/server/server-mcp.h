#pragma once

#include "server-common.h"
#include "server-http.h"
#include "server-tools.h"
#include "server-mcp-oauth.h"

#include <memory>
#include <mutex>
#include <string>
#include <vector>

struct mcp_server_config {
    std::string id;
    std::string url;
    std::vector<std::string> scopes;
    std::string client_id;
    std::string client_secret;
    bool disabled = false;
};

struct mcp_client;

struct mcp_tool : server_tool {
    std::string server_id;
    json        input_schema;
    mcp_client * client_ptr;

    mcp_tool(const std::string & sid, const std::string & tname, const json & schema, mcp_client * client);

    json get_definition() const override;
    json invoke(json params, stream * st = nullptr) const override;
};

enum mcp_client_state {
    MCP_CLIENT_STATE_DISCONNECTED,
    MCP_CLIENT_STATE_NEEDS_AUTH,
    MCP_CLIENT_STATE_CONNECTED,
    MCP_CLIENT_STATE_ERROR,
};

struct mcp_client {
    mcp_server_config cfg;
    mcp_client_state  state = MCP_CLIENT_STATE_DISCONNECTED;
    std::string       last_error;
    std::mutex        mutex;

    std::string session_id;
    std::string token_store_path;
    std::string redirect_uri;
    std::vector<std::unique_ptr<mcp_tool>> tools;
    std::unique_ptr<mcp_oauth_session> oauth;

    bool connect();
    bool connect_with_auth();
    void list_tools();
    json call_tool(const std::string & tool_name, const json & arguments);
    json get_status() const;

    json json_rpc(const std::string & method, const json & params = json::object());
};

struct mcp_oauth_pending {
    std::string server_id;
    std::string code_verifier;
};

struct server_mcp {
    std::vector<std::unique_ptr<mcp_client>> clients;
    std::string token_store_path;
    std::string redirect_uri;
    std::unordered_map<std::string, mcp_oauth_pending> pending_authorizations;

    void setup(const std::vector<mcp_server_config> & configs, const std::string & token_store_path, const std::string & redirect_uri, bool oauth_interactive);
    std::vector<std::unique_ptr<server_tool>> collect_tools();

    server_http_context::handler_t handle_get_servers;
    server_http_context::handler_t handle_authorize;
    server_http_context::handler_t handle_oauth_callback;
};
