#include "server-mcp.h"
#include "http.h"

#include <algorithm>
#include <cassert>
#include <sstream>

mcp_tool::mcp_tool(const std::string & sid, const std::string & tname, const json & schema, mcp_client * client)
    : server_id(sid), input_schema(schema), client_ptr(client) {
    name = "mcp:" + sid + ":" + tname;
    display_name = tname;
    permission_write = true;
}

json mcp_tool::get_definition() const {
    json func_def = json::object();
    if (input_schema.contains("name")) {
        func_def["name"] = input_schema["name"];
    }
    if (input_schema.contains("description")) {
        func_def["description"] = input_schema["description"];
    }
    if (input_schema.contains("inputSchema")) {
        func_def["parameters"] = input_schema["inputSchema"];
    } else {
        func_def["parameters"] = {{"type", "object"}, {"properties", json::object()}};
    }
    return {
        {"type", "function"},
        {"function", func_def},
    };
}

json mcp_tool::invoke(json params, stream *) const {
    if (!client_ptr) {
        return {{"error", "MCP client not available"}};
    }
    return client_ptr->call_tool(name, params);
}

bool mcp_client::connect() {
    std::lock_guard<std::mutex> lock(mutex);
    try {
        auto [cli, url_parts] = common_http_client(cfg.url);
        cli.set_connection_timeout(10, 0);
        cli.set_read_timeout(10, 0);
        cli.set_write_timeout(10, 0);

        json init_req = {
            {"jsonrpc", "2.0"},
            {"id", 1},
            {"method", "initialize"},
            {"params", {
                {"protocolVersion", "2024-11-05"},
                {"capabilities", json::object()},
                {"clientInfo", {
                    {"name", "llama.cpp"},
                    {"version", "0.1.0"},
                }},
            }},
        };

        auto res = cli.Post(
            url_parts.path.empty() ? "/" : url_parts.path,
            safe_json_to_str(init_req),
            "application/json"
        );

        if (!res || res->status != 200) {
            if (res && res->status == 401) {
                state = MCP_CLIENT_STATE_NEEDS_AUTH;
                last_error = "MCP server requires authentication";
                return false;
            }
            state = MCP_CLIENT_STATE_ERROR;
            last_error = string_format("MCP initialize failed with status %d", res ? res->status : 0);
            return false;
        }

        json resp = json::parse(res->body);
        if (resp.contains("error")) {
            state = MCP_CLIENT_STATE_ERROR;
            last_error = "MCP initialize error: " + resp["error"].dump();
            return false;
        }

        if (resp.contains("result") && resp["result"].contains("capabilities")) {
            session_id = random_string();
            state = MCP_CLIENT_STATE_CONNECTED;
            last_error.clear();
            return true;
        }

        state = MCP_CLIENT_STATE_ERROR;
        last_error = "MCP initialize response missing result.capabilities";
        return false;
    } catch (const std::exception & e) {
        state = MCP_CLIENT_STATE_ERROR;
        last_error = std::string("MCP connect exception: ") + e.what();
        return false;
    }
}

bool mcp_client::connect_with_auth() {
    if (!oauth) {
        oauth = std::make_unique<mcp_oauth_session>();
    }
    oauth->current_token.resource = cfg.url;

    if (!cfg.client_id.empty()) {
        oauth->client_id = cfg.client_id;
        oauth->client_secret = cfg.client_secret;
    }

    std::string token_path = token_store_path + "/" + cfg.id + ".json";
    if (oauth->load_token(cfg.id, token_path)) {
        if (oauth->is_token_valid()) {
            return connect();
        }
        if (oauth->refresh()) {
            oauth->save_token(cfg.id, token_path);
            return connect();
        }
    }

    if (!oauth->discover_resource_metadata(cfg.url)) {
        last_error = "OAuth resource metadata discovery failed";
        state = MCP_CLIENT_STATE_ERROR;
        return false;
    }

    if (!oauth->discover_authorization_server()) {
        last_error = "OAuth authorization server discovery failed";
        state = MCP_CLIENT_STATE_ERROR;
        return false;
    }

    oauth->redirect_uri = redirect_uri;
    if (cfg.client_id.empty() && !oauth->dynamic_client_registration()) {
        last_error = "OAuth dynamic client registration failed and no client_id configured";
        state = MCP_CLIENT_STATE_ERROR;
        return false;
    }

    state = MCP_CLIENT_STATE_NEEDS_AUTH;
    last_error = "OAuth interactive authorization required";
    return false;
}

json mcp_client::json_rpc(const std::string & method, const json & params) {
    std::lock_guard<std::mutex> lock(mutex);
    try {
        auto [cli, url_parts] = common_http_client(cfg.url);
        cli.set_connection_timeout(30, 0);
        cli.set_read_timeout(30, 0);
        cli.set_write_timeout(30, 0);

        json req = {
            {"jsonrpc", "2.0"},
            {"id", (int) (std::hash<std::string>{}(method) & 0xFFFFFFFF)},
            {"method", method},
            {"params", params},
        };

        auto headers = httplib::Headers();
        if (oauth && oauth->is_token_valid()) {
            std::string auth_header = oauth->get_authorization_header();
            if (!auth_header.empty()) {
                headers.emplace("Authorization", auth_header);
            }
        }

        auto res = cli.Post(
            url_parts.path.empty() ? "/" : url_parts.path,
            headers,
            safe_json_to_str(req),
            "application/json"
        );

        if (!res || res->status != 200) {
            if (res && res->status == 401) {
                if (oauth && oauth->refresh()) {
                    std::string token_path = token_store_path + "/" + cfg.id + ".json";
                    oauth->save_token(cfg.id, token_path);
                    headers.emplace("Authorization", oauth->get_authorization_header());
                    res = cli.Post(
                        url_parts.path.empty() ? "/" : url_parts.path,
                        headers,
                        safe_json_to_str(req),
                        "application/json"
                    );
                    if (res && res->status == 200) {
                        json resp = json::parse(res->body);
                        if (resp.contains("error")) {
                            return {{"error", resp["error"].dump()}};
                        }
                        return resp.value("result", json::object());
                    }
                }
                state = MCP_CLIENT_STATE_NEEDS_AUTH;
                last_error = "MCP server returned 401, authentication required";
                return {{"error", "authentication required"}};
            }
            return {{"error", string_format("MCP request failed with status %d", res ? res->status : 0)}};
        }

        json resp = json::parse(res->body);
        if (resp.contains("error")) {
            return {{"error", resp["error"].dump()}};
        }
        return resp.value("result", json::object());
    } catch (const std::exception & e) {
        return {{"error", std::string("MCP request exception: ") + e.what()}};
    }
}

void mcp_client::list_tools() {
    tools.clear();
    json result = json_rpc("tools/list");
    if (result.contains("error")) {
        return;
    }

    if (result.contains("tools") && result["tools"].is_array()) {
        for (const auto & t : result["tools"]) {
            auto tool = std::make_unique<mcp_tool>(cfg.id,
                t.value("name", "unknown"), t, this);
            tools.push_back(std::move(tool));
        }
    }
}

json mcp_client::call_tool(const std::string & tool_name, const json & arguments) {
    std::string raw_name = tool_name;
    size_t prefix_end = raw_name.find(':');
    if (prefix_end == std::string::npos) {
        return {{"error", "invalid MCP tool name: missing server id"}};
    }
    size_t tool_start = raw_name.find(':', prefix_end + 1);
    if (tool_start == std::string::npos) {
        return {{"error", "invalid MCP tool name: missing tool name"}};
    }
    std::string tname = raw_name.substr(tool_start + 1);

    json params = {
        {"name", tname},
    };
    if (!arguments.empty()) {
        params["arguments"] = arguments;
    }

    json result = json_rpc("tools/call", params);

    if (result.contains("error")) {
        return result;
    }

    if (result.contains("content")) {
        json content = result["content"];
        if (content.is_array()) {
            std::ostringstream oss;
            for (const auto & item : content) {
                if (item.contains("text") && item["text"].is_string()) {
                    oss << item["text"];
                } else if (item.is_string()) {
                    oss << item.get<std::string>();
                }
            }
            return {{"plain_text_response", oss.str()}};
        }
        if (content.is_string()) {
            return {{"plain_text_response", content.get<std::string>()}};
        }
    }

    return result;
}

json mcp_client::get_status() const {
    const char * state_str = "disconnected";
    switch (state) {
        case MCP_CLIENT_STATE_DISCONNECTED: state_str = "disconnected"; break;
        case MCP_CLIENT_STATE_NEEDS_AUTH:   state_str = "needs_auth";   break;
        case MCP_CLIENT_STATE_CONNECTED:    state_str = "connected";    break;
        case MCP_CLIENT_STATE_ERROR:        state_str = "error";        break;
    }
    json status = {
        {"id", cfg.id},
        {"url", cfg.url},
        {"state", state_str},
        {"tool_count", (int) tools.size()},
    };
    if (!last_error.empty()) {
        status["last_error"] = last_error;
    }
    return status;
}

void server_mcp::setup(const std::vector<mcp_server_config> & configs, const std::string & token_store_path, const std::string & redirect_uri, bool oauth_interactive) {
    this->token_store_path = token_store_path;
    this->redirect_uri = redirect_uri;
    clients.clear();
    for (const auto & cfg : configs) {
        if (cfg.disabled) continue;
        auto client = std::make_unique<mcp_client>();
        client->cfg = cfg;
        client->token_store_path = token_store_path;
        client->redirect_uri = redirect_uri;
        if (client->connect()) {
            client->list_tools();
            SRV_INF("MCP server '%s' connected, %zu tools discovered\n",
                cfg.id.c_str(), client->tools.size());
        } else if (client->state == MCP_CLIENT_STATE_NEEDS_AUTH) {
            if (!oauth_interactive) {
                SRV_ERR("MCP server '%s' requires OAuth authorization but --no-mcp-oauth is set. Skipping.\n",
                    cfg.id.c_str());
                client->state = MCP_CLIENT_STATE_ERROR;
                client->last_error = "OAuth interactive mode disabled (--no-mcp-oauth)";
            } else if (client->connect_with_auth()) {
                client->list_tools();
                SRV_INF("MCP server '%s' connected (OAuth), %zu tools discovered\n",
                    cfg.id.c_str(), client->tools.size());
            } else {
                SRV_WRN("MCP server '%s' needs authorization: %s\n",
                    cfg.id.c_str(), client->last_error.c_str());
            }
        } else {
            SRV_WRN("MCP server '%s' connection failed: %s\n",
                cfg.id.c_str(), client->last_error.c_str());
        }
        clients.push_back(std::move(client));
    }

    handle_get_servers = [this](const server_http_req &) -> server_http_res_ptr {
        auto res = std::make_unique<server_http_res>();
        try {
            json result = json::array();
            for (const auto & c : clients) {
                result.push_back(c->get_status());
            }
            res->data = safe_json_to_str(result);
        } catch (const std::exception & e) {
            SRV_ERR("mcp servers status error: %s\n", e.what());
            res->status = 500;
            res->data = safe_json_to_str(format_error_response(e.what(), ERROR_TYPE_SERVER));
        }
        return res;
    };

    handle_authorize = [this](const server_http_req & req) -> server_http_res_ptr {
        auto res = std::make_unique<server_http_res>();
        try {
            std::string server_id = req.get_param("id");
            for (auto & c : clients) {
                if (c->cfg.id == server_id) {
                    if (!c->oauth) {
                        c->oauth = std::make_unique<mcp_oauth_session>();
                    }
                    c->oauth->current_token.resource = c->cfg.url;

                    if (!c->cfg.client_id.empty()) {
                        c->oauth->client_id = c->cfg.client_id;
                        c->oauth->client_secret = c->cfg.client_secret;
                    }

                    std::string token_path = this->token_store_path + "/" + c->cfg.id + ".json";
                    if (c->oauth->load_token(c->cfg.id, token_path)) {
                        if (c->oauth->client_id.empty()) {
                            // tokens loaded but no client_id, use from file
                        }
                    }

                    if (!c->oauth->discover_resource_metadata(c->cfg.url)) {
                        res->status = 500;
                        res->data = safe_json_to_str({{"error", "OAuth resource metadata discovery failed"}});
                        return res;
                    }

                    if (!c->oauth->discover_authorization_server()) {
                        res->status = 500;
                        res->data = safe_json_to_str({{"error", "OAuth authorization server discovery failed"}});
                        return res;
                    }

                    c->oauth->redirect_uri = this->redirect_uri + "/mcp/oauth/callback";
                    if (c->oauth->client_id.empty() && !c->oauth->dynamic_client_registration()) {
                        res->status = 500;
                        res->data = safe_json_to_str({{"error", "OAuth dynamic client registration failed and no client_id configured"}});
                        return res;
                    }

                    std::string state = c->oauth->generate_state();
                    std::string auth_url = c->oauth->start_authorization(this->redirect_uri + "/mcp/oauth/callback", state);

                    pending_authorizations[state] = {c->cfg.id, c->oauth->code_verifier};

                    c->state = MCP_CLIENT_STATE_NEEDS_AUTH;
                    c->last_error = "OAuth interactive authorization required";

                    res->data = safe_json_to_str({
                        {"auth_url", auth_url},
                        {"state", state},
                    });
                    return res;
                }
            }
            res->status = 404;
            res->data = safe_json_to_str({{"error", "MCP server not found: " + server_id}});
        } catch (const std::exception & e) {
            SRV_ERR("mcp authorize error: %s\n", e.what());
            res->status = 500;
            res->data = safe_json_to_str(format_error_response(e.what(), ERROR_TYPE_SERVER));
        }
        return res;
    };

    handle_oauth_callback = [this](const server_http_req & req) -> server_http_res_ptr {
        auto res = std::make_unique<server_http_res>();
        res->content_type = "text/html; charset=utf-8";
        try {
            std::string code = req.get_param("code");
            std::string state = req.get_param("state");
            std::string error = req.get_param("error");

            if (!error.empty()) {
                res->status = 200;
                res->data = "<html><head><title>OAuth Error</title></head><body><h1>Authorization Failed</h1><p>" + error + "</p><script>window.close();</script></body></html>";
                return res;
            }

            if (code.empty() || state.empty()) {
                res->status = 400;
                res->data = "<html><head><title>OAuth Error</title></head><body><h1>Missing Parameters</h1><p>code and state parameters are required.</p><script>window.close();</script></body></html>";
                return res;
            }

            auto it = pending_authorizations.find(state);
            if (it == pending_authorizations.end()) {
                res->status = 400;
                res->data = "<html><head><title>OAuth Error</title></head><body><h1>Invalid State</h1><p>Authorization state not found or expired.</p><script>window.close();</script></body></html>";
                return res;
            }

            mcp_oauth_pending pending = std::move(it->second);
            pending_authorizations.erase(it);

            for (auto & c : clients) {
                if (c->cfg.id == pending.server_id) {
                    std::string token_path = this->token_store_path + "/" + c->cfg.id + ".json";

                    if (!c->oauth) {
                        c->oauth = std::make_unique<mcp_oauth_session>();
                    }
                    c->oauth->code_verifier = pending.code_verifier;

                    if (c->oauth->exchange_code(code, this->redirect_uri + "/mcp/oauth/callback")) {
                        c->oauth->save_token(c->cfg.id, token_path);
                        if (c->connect()) {
                            c->list_tools();
                            res->status = 200;
                            res->data = "<html><head><title>OAuth Success</title></head><body><h1>Authorization Successful</h1><p>MCP server connected successfully. You may close this window.</p><script>setTimeout(function(){ window.close(); }, 3000);</script></body></html>";
                            SRV_INF("MCP server '%s' OAuth authorized, %zu tools discovered\n",
                                c->cfg.id.c_str(), c->tools.size());
                            return res;
                        } else {
                            res->status = 200;
                            res->data = "<html><head><title>OAuth Warning</title></head><body><h1>Token Obtained</h1><p>Authorization token obtained but connection failed: " + c->last_error + ". You may close this window.</p><script>setTimeout(function(){ window.close(); }, 5000);</script></body></html>";
                            return res;
                        }
                    } else {
                        res->status = 200;
                        res->data = "<html><head><title>OAuth Error</title></head><body><h1>Token Exchange Failed</h1><p>Failed to exchange authorization code for token.</p><script>setTimeout(function(){ window.close(); }, 5000);</script></body></html>";
                        return res;
                    }
                }
            }

            res->status = 404;
            res->data = "<html><head><title>OAuth Error</title></head><body><h1>MCP Server Not Found</h1><p>The specified MCP server was not found.</p><script>window.close();</script></body></html>";
        } catch (const std::exception & e) {
            SRV_ERR("mcp oauth callback error: %s\n", e.what());
            res->status = 500;
            res->data = "<html><head><title>OAuth Error</title></head><body><h1>Server Error</h1><p>" + std::string(e.what()) + "</p><script>window.close();</script></body></html>";
        }
        return res;
    };
}

std::vector<std::unique_ptr<server_tool>> server_mcp::collect_tools() {
    std::vector<std::unique_ptr<server_tool>> all;
    for (auto & c : clients) {
        for (auto & t : c->tools) {
            all.push_back(std::move(t));
        }
        c->tools.clear();
    }
    return all;
}
