import Foundation

public enum ProxymanToolClassification: String, Codable, Sendable {
    case metadataRead, sensitiveRead, export, appOnlyAction, captureChange, trafficMutation
    case securityConfiguration, processLaunch, deniedUnknown
}

/// Local classification is authoritative. Untrusted MCP annotations never grant authority.
public enum ProxymanToolPolicy {
    public static func classification(of name: String) -> ProxymanToolClassification {
        switch name {
        case "answer_setup_question", "get_certificate_status", "get_http_version_mode",
             "get_license_status", "get_network_extension_status", "get_proxy_status",
             "get_proxyman_cli_help", "get_system_proxy_status", "get_version",
             "list_custom_columns", "list_devices", "list_ios_simulators",
             "list_popular_workflows", "list_previewer_tabs", "list_setup_workflows",
             "list_tool_status", "search_docs": .metadataRead
        case "diff_flows", "filter_flows", "get_compose_http",
             "get_external_proxy", "get_flow_as", "get_flow_detail",
             "get_flow_filter", "get_flow_timing", "get_flows",
             "get_settings", "get_ssl_proxying_list", "get_traffic_overview",
             "get_websocket_messages", "list_dns_spoofing", "list_network_conditions",
             "list_pending_breakpoints", "list_reverse_proxies", "list_rule_folders",
             "list_rules", "list_websocket_sessions", "query_flow_body": .sensitiveRead
        case "export_flow_curl", "export_flows", "export_rules",
             "generate_code": .export
        case "open_session_file", "save_flow_body", "save_flows",
             "save_session": .appOnlyAction
        case "annotate_flows", "clear_session", "delete_flows",
             "pin_flows", "set_flow_filter", "set_previewer_tab",
             "toggle_recording", "update_custom_column": .captureChange
        case "close_websocket_session", "create_allow_list", "create_blacklist",
             "create_breakpoint", "create_compose_http", "create_compose_http_from_flow",
             "create_dns_spoofing", "create_map_local", "create_map_local_from_flow",
             "create_map_remote", "create_network_condition", "create_reverse_proxy",
             "create_rule_folder", "create_scripting_rule", "delete_compose_http",
             "delete_rule", "delete_rule_folder", "import_rules",
             "rename_rule_folder", "repeat_flows", "resolve_breakpoint",
             "send_compose_http", "toggle_no_caching", "toggle_rule",
             "toggle_rule_folder", "toggle_tool", "update_allow_list",
             "update_blacklist", "update_breakpoint", "update_compose_http",
             "update_dns_spoofing", "update_map_local", "update_map_remote",
             "update_network_condition", "update_reverse_proxy", "update_scripting_rule": .trafficMutation
        case "disable_ssl_proxying", "enable_ssl_proxying", "install_certificate",
             "install_ios_simulator_certificate", "install_network_extension", "retry_network_extension",
             "set_external_proxy", "set_http_version_mode", "set_network_extension_enabled",
             "set_system_proxy", "toggle_ssl_proxying_domain", "uninstall_certificate",
             "uninstall_network_extension", "update_settings": .securityConfiguration
        case "get_terminal_manual_command", "inject_electron", "inject_terminal",
             "open_proxyman", "open_proxyman_screen", "quit_proxyman",
             "run_guided_setup": .processLaunch
        default: .deniedUnknown
        }
    }

    static let implementedReads: Set<String> = [
        "get_version", "get_proxy_status", "get_flows", "get_flow_detail", "list_rules", "list_tool_status",
        "get_ssl_proxying_list", "get_certificate_status", "list_reverse_proxies", "list_dns_spoofing",
        "get_external_proxy"
    ]
    static let reviewedMutations: Set<String> = ["create_breakpoint", "create_blacklist"]
}
