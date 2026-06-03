use agentmesh_mcp::mcp as canonical_mcp;

#[allow(deprecated)]
fn expect_compat_error(_: agentmesh::mcp::McpError) {}

#[allow(deprecated)]
fn expect_compat_gateway_config(_: agentmesh::mcp::McpGatewayConfig) {}

fn expect_flattened_gateway_config(_: agentmesh::McpGatewayConfig) {}

#[test]
fn agentmesh_mcp_reexports_use_canonical_types() {
    expect_compat_error(canonical_mcp::McpError::InvalidSignature);
    expect_compat_gateway_config(canonical_mcp::McpGatewayConfig::default());
    expect_flattened_gateway_config(canonical_mcp::McpGatewayConfig::default());
}
