// Basic MCP server implementation for testing
export const mcpServer = {
  name: "basic-test-server",
  version: "1.0.0",
  tools: [
    {
      name: "echo-tool",
      description: "Simple echo tool",
      inputSchema: {
        type: "object",
        properties: {
          message: { type: "string" }
        }
      },
      implementation: "tools/echo.ts"
    }
  ],
  resources: [],
  prompts: []
};

export async function echoTool(params: any) {
  return { echo: params.message };
}
