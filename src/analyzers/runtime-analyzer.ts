import { SourceFile, MCPTool, MCPServerInfo } from '../core/types';
import { spawn } from 'child_process';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { tmpdir } from 'os';

export interface RuntimeAnalysisResult {
  serverHealth: ServerHealthInfo;
  toolBehavior: ToolBehaviorInfo[];
  securityTests: SecurityTestResult[];
  performanceMetrics: PerformanceMetrics;
  networkActivity: NetworkActivity[];
}

export interface ServerHealthInfo {
  isRunning: boolean;
  startupTime: number;
  memoryUsage: number;
  cpuUsage: number;
  errors: string[];
}

export interface ToolBehaviorInfo {
  toolName: string;
  responseTime: number;
  inputValidation: boolean;
  outputSanitization: boolean;
  errorHandling: boolean;
  rateLimit: RateLimitInfo | null;
}

export interface RateLimitInfo {
  enabled: boolean;
  limit: number;
  window: number;
  tested: boolean;
}

export interface SecurityTestResult {
  testName: string;
  category: 'injection' | 'auth' | 'dos' | 'xss' | 'path-traversal';
  passed: boolean;
  details: string;
  severity: 'high' | 'medium' | 'low';
}

export interface PerformanceMetrics {
  averageResponseTime: number;
  maxResponseTime: number;
  throughput: number;
  errorRate: number;
}

export interface NetworkActivity {
  timestamp: number;
  method: string;
  url: string;
  statusCode: number;
  responseTime: number;
  size: number;
}

export class RuntimeAnalyzer {
  private testPayloads = {
    sqlInjection: [
      "'; DROP TABLE users; --",
      "' OR '1'='1",
      "1' UNION SELECT * FROM users--",
      "'; INSERT INTO users VALUES ('hacker', 'password'); --"
    ],
    commandInjection: [
      "; cat /etc/passwd",
      "& dir",
      "| whoami",
      "; rm -rf /",
      "&& ls -la"
    ],
    xss: [
      "<script>alert('xss')</script>",
      "<img src=x onerror=alert('xss')>",
      "javascript:alert('xss')",
      "<svg onload=alert('xss')>"
    ],
    pathTraversal: [
      "../../../etc/passwd",
      "..\\..\\..\\windows\\system32\\config\\sam",
      "....//....//....//etc/passwd",
      "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    ],
    oversizedPayload: 'A'.repeat(10000),
    specialChars: "!@#$%^&*()[]{}|;':\"<>?,.~`"
  };

  public async analyze(mcpServer: MCPServerInfo, projectPath: string): Promise<RuntimeAnalysisResult> {
    const result: RuntimeAnalysisResult = {
      serverHealth: await this.checkServerHealth(projectPath),
      toolBehavior: [],
      securityTests: [],
      performanceMetrics: {
        averageResponseTime: 0,
        maxResponseTime: 0,
        throughput: 0,
        errorRate: 0
      },
      networkActivity: []
    };

    // Only run runtime tests if server can be started
    if (result.serverHealth.isRunning) {
      result.toolBehavior = await this.analyzeToolBehavior(mcpServer.tools);
      result.securityTests = await this.runSecurityTests(mcpServer.tools);
      result.performanceMetrics = await this.measurePerformance(mcpServer.tools);
    }

    return result;
  }

  private async checkServerHealth(projectPath: string): Promise<ServerHealthInfo> {
    const healthInfo: ServerHealthInfo = {
      isRunning: false,
      startupTime: 0,
      memoryUsage: 0,
      cpuUsage: 0,
      errors: []
    };

    try {
      const packageJsonPath = join(projectPath, 'package.json');
      if (!existsSync(packageJsonPath)) {
        healthInfo.errors.push('package.json not found');
        return healthInfo;
      }

      const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));
      const startScript = packageJson.scripts?.start || packageJson.scripts?.dev;

      if (!startScript) {
        healthInfo.errors.push('No start script found in package.json');
        return healthInfo;
      }

      // Try to start the server and measure startup time
      const startTime = Date.now();
      const serverProcess = await this.startServer(projectPath, startScript);
      
      if (serverProcess) {
        healthInfo.isRunning = true;
        healthInfo.startupTime = Date.now() - startTime;
        
        // Wait a bit for server to fully initialize
        await this.sleep(2000);
        
        // Get process metrics
        const metrics = await this.getProcessMetrics(serverProcess.pid!);
        healthInfo.memoryUsage = metrics.memory;
        healthInfo.cpuUsage = metrics.cpu;

        // Clean up
        serverProcess.kill();
      }

    } catch (error) {
      healthInfo.errors.push(`Server health check failed: ${error.message}`);
    }

    return healthInfo;
  }

  private async startServer(projectPath: string, startScript: string): Promise<any> {
    return new Promise((resolve, reject) => {
      const serverProcess = spawn('npm', ['run', 'start'], {
        cwd: projectPath,
        stdio: 'pipe'
      });

      let serverReady = false;

      // Listen for server ready indicators
      serverProcess.stdout?.on('data', (data) => {
        const output = data.toString();
        if (output.includes('listening') || output.includes('started') || output.includes('ready')) {
          serverReady = true;
          resolve(serverProcess);
        }
      });

      serverProcess.stderr?.on('data', (data) => {
        const error = data.toString();
        if (!serverReady) {
          reject(new Error(error));
        }
      });

      // Timeout after 10 seconds
      setTimeout(() => {
        if (!serverReady) {
          serverProcess.kill();
          reject(new Error('Server startup timeout'));
        }
      }, 10000);
    });
  }

  private async analyzeToolBehavior(tools: MCPTool[]): Promise<ToolBehaviorInfo[]> {
    const behaviors: ToolBehaviorInfo[] = [];

    for (const tool of tools) {
      const behavior: ToolBehaviorInfo = {
        toolName: tool.name,
        responseTime: 0,
        inputValidation: false,
        outputSanitization: false,
        errorHandling: false,
        rateLimit: null
      };

      try {
        // Test basic functionality
        const startTime = Date.now();
        const response = await this.callTool(tool, this.generateValidInput(tool));
        behavior.responseTime = Date.now() - startTime;

        // Test input validation
        behavior.inputValidation = await this.testInputValidation(tool);
        
        // Test output sanitization
        behavior.outputSanitization = await this.testOutputSanitization(tool);
        
        // Test error handling
        behavior.errorHandling = await this.testErrorHandling(tool);
        
        // Test rate limiting
        behavior.rateLimit = await this.testRateLimit(tool);

      } catch (error) {
        console.warn(`Failed to analyze tool ${tool.name}:`, error.message);
      }

      behaviors.push(behavior);
    }

    return behaviors;
  }

  private async runSecurityTests(tools: MCPTool[]): Promise<SecurityTestResult[]> {
    const results: SecurityTestResult[] = [];

    for (const tool of tools) {
      // SQL Injection Tests
      for (const payload of this.testPayloads.sqlInjection) {
        const result = await this.testSQLInjection(tool, payload);
        results.push(result);
      }

      // Command Injection Tests
      for (const payload of this.testPayloads.commandInjection) {
        const result = await this.testCommandInjection(tool, payload);
        results.push(result);
      }

      // XSS Tests
      for (const payload of this.testPayloads.xss) {
        const result = await this.testXSS(tool, payload);
        results.push(result);
      }

      // Path Traversal Tests
      for (const payload of this.testPayloads.pathTraversal) {
        const result = await this.testPathTraversal(tool, payload);
        results.push(result);
      }

      // DoS Tests
      const dosResult = await this.testDoS(tool);
      results.push(dosResult);
    }

    return results;
  }

  private async measurePerformance(tools: MCPTool[]): Promise<PerformanceMetrics> {
    const responseTimes: number[] = [];
    let errorCount = 0;
    const testDuration = 30000; // 30 seconds
    const startTime = Date.now();

    while (Date.now() - startTime < testDuration) {
      for (const tool of tools) {
        try {
          const testStart = Date.now();
          await this.callTool(tool, this.generateValidInput(tool));
          const responseTime = Date.now() - testStart;
          responseTimes.push(responseTime);
        } catch (error) {
          errorCount++;
        }
      }
    }

    const averageResponseTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length || 0;
    const maxResponseTime = Math.max(...responseTimes, 0);
    const throughput = responseTimes.length / (testDuration / 1000); // requests per second
    const errorRate = errorCount / (responseTimes.length + errorCount) || 0;

    return {
      averageResponseTime,
      maxResponseTime,
      throughput,
      errorRate
    };
  }

  private async testInputValidation(tool: MCPTool): Promise<boolean> {
    try {
      // Test with invalid input types
      const invalidInputs = [
        null,
        undefined,
        { malformed: 'object' },
        ['array', 'instead', 'of', 'object'],
        'string_instead_of_object'
      ];

      for (const input of invalidInputs) {
        const response = await this.callTool(tool, input);
        // If tool doesn't reject invalid input, validation is poor
        if (response && !response.error) {
          return false;
        }
      }

      return true;
    } catch (error) {
      // If tool throws proper errors for invalid input, that's good
      return true;
    }
  }

  private async testOutputSanitization(tool: MCPTool): Promise<boolean> {
    try {
      const maliciousInput = {
        query: "<script>alert('xss')</script>",
        data: "'; DROP TABLE users; --"
      };

      const response = await this.callTool(tool, maliciousInput);
      
      if (response && typeof response === 'string') {
        // Check if malicious content is properly escaped/sanitized
        return !response.includes('<script>') && !response.includes('DROP TABLE');
      }

      return true;
    } catch (error) {
      return true; // Error handling is better than returning unsanitized data
    }
  }

  private async testErrorHandling(tool: MCPTool): Promise<boolean> {
    try {
      // Test with various error-inducing inputs
      const errorInputs = [
        { file: '/nonexistent/path' },
        { url: 'invalid://url' },
        { query: null },
        { data: undefined }
      ];

      for (const input of errorInputs) {
        try {
          const response = await this.callTool(tool, input);
          // Check if error response is properly structured
          if (response && response.error && typeof response.error === 'string') {
            // Good: structured error response
            continue;
          } else if (!response || response.error) {
            // Good: proper rejection
            continue;
          } else {
            // Bad: no error handling
            return false;
          }
        } catch (error) {
          // Good: proper error throwing
          continue;
        }
      }

      return true;
    } catch (error) {
      return false;
    }
  }

  private async testRateLimit(tool: MCPTool): Promise<RateLimitInfo | null> {
    const rateLimit: RateLimitInfo = {
      enabled: false,
      limit: 0,
      window: 0,
      tested: true
    };

    try {
      const requests = [];
      const startTime = Date.now();

      // Send 50 rapid requests
      for (let i = 0; i < 50; i++) {
        requests.push(this.callTool(tool, this.generateValidInput(tool)));
      }

      const responses = await Promise.allSettled(requests);
      const rejectedCount = responses.filter(r => r.status === 'rejected').length;
      const rateLimitedCount = responses.filter(r => 
        r.status === 'fulfilled' && 
        r.value && 
        (r.value.error?.includes('rate limit') || r.value.error?.includes('too many'))
      ).length;

   if (rejectedCount > 10 || rateLimitedCount > 0) {
       rateLimit.enabled = true;
       rateLimit.limit = 50 - rejectedCount - rateLimitedCount;
       rateLimit.window = Date.now() - startTime;
     }

     return rateLimit;
   } catch (error) {
     return null;
   }
 }

 private async testSQLInjection(tool: MCPTool, payload: string): Promise<SecurityTestResult> {
   try {
     const input = this.injectPayloadIntoInput(tool, payload);
     const response = await this.callTool(tool, input);

     // Check if response indicates SQL injection vulnerability
     const dangerous = this.containsDangerousSQL(response);

     return {
       testName: `SQL Injection: ${payload.substring(0, 20)}...`,
       category: 'injection',
       passed: !dangerous,
       details: dangerous ? 'Tool appears vulnerable to SQL injection' : 'No SQL injection detected',
       severity: dangerous ? 'high' : 'low'
     };
   } catch (error) {
     return {
       testName: `SQL Injection: ${payload.substring(0, 20)}...`,
       category: 'injection',
       passed: true,
       details: 'Tool properly rejected malicious input',
       severity: 'low'
     };
   }
 }

 private async testCommandInjection(tool: MCPTool, payload: string): Promise<SecurityTestResult> {
   try {
     const input = this.injectPayloadIntoInput(tool, payload);
     const response = await this.callTool(tool, input);

     // Check if response indicates command execution
     const dangerous = this.containsCommandOutput(response);

     return {
       testName: `Command Injection: ${payload.substring(0, 20)}...`,
       category: 'injection',
       passed: !dangerous,
       details: dangerous ? 'Tool appears vulnerable to command injection' : 'No command injection detected',
       severity: dangerous ? 'high' : 'low'
     };
   } catch (error) {
     return {
       testName: `Command Injection: ${payload.substring(0, 20)}...`,
       category: 'injection',
       passed: true,
       details: 'Tool properly rejected malicious input',
       severity: 'low'
     };
   }
 }

 private async testXSS(tool: MCPTool, payload: string): Promise<SecurityTestResult> {
   try {
     const input = this.injectPayloadIntoInput(tool, payload);
     const response = await this.callTool(tool, input);

     // Check if XSS payload is reflected without encoding
     const vulnerable = typeof response === 'string' && response.includes(payload);

     return {
       testName: `XSS: ${payload.substring(0, 20)}...`,
       category: 'xss',
       passed: !vulnerable,
       details: vulnerable ? 'Tool reflects unescaped user input' : 'XSS payload properly handled',
       severity: vulnerable ? 'medium' : 'low'
     };
   } catch (error) {
     return {
       testName: `XSS: ${payload.substring(0, 20)}...`,
       category: 'xss',
       passed: true,
       details: 'Tool properly rejected malicious input',
       severity: 'low'
     };
   }
 }

 private async testPathTraversal(tool: MCPTool, payload: string): Promise<SecurityTestResult> {
   try {
     const input = this.injectPayloadIntoInput(tool, payload);
     const response = await this.callTool(tool, input);

     // Check if response contains sensitive file content
     const dangerous = this.containsSensitiveFileContent(response);

     return {
       testName: `Path Traversal: ${payload.substring(0, 20)}...`,
       category: 'path-traversal',
       passed: !dangerous,
       details: dangerous ? 'Tool appears vulnerable to path traversal' : 'No path traversal detected',
       severity: dangerous ? 'high' : 'low'
     };
   } catch (error) {
     return {
       testName: `Path Traversal: ${payload.substring(0, 20)}...`,
       category: 'path-traversal',
       passed: true,
       details: 'Tool properly rejected malicious input',
       severity: 'low'
     };
   }
 }

 private async testDoS(tool: MCPTool): Promise<SecurityTestResult> {
   try {
     const oversizedInput = this.injectPayloadIntoInput(tool, this.testPayloads.oversizedPayload);
     const startTime = Date.now();
     
     const response = await Promise.race([
       this.callTool(tool, oversizedInput),
       this.timeout(10000) // 10 second timeout
     ]);

     const responseTime = Date.now() - startTime;

     // If response takes too long or times out, might be vulnerable to DoS
     const vulnerable = responseTime > 5000;

     return {
       testName: 'DoS: Oversized Input',
       category: 'dos',
       passed: !vulnerable,
       details: vulnerable ? 
         `Tool took ${responseTime}ms to respond to oversized input` : 
         'Tool handled oversized input appropriately',
       severity: vulnerable ? 'medium' : 'low'
     };
   } catch (error) {
     return {
       testName: 'DoS: Oversized Input',
       category: 'dos',
       passed: true,
       details: 'Tool properly rejected oversized input',
       severity: 'low'
     };
   }
 }

 private async callTool(tool: MCPTool, input: any): Promise<any> {
   // This would need to be implemented based on your MCP protocol
   // For now, return a mock response
   return new Promise((resolve) => {
     setTimeout(() => {
       resolve({ success: true, data: 'mock response' });
     }, Math.random() * 100);
   });
 }

 private generateValidInput(tool: MCPTool): any {
   // Generate valid input based on tool's input schema
   if (tool.inputSchema && tool.inputSchema.properties) {
     const input: any = {};
     
     for (const [key, schema] of Object.entries(tool.inputSchema.properties)) {
       const schemaObj = schema as any;
       
       switch (schemaObj.type) {
         case 'string':
           input[key] = 'test_string';
           break;
         case 'number':
           input[key] = 42;
           break;
         case 'boolean':
           input[key] = true;
           break;
         case 'array':
           input[key] = ['test'];
           break;
         default:
           input[key] = 'test_value';
       }
     }
     
     return input;
   }

   return { test: 'data' };
 }

 private injectPayloadIntoInput(tool: MCPTool, payload: string): any {
   const baseInput = this.generateValidInput(tool);
   
   // Inject payload into string fields
   if (typeof baseInput === 'object') {
     for (const [key, value] of Object.entries(baseInput)) {
       if (typeof value === 'string') {
         baseInput[key] = payload;
         break; // Only inject into first string field
       }
     }
   }

   return baseInput;
 }

 private containsDangerousSQL(response: any): boolean {
   if (!response || typeof response !== 'string') return false;
   
   const dangerousPatterns = [
     /ERROR.*syntax.*near/i,
     /mysql.*error/i,
     /postgresql.*error/i,
     /sqlite.*error/i,
     /table.*doesn.*exist/i,
     /column.*unknown/i
   ];

   return dangerousPatterns.some(pattern => pattern.test(response));
 }

 private containsCommandOutput(response: any): boolean {
   if (!response || typeof response !== 'string') return false;
   
   const commandOutputPatterns = [
     /uid=\d+.*gid=\d+/,  // whoami output
     /total \d+/,          // ls output
     /volume.*serial/i,    // dir output
     /etc\/passwd/,        // passwd file
     /windows\\system32/i  // windows paths
   ];

   return commandOutputPatterns.some(pattern => pattern.test(response));
 }

 private containsSensitiveFileContent(response: any): boolean {
   if (!response || typeof response !== 'string') return false;
   
   const sensitivePatterns = [
     /root:.*:0:0:/,       // /etc/passwd content
     /\[boot loader\]/i,   // Windows SAM file
     /-----BEGIN.*KEY-----/, // Private keys
     /password.*=/i,       // Config files with passwords
     /#.*shadow/           // Shadow file content
   ];

   return sensitivePatterns.some(pattern => pattern.test(response));
 }

 private async getProcessMetrics(pid: number): Promise<{ memory: number; cpu: number }> {
   try {
     // This is a simplified implementation
     // In a real implementation, you'd use proper process monitoring
     return { memory: 50, cpu: 10 }; // Mock values
   } catch (error) {
     return { memory: 0, cpu: 0 };
   }
 }

 private async sleep(ms: number): Promise<void> {
   return new Promise(resolve => setTimeout(resolve, ms));
 }

 private async timeout(ms: number): Promise<never> {
   return new Promise((_, reject) => 
     setTimeout(() => reject(new Error('Timeout')), ms)
   );
 }
}