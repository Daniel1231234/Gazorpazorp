/**
 * Load Test Example for Gazorpazorp Gateway
 *
 * This script demonstrates how to perform load testing on the gateway
 * with realistic agent behavior patterns.
 *
 * Usage:
 *   npm install -D @types/node
 *   npx tsx examples/load_test.ts
 *
 * Configuration:
 *   - GATEWAY_URL: Gateway endpoint (default: http://localhost:3000)
 *   - NUM_AGENTS: Number of concurrent agents (default: 10)
 *   - REQUESTS_PER_AGENT: Requests each agent makes (default: 100)
 *   - THINK_TIME_MS: Delay between requests (default: 100ms)
 */

import { randomBytes, generateKeyPairSync, sign } from "crypto";

interface LoadTestConfig {
  gatewayUrl: string;
  numAgents: number;
  requestsPerAgent: number;
  thinkTimeMs: number;
}

interface TestAgent {
  id: string;
  publicKey: string;
  privateKey: Buffer;
  reputation: number;
}

interface RequestStats {
  total: number;
  successful: number;
  failed: number;
  challenged: number;
  rateLimited: number;
  latencies: number[];
}

class LoadTester {
  private config: LoadTestConfig;
  private agents: TestAgent[] = [];
  private stats: RequestStats = {
    total: 0,
    successful: 0,
    failed: 0,
    challenged: 0,
    rateLimited: 0,
    latencies: []
  };

  constructor(config: Partial<LoadTestConfig> = {}) {
    this.config = {
      gatewayUrl: process.env.GATEWAY_URL || "http://localhost:3000",
      numAgents: parseInt(process.env.NUM_AGENTS || "10"),
      requestsPerAgent: parseInt(process.env.REQUESTS_PER_AGENT || "100"),
      thinkTimeMs: parseInt(process.env.THINK_TIME_MS || "100"),
      ...config
    };
  }

  private generateAgents(): void {
    console.log(`🔑 Generating ${this.config.numAgents} test agents...`);

    for (let i = 0; i < this.config.numAgents; i++) {
      const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" }
      });

      this.agents.push({
        id: `agent_${i + 1}`,
        publicKey,
        privateKey: Buffer.from(privateKey),
        reputation: 50 + Math.random() * 50
      });
    }

    console.log(`✅ Generated ${this.agents.length} agents\n`);
  }

  private signRequest(request: any, privateKey: Buffer): string {
    const payload = JSON.stringify(request);
    const signature = sign(null, Buffer.from(payload), privateKey);
    return signature.toString("hex");
  }

  private async makeRequest(agent: TestAgent, requestNum: number): Promise<number> {
    const startTime = Date.now();

    try {
      const request = {
        method: "POST",
        path: "/api/data/query",
        body: {
          query: `SELECT * FROM data WHERE id = ${requestNum}`,
          requestId: randomBytes(16).toString("hex")
        },
        timestamp: Date.now(),
        nonce: randomBytes(16).toString("hex")
      };

      const signature = this.signRequest(request, agent.privateKey);
      const signedPayloadStr = Buffer.from(JSON.stringify(request)).toString("base64");

      const response = await fetch(`${this.config.gatewayUrl}/api/data/query`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Agent-Signature": signature,
          "X-Agent-Pubkey": agent.publicKey,
          "X-Signed-Payload": signedPayloadStr
        },
        body: JSON.stringify(request.body)
      });

      const latency = Date.now() - startTime;
      this.stats.latencies.push(latency);
      this.stats.total++;

      if (response.status === 200) {
        this.stats.successful++;
      } else if (response.status === 401 && response.headers.get("content-type")?.includes("json")) {
        const body = await response.json();
        if (body.status === "challenge_required") {
          this.stats.challenged++;
        } else {
          this.stats.failed++;
        }
      } else if (response.status === 429) {
        this.stats.rateLimited++;
      } else {
        this.stats.failed++;
      }

      return latency;
    } catch (error) {
      this.stats.total++;
      this.stats.failed++;
      return Date.now() - startTime;
    }
  }

  private async runAgentLoad(agent: TestAgent): Promise<void> {
    for (let i = 0; i < this.config.requestsPerAgent; i++) {
      await this.makeRequest(agent, i + 1);

      if (this.config.thinkTimeMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, this.config.thinkTimeMs));
      }
    }
  }

  private calculateStats() {
    const latencies = this.stats.latencies.sort((a, b) => a - b);
    const p50 = latencies[Math.floor(latencies.length * 0.5)];
    const p95 = latencies[Math.floor(latencies.length * 0.95)];
    const p99 = latencies[Math.floor(latencies.length * 0.99)];
    const avg = latencies.reduce((a, b) => a + b, 0) / latencies.length;
    const min = latencies[0];
    const max = latencies[latencies.length - 1];

    return {
      total: this.stats.total,
      successful: this.stats.successful,
      failed: this.stats.failed,
      challenged: this.stats.challenged,
      rateLimited: this.stats.rateLimited,
      successRate: ((this.stats.successful / this.stats.total) * 100).toFixed(2),
      challengeRate: ((this.stats.challenged / this.stats.total) * 100).toFixed(2),
      rateLimitRate: ((this.stats.rateLimited / this.stats.total) * 100).toFixed(2),
      latency: {
        min: min.toFixed(2),
        avg: avg.toFixed(2),
        p50: p50.toFixed(2),
        p95: p95.toFixed(2),
        p99: p99.toFixed(2),
        max: max.toFixed(2)
      }
    };
  }

  private printProgress(current: number, total: number): void {
    const percentage = (current / total) * 100;
    const barLength = 40;
    const filled = Math.floor((percentage / 100) * barLength);
    const empty = barLength - filled;
    const bar = "█".repeat(filled) + "░".repeat(empty);

    process.stdout.write(`\r[${bar}] ${percentage.toFixed(1)}% (${current}/${total})`);
  }

  async run(): Promise<void> {
    console.log("🛡️  Gazorpazorp Load Test\n");
    console.log("Configuration:");
    console.log(`  Gateway URL: ${this.config.gatewayUrl}`);
    console.log(`  Agents: ${this.config.numAgents}`);
    console.log(`  Requests per agent: ${this.config.requestsPerAgent}`);
    console.log(`  Think time: ${this.config.thinkTimeMs}ms`);
    console.log(`  Total requests: ${this.config.numAgents * this.config.requestsPerAgent}\n`);

    this.generateAgents();

    console.log("🏥 Checking gateway health...");
    try {
      const healthResponse = await fetch(`${this.config.gatewayUrl}/health`);
      if (!healthResponse.ok) {
        throw new Error(`Health check failed: ${healthResponse.status}`);
      }
      console.log("✅ Gateway is healthy\n");
    } catch (error) {
      console.error("❌ Gateway health check failed:", error);
      console.error("   Make sure the gateway is running at", this.config.gatewayUrl);
      process.exit(1);
    }

    console.log("🚀 Starting load test...\n");
    const startTime = Date.now();

    const totalRequests = this.config.numAgents * this.config.requestsPerAgent;

    const progressInterval = setInterval(() => {
      this.printProgress(this.stats.total, totalRequests);
    }, 100);

    await Promise.all(this.agents.map((agent) => this.runAgentLoad(agent)));

    clearInterval(progressInterval);
    this.printProgress(totalRequests, totalRequests);
    console.log("\n");

    const duration = (Date.now() - startTime) / 1000;
    const throughput = (this.stats.total / duration).toFixed(2);

    const stats = this.calculateStats();

    console.log("\n📊 Load Test Results\n");
    console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    console.log(`Duration:        ${duration.toFixed(2)}s`);
    console.log(`Throughput:      ${throughput} req/s`);
    console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
    console.log(`Total Requests:  ${stats.total}`);
    console.log(`✅ Successful:    ${stats.successful} (${stats.successRate}%)`);
    console.log(`⚠️  Challenged:    ${stats.challenged} (${stats.challengeRate}%)`);
    console.log(`🚫 Rate Limited:  ${stats.rateLimited} (${stats.rateLimitRate}%)`);
    console.log(`❌ Failed:        ${stats.failed}`);
    console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
    console.log(`Latency (ms):`);
    console.log(`  Min:  ${stats.latency.min}ms`);
    console.log(`  Avg:  ${stats.latency.avg}ms`);
    console.log(`  P50:  ${stats.latency.p50}ms`);
    console.log(`  P95:  ${stats.latency.p95}ms`);
    console.log(`  P99:  ${stats.latency.p99}ms`);
    console.log(`  Max:  ${stats.latency.max}ms`);
    console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);

    if (stats.rateLimited > 0) {
      console.log("💡 Recommendation: Some requests were rate limited. Consider:");
      console.log("   - Increasing rate limit thresholds");
      console.log("   - Adding more think time between requests");
      console.log("   - Using fewer concurrent agents\n");
    }

    if (stats.challenged > 0) {
      console.log("💡 Recommendation: Some agents were challenged. This indicates:");
      console.log("   - Gateway is actively detecting suspicious patterns");
      console.log("   - Challenge-response system is working correctly\n");
    }

    const successPercentage = parseFloat(stats.successRate);
    if (successPercentage < 95) {
      console.log("⚠️  Warning: Success rate below 95%. Investigate failed requests.\n");
    }
  }
}

if (require.main === module) {
  const tester = new LoadTester();
  tester
    .run()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error("❌ Load test failed:", error);
      process.exit(1);
    });
}

export { LoadTester, LoadTestConfig };
