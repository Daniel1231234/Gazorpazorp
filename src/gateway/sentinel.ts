// src/gateway/gazorpazorp.ts
import express, { Request, Response, NextFunction } from "express";
import { createProxyMiddleware } from "http-proxy-middleware";
import { CryptoVerifier } from "../crypto/agent-identity.js";
import { SignedRequest } from "../crypto/agent-identity.js";
import { IntentAnalyzer } from "../semantic/intent-analyzer.js";
import { PolicyEngine, PolicyContext } from "../policy/engine.js";
import { Redis } from "ioredis";

export class SentinelGateway {
  protected app: express.Application;
  protected cryptoVerifier: CryptoVerifier;
  protected intentAnalyzer: IntentAnalyzer;
  protected policyEngine: PolicyEngine;
  protected redis: Redis;
  private backendUrl: string;

  constructor(config: { backendUrl: string; redisUrl: string; llmDeepModel: string; llmFastModel: string }) {
    this.app = express();
    this.backendUrl = config.backendUrl;
    this.redis = new Redis(config.redisUrl);
    this.cryptoVerifier = new CryptoVerifier(this.redis);
    this.intentAnalyzer = new IntentAnalyzer({
      deepModel: config.llmDeepModel,
      fastModel: config.llmFastModel
    });
    this.policyEngine = new PolicyEngine(this.redis);

    this.setupMiddleware();
  }

  private setupMiddleware(): void {
    this.app.use(express.json({ limit: "1mb" }));

    // Middleware chain
    this.app.use(this.cryptoMiddleware.bind(this));
    this.app.use(this.semanticMiddleware.bind(this));
    this.app.use(this.policyMiddleware.bind(this));
    this.app.get("/health", (req, res) => res.status(200).json({ status: "healthy" }));
    this.app.use(this.proxyMiddleware());
  }

  /**
   * Layer 1: Cryptographic verification
   */
  protected async cryptoMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
    const signature = req.headers["x-agent-signature"] as string;
    const publicKey = req.headers["x-agent-pubkey"] as string;
    const signedPayloadStr = req.headers["x-signed-payload"] as string;

    if (!signature || !publicKey || !signedPayloadStr) {
      res.status(401).json({
        error: "Missing authentication headers",
        required: ["x-agent-signature", "x-agent-pubkey", "x-signed-payload"]
      });
      return;
    }

    try {
      const signedPayload: SignedRequest = JSON.parse(Buffer.from(signedPayloadStr, "base64").toString());

      const result = await this.cryptoVerifier.verifyRequest(signedPayload, signature, publicKey);

      if (!result.valid) {
        await this.logSecurityEvent("crypto_failure", { error: result.error, publicKey });
        res.status(403).json({ error: result.error });
        return;
      }

      // Attach agent info to request for downstream middleware
      (req as any).sentinelContext = {
        agent: result.agent,
        signedPayload
      };

      next();
    } catch (error) {
      res.status(400).json({ error: "Invalid authentication data" });
    }
  }

  /**
   * Layer 2: Semantic analysis
   */
  protected async semanticMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
    const context = (req as any).sentinelContext;

    // Get agent's request history for context
    const historyKey = `agent:${context.agent.id}:history`;
    const history = await this.redis.lrange(historyKey, 0, 9);

    const analysis = await this.intentAnalyzer.analyzeIntent(
      {
        method: req.method,
        path: req.path,
        body: req.body
      },
      {
        reputation: context.agent.reputation,
        history
      }
    );

    // Store request in history
    await this.redis.lpush(
      historyKey,
      JSON.stringify({
        timestamp: Date.now(),
        path: req.path,
        riskScore: analysis.riskScore
      })
    );
    await this.redis.ltrim(historyKey, 0, 99);

    context.analysis = analysis;

    if (analysis.isMalicious && analysis.confidence > 0.85) {
      const eventData = {
        agentId: context.agent.id,
        analysis
      };
      await this.logSecurityEvent("malicious_request_blocked", eventData);

      // Publish to threat map channel
      await this.redis.publish(
        "gazorpazorp:threats",
        JSON.stringify({
          type: "malicious_request",
          agentId: context.agent.id,
          threatType: analysis.threatType,
          riskScore: analysis.riskScore,
          timestamp: new Date().toISOString()
        })
      );

      res.status(403).json({
        error: "Request blocked",
        reason: analysis.explanation,
        threatType: analysis.threatType
      });
      return;
    }

    next();
  }

  /**
   * Layer 3: Policy evaluation
   */
  protected async policyMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
    const context = (req as any).sentinelContext;

    const policyContext: PolicyContext = {
      agent: {
        id: context.agent.id,
        reputation: context.agent.reputation,
        permissions: context.agent.permissions
      },
      request: {
        method: req.method,
        path: req.path,
        body: req.body,
        timestamp: Date.now()
      },
      analysis: context.analysis
    };

    const decision = await this.policyEngine.evaluate(policyContext);

    switch (decision.action.type) {
      case "deny":
        res.status(403).json({
          error: "Access denied by policy",
          reason: decision.action.params?.reason,
          policyId: decision.matchedRule?.id
        });
        return;

      case "rate_limit":
        const limited = await this.checkRateLimit(context.agent.id, decision.action.params as any);
        if (limited) {
          res.status(429).json({ error: "Rate limit exceeded" });
          return;
        }
        break;

      case "challenge":
        // Implement challenge-response mechanism
        // For now, just log and continue
        await this.logSecurityEvent("challenge_issued", { agentId: context.agent.id });
        break;
    }

    next();
  }

  /**
   * Proxy to backend
   */
  private proxyMiddleware() {
    return createProxyMiddleware({
      target: this.backendUrl,
      changeOrigin: true,
      on: {
        proxyReq: (proxyReq: any, req: any) => {
          // Add internal headers for backend
          const context = (req as any).sentinelContext;
          proxyReq.setHeader("X-Gazorpazorp-Agent-Id", context.agent.id);
          proxyReq.setHeader("X-Gazorpazorp-Risk-Score", context.analysis.riskScore);
          proxyReq.setHeader("X-Gazorpazorp-Verified", "true");
        }
      }
    });
  }

  private async checkRateLimit(agentId: string, params: { maxRequests: number; windowSeconds: number }): Promise<boolean> {
    const key = `ratelimit:${agentId}`;
    const current = await this.redis.incr(key);

    if (current === 1) {
      await this.redis.expire(key, params.windowSeconds);
    }

    return current > params.maxRequests;
  }

  private async logSecurityEvent(event: string, data: unknown): Promise<void> {
    await this.redis.lpush(
      "gazorpazorp:security_events",
      JSON.stringify({
        event,
        data,
        timestamp: new Date().toISOString()
      })
    );
  }

  public start(port: number): void {
    this.app.listen(port, () => {
      console.log(`🛡️ Gazorpazorp Gateway running on port ${port}`);
    });
  }
}
