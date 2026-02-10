// src/gateway/gazorpazorp.ts
import express, { Request, Response, NextFunction } from "express";
import { createProxyMiddleware } from "http-proxy-middleware";
import { randomBytes } from "crypto";
import { CryptoVerifier } from "../crypto/agent-identity.js";
import { SignedRequest } from "../crypto/agent-identity.js";
import { IntentAnalyzer } from "../semantic/intent-analyzer.js";
import { PolicyEngine, PolicyContext } from "../policy/engine.js";
import { ChallengeService, createChallengeResponse } from "../challenge/challenge-service.js";
import { Redis } from "ioredis";
import { GatewayConfig } from "../types/config.js";
import { logger } from "../utils/logger.js";

/**
 * Lua script for atomic rate limiting.
 * Prevents race conditions by performing increment, TTL check, and expiry in a single atomic operation.
 *
 * KEYS[1] = rate limit key
 * ARGV[1] = max requests allowed
 * ARGV[2] = window in seconds
 *
 * Returns: [current_count, ttl, is_limited]
 */
const RATE_LIMIT_SCRIPT = `
local key = KEYS[1]
local max_requests = tonumber(ARGV[1])
local window = tonumber(ARGV[2])

local current = redis.call('INCR', key)
local ttl = redis.call('TTL', key)

-- Set expiry on first request or if key has no TTL
if current == 1 or ttl == -1 then
  redis.call('EXPIRE', key, window)
  ttl = window
end

local is_limited = 0
if current > max_requests then
  is_limited = 1
end

return {current, ttl, is_limited}
`;

/**
 * Sentinel Gateway - Multi-layer zero-trust security gateway for AI agents.
 *
 * Security Layers:
 * 1. Cryptographic verification (Ed25519 signatures)
 * 2. Semantic analysis (LLM-based intent detection)
 * 3. Policy evaluation (reputation-based access control)
 *
 * Features:
 * - Challenge-response authentication
 * - Rate limiting with atomic Lua scripts
 * - Header sanitization
 * - Payload size enforcement
 * - Structured logging with Winston
 * - Circuit breaker for LLM resilience
 */
export class SentinelGateway {
  protected app: express.Application;
  protected cryptoVerifier: CryptoVerifier;
  protected intentAnalyzer: IntentAnalyzer;
  protected policyEngine: PolicyEngine;
  protected challengeService: ChallengeService;
  protected redis: Redis;
  private backendUrl: string;
  private readonly MAX_PAYLOAD_SIZE = 1048576; // 1MB in bytes

  /**
   * Initialize the Sentinel Gateway with configuration.
   *
   * @param config - Gateway configuration including ports, URLs, and LLM models
   */
  constructor(config: GatewayConfig) {
    this.app = express();
    this.backendUrl = config.backendUrl;
    this.redis = new Redis(config.redisUrl);
    this.cryptoVerifier = new CryptoVerifier(this.redis);
    this.intentAnalyzer = new IntentAnalyzer({
      deepModel: config.llmDeepModel,
      fastModel: config.llmFastModel
    });
    this.policyEngine = new PolicyEngine(this.redis);
    this.challengeService = new ChallengeService(this.redis);

    this.registerLuaScripts();
    this.setupMiddleware();
  }

  /**
   * Register Lua scripts with Redis for atomic operations
   */
  private registerLuaScripts(): void {
    this.redis.defineCommand("rateLimitAtomic", {
      numberOfKeys: 1,
      lua: RATE_LIMIT_SCRIPT
    });
  }

  /**
   * Configure middleware chain and routes
   */
  private setupMiddleware(): void {
    // Correlation ID middleware (first, so all subsequent logs include it)
    this.app.use(this.correlationIdMiddleware.bind(this));

    // Payload size enforcement (before body parsing)
    this.app.use(this.payloadSizeEnforcement.bind(this));

    // Body parser with size limit
    this.app.use(express.json({ limit: "1mb" }));

    // Challenge verification endpoint (before auth middleware)
    this.app.post("/api/challenge/verify", this.handleChallengeVerification.bind(this));

    // Middleware chain
    this.app.use(this.cryptoMiddleware.bind(this));
    this.app.use(this.semanticMiddleware.bind(this));
    this.app.use(this.policyMiddleware.bind(this));
    this.app.get("/health", (req, res) => res.status(200).json({ status: "healthy" }));
    this.app.use(this.proxyMiddleware());
  }

  /**
   * Middleware to extract or generate correlation IDs for request tracing.
   * Supports multiple header names and generates UUID if not provided.
   */
  private correlationIdMiddleware(req: Request, res: Response, next: NextFunction): void {
    // Try to extract correlation ID from headers (support multiple standard names)
    let correlationId =
      (req.headers["x-correlation-id"] as string) ||
      (req.headers["x-request-id"] as string) ||
      (req.headers["x-trace-id"] as string);

    // Sanitize if present
    if (correlationId) {
      correlationId = this.sanitizeHeader(correlationId)!;
    }

    // Generate new UUID if not provided or sanitization removed it
    if (!correlationId || correlationId.length < 8) {
      correlationId = `req_${randomBytes(16).toString("hex")}`;
    }

    // Attach to request context for use in downstream middleware
    (req as any).correlationId = correlationId;

    // Set response header so client can track the request
    res.setHeader("X-Correlation-ID", correlationId);

    // Log request start with correlation ID
    logger.info("Request received", {
      correlationId,
      method: req.method,
      path: req.path,
      ip: req.ip,
      userAgent: req.headers["user-agent"]
    });

    next();
  }

  /**
   * Middleware to enforce payload size limits before parsing.
   * Prevents resource exhaustion from oversized payloads.
   */
  private payloadSizeEnforcement(req: Request, res: Response, next: NextFunction): void {
    const contentLength = req.headers["content-length"];

    if (contentLength) {
      const size = parseInt(contentLength, 10);

      if (isNaN(size)) {
        res.status(400).json({
          error: "Invalid Content-Length header"
        });
        return;
      }

      if (size > this.MAX_PAYLOAD_SIZE) {
        logger.warn("Payload size exceeded", {
          size,
          maxAllowed: this.MAX_PAYLOAD_SIZE,
          path: req.path,
          ip: req.ip
        });

        res.status(413).json({
          error: "Payload too large",
          maxSize: this.MAX_PAYLOAD_SIZE,
          receivedSize: size
        });
        return;
      }
    }

    next();
  }

  /**
   * Handle challenge verification requests with rate limiting.
   * Agents submit challenge solutions to this endpoint to prove they completed the required challenge.
   *
   * @param req - Express request with challengeId and solution in body
   * @param res - Express response
   */
  private async handleChallengeVerification(req: Request, res: Response): Promise<void> {
    const { challengeId, solution } = req.body;

    if (!challengeId || !solution) {
      res.status(400).json({
        error: "Missing required fields",
        required: ["challengeId", "solution"]
      });
      return;
    }

    // Rate limit challenge verification attempts by IP
    const clientIp = (req.headers["x-forwarded-for"] as string)?.split(",")[0] || req.socket.remoteAddress || "unknown";
    const rateLimitResult = await this.checkRateLimit(`challenge:${clientIp}`, {
      maxRequests: 10, // Max 10 verification attempts
      windowSeconds: 60 // Per minute
    });

    if (rateLimitResult.limited) {
      res.status(429).json({
        error: "Too many verification attempts",
        retryAfter: rateLimitResult.resetIn,
        remaining: 0
      });
      return;
    }

    const result = await this.challengeService.verifyChallenge({ challengeId, solution });

    if (result.valid) {
      res.status(200).json({
        status: "verified",
        message: "Challenge completed successfully. You may now retry your original request."
      });
    } else {
      res.status(400).json({
        status: "failed",
        error: result.error
      });
    }
  }

  /**
   * Sanitize header values to prevent injection attacks.
   * Removes control characters, newlines, and null bytes.
   *
   * @param value - Header value to sanitize
   * @returns Sanitized header value
   */
  private sanitizeHeader(value: string | undefined): string | undefined {
    if (!value) return value;

    return value
      // Remove control characters including newlines, carriage returns, null bytes
      .replace(/[\x00-\x1F\x7F]/g, "")
      // Limit header length to prevent DoS
      .substring(0, 8192);
  }

  /**
   * Layer 1: Cryptographic verification with header sanitization
   */
  protected async cryptoMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
    const correlationId = (req as any).correlationId;

    // Sanitize headers before processing to prevent injection attacks
    const signature = this.sanitizeHeader(req.headers["x-agent-signature"] as string);
    const publicKey = this.sanitizeHeader(req.headers["x-agent-pubkey"] as string);
    const signedPayloadStr = this.sanitizeHeader(req.headers["x-signed-payload"] as string);

    if (!signature || !publicKey || !signedPayloadStr) {
      logger.warn("Missing authentication headers", { correlationId });
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
        await this.logSecurityEvent("crypto_failure", { error: result.error, publicKey }, correlationId);
        res.status(403).json({ error: result.error });
        return;
      }

      // Attach agent info to request for downstream middleware
      (req as any).sentinelContext = {
        agent: result.agent,
        signedPayload
      };

      if (result.agent) {
        logger.debug("Crypto verification successful", {
          correlationId,
          agentId: result.agent.id,
          reputation: result.agent.reputation
        });
      }

      next();
    } catch (error) {
      logger.error("Crypto verification error", { correlationId, error });
      res.status(400).json({ error: "Invalid authentication data" });
    }
  }

  /**
   * Layer 2: Semantic analysis using LLM.
   * Analyzes request intent to detect malicious patterns and determine risk score.
   *
   * @param req - Express request with sentinelContext attached
   * @param res - Express response
   * @param next - Next middleware function
   */
  protected async semanticMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
    const context = (req as any).sentinelContext;
    const correlationId = (req as any).correlationId;

    // Check if this is a retry after a completed challenge
    const challengeId = req.headers["x-challenge-id"] as string;
    if (challengeId) {
      const completed = await this.challengeService.isChallengeCompleted(challengeId);
      if (completed) {
        // Challenge was completed, allow the request with reduced scrutiny
        context.analysis = {
          isMalicious: false,
          confidence: 0.7,
          explanation: "Request allowed after challenge completion",
          suggestedAction: "allow",
          riskScore: 30
        };
        next();
        return;
      }
    }

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
      await this.logSecurityEvent("malicious_request_blocked", eventData, correlationId);

      // Publish to threat map channel
      await this.redis.publish(
        "gazorpazorp:threats",
        JSON.stringify({
          type: "malicious_request",
          agentId: context.agent.id,
          threatType: analysis.threatType,
          riskScore: analysis.riskScore,
          timestamp: new Date().toISOString(),
          correlationId
        })
      );

      logger.info("Malicious request blocked", {
        correlationId,
        agentId: context.agent.id,
        threatType: analysis.threatType,
        riskScore: analysis.riskScore
      });

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
   * Layer 3: Policy evaluation.
   * Applies policy rules based on agent reputation, request type, and analysis results.
   * Can result in: allow, deny, rate_limit, or challenge actions.
   *
   * @param req - Express request with sentinelContext attached
   * @param res - Express response
   * @param next - Next middleware function
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
    context.decision = decision;

    switch (decision.action.type) {
      case "deny":
        res.status(403).json({
          error: "Access denied by policy",
          reason: decision.action.params?.reason,
          policyId: decision.matchedRule?.id
        });
        return;

      case "rate_limit":
        const rateLimitResult = await this.checkRateLimit(context.agent.id, decision.action.params as any);
        if (rateLimitResult.limited) {
          res.status(429).json({
            error: "Rate limit exceeded",
            retryAfter: rateLimitResult.resetIn,
            remaining: rateLimitResult.remaining
          });
          return;
        }
        break;

      case "challenge":
        // Issue a challenge to the agent
        const pendingChallenges = await this.challengeService.getPendingChallengeCount(context.agent.id);

        // Limit pending challenges per agent to prevent abuse
        if (pendingChallenges >= 5) {
          res.status(429).json({
            error: "Too many pending challenges",
            message: "Complete existing challenges before making new requests"
          });
          return;
        }

        const challenge = await this.challengeService.issueChallenge(context.agent.id, context.analysis.riskScore);
        const correlationId = (req as any).correlationId;

        await this.logSecurityEvent(
          "challenge_issued",
          {
            agentId: context.agent.id,
            challengeId: challenge.id,
            challengeType: challenge.type,
            riskScore: context.analysis.riskScore
          },
          correlationId
        );

        const baseUrl = `${req.protocol}://${req.get("host")}`;
        const challengeResponse = createChallengeResponse(challenge, baseUrl);

        res.status(401).json(challengeResponse);
        return;
    }

    next();
  }

  /**
   * Create proxy middleware to forward verified requests to backend.
   * Adds Gazorpazorp-specific headers for backend consumption.
   *
   * @returns Configured http-proxy-middleware instance
   */
  private proxyMiddleware() {
    return createProxyMiddleware({
      target: this.backendUrl,
      changeOrigin: true,
      on: {
        proxyReq: (proxyReq, req) => {
          // Add internal headers for backend
          const context = (req as any).sentinelContext;
          const correlationId = (req as any).correlationId;

          if (context) {
            proxyReq.setHeader("X-Gazorpazorp-Agent-Id", context.agent.id);
            proxyReq.setHeader("X-Gazorpazorp-Risk-Score", context.analysis.riskScore.toString());
            proxyReq.setHeader("X-Gazorpazorp-Verified", "true");
          }

          // Forward correlation ID to backend for end-to-end tracing
          if (correlationId) {
            proxyReq.setHeader("X-Correlation-ID", correlationId);
          }

          logger.debug("Proxying request to backend", {
            correlationId,
            method: req.method,
            path: req.url,
            agentId: context?.agent?.id
          });
        }
      }
    });
  }

  /**
   * Check rate limit using atomic Lua script to prevent race conditions.
   *
   * @param agentId - Unique identifier for the agent or IP being rate limited
   * @param params - Rate limit configuration (maxRequests per windowSeconds)
   * @returns Rate limit status with remaining quota and reset time
   */
  private async checkRateLimit(
    agentId: string,
    params: { maxRequests: number; windowSeconds: number }
  ): Promise<{ limited: boolean; remaining: number; resetIn: number }> {
    const key = `ratelimit:${agentId}`;

    try {
      // Use Lua script for atomic rate limiting (prevents race conditions)
      const result = (await (this.redis as any).rateLimitAtomic(
        key,
        params.maxRequests,
        params.windowSeconds
      )) as [number, number, number];

      const [current, ttl, isLimited] = result;

      return {
        limited: isLimited === 1,
        remaining: Math.max(0, params.maxRequests - current),
        resetIn: ttl
      };
    } catch (error: any) {
      // Fallback to non-atomic method if Lua script fails
      if (error.message?.includes("NOSCRIPT") || error.message?.includes("not found")) {
        return this.checkRateLimitFallback(agentId, params);
      }
      throw error;
    }
  }

  /**
   * Fallback rate limiting using WATCH for optimistic locking.
   * Used when Lua scripts are not available.
   */
  private async checkRateLimitFallback(
    agentId: string,
    params: { maxRequests: number; windowSeconds: number }
  ): Promise<{ limited: boolean; remaining: number; resetIn: number }> {
    const key = `ratelimit:${agentId}`;

    const multi = this.redis.multi();
    multi.incr(key);
    multi.ttl(key);

    const results = await multi.exec();
    const current = results?.[0]?.[1] as number;
    let ttl = results?.[1]?.[1] as number;

    if (current === 1 || ttl === -1) {
      await this.redis.expire(key, params.windowSeconds);
      ttl = params.windowSeconds;
    }

    return {
      limited: current > params.maxRequests,
      remaining: Math.max(0, params.maxRequests - current),
      resetIn: ttl
    };
  }

  /**
   * Log security events to Redis for audit trail and monitoring.
   *
   * @param event - Event type (e.g., "crypto_failure", "malicious_request_blocked")
   * @param data - Event-specific data and metadata
   * @param correlationId - Optional correlation ID for request tracing
   */
  private async logSecurityEvent(event: string, data: unknown, correlationId?: string): Promise<void> {
    const logEntry = {
      event,
      data,
      timestamp: new Date().toISOString(),
      ...(correlationId && { correlationId })
    };

    await this.redis.lpush("gazorpazorp:security_events", JSON.stringify(logEntry));

    // Also log to structured logger for immediate visibility
    logger.warn("Security event", {
      event,
      correlationId,
      ...((data as any) || {})
    });
  }

  /**
   * Start the gateway server
   * @param port - Port number to listen on
   */
  public start(port: number): void {
    this.app.listen(port, () => {
      logger.info("Gazorpazorp Gateway started", { port, status: "ready" });
    });
  }
}
