// src/index.ts
import { SentinelGateway } from "./gateway/gazorpazorp.js";
import { CachedIntentAnalyzer } from "./cache/analysis-cache.js";
import { AnomalyDetector } from "./behavioral/anomaly-detector.js";
import { SentinelMetrics } from "./observability/metrics.js";
import { logger } from "./utils/logger.js";
import { Request, Response, NextFunction } from "express";
import { createDashboardRouter } from "./dashboard/api.js";

class ProductionGateway extends SentinelGateway {
  private metrics = SentinelMetrics.getInstance();
  private anomalyDetector: AnomalyDetector;

  constructor(config: any) {
    super(config);
    this.anomalyDetector = new AnomalyDetector(this.redis);

    // Use Cached Intent Analyzer
    this.intentAnalyzer = new CachedIntentAnalyzer(
      {
        deepModel: config.llmDeepModel,
        fastModel: config.llmFastModel
      },
      this.redis
    );

    // Setup dashboard API
    this.app.use("/dashboard", createDashboardRouter(this.redis));

    // Setup metrics endpoint
    this.app.get("/metrics", async (req, res) => {
      res.set("Content-Type", (await this.metrics.getMetrics()) ? "text/plain" : "application/json"); // Simplified
      res.end(await this.metrics.getMetrics());
    });
  }

  protected async cryptoMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
    const timer = this.metrics.requestDuration.startTimer({ layer: "crypto" });
    try {
      await super.cryptoMiddleware(req, res, next);
    } finally {
      timer();
    }
  }

  protected async semanticMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
    const timer = this.metrics.requestDuration.startTimer({ layer: "semantic" });
    const llmTimer = this.metrics.llmLatency.startTimer({ model: "llama3", tier: "deep" });

    try {
      // 1. Run Semantic Analysis (via super, which uses the CachedIntentAnalyzer)
      await super.semanticMiddleware(req, res, next);

      const context = (req as any).sentinelContext;
      if (!context) return; // Blocked or early exit

      // 2. Behavioral Anomaly Detection
      const anomaly = await this.anomalyDetector.detectAnomaly(context.agent.id, {
        path: req.path,
        method: req.method,
        body: req.body,
        timestamp: Date.now()
      });

      await this.anomalyDetector.updateProfile(context.agent.id, {
        path: req.path,
        method: req.method,
        body: req.body,
        timestamp: Date.now()
      });

      if (anomaly.isAnomalous) {
        context.analysis.riskScore = Math.min(context.analysis.riskScore + anomaly.score * 20, 100);
        context.analysis.explanation += ` [Behavioral anomaly: ${anomaly.reasons.join(", ")}]`;
      }

      // Record metrics
      this.metrics.riskScoreDistribution.observe(context.analysis.riskScore);
      this.metrics.agentReputation.set({ agent_id: context.agent.id }, context.agent.reputation);
    } finally {
      timer();
      llmTimer();
    }
  }

  protected async policyMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
    const timer = this.metrics.requestDuration.startTimer({ layer: "policy" });
    try {
      await super.policyMiddleware(req, res, next);

      const context = (req as any).sentinelContext;
      if (!context || !context.decision) return;

      this.metrics.requestsTotal.inc({
        agent_id: context.agent.id,
        decision: context.decision.action.type,
        threat_type: context.analysis.threatType
      });
    } finally {
      timer();
    }
  }
}

const config = {
  port: Number(process.env.PORT) || 3000,
  backendUrl: process.env.BACKEND_URL || "http://localhost:8080",
  redisUrl: process.env.REDIS_URL || "redis://localhost:6379",
  llmDeepModel: process.env.LLM_DEEP_MODEL || "llama3:8b",
  llmFastModel: process.env.LLM_FAST_MODEL || "tinyllama"
};

async function main() {
  try {
    logger.info("Initializing Production Gazorpazorp Gateway...");

    const gateway = new ProductionGateway(config);
    gateway.start(config.port);

    logger.info(`🛡️ Gazorpazorp is active on port ${config.port}`);
  } catch (error) {
    logger.error("Failed to start Gazorpazorp:", error);
    process.exit(1);
  }
}

main();
