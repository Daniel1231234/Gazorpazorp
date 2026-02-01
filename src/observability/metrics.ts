import { Request, Response, NextFunction } from "express";
import prometheus from "prom-client";
import { SentinelGateway } from "../gateway/gazorpazorp.js";

export class SentinelMetrics {
  private static instance: SentinelMetrics;

  // Counters
  public readonly requestsTotal = new prometheus.Counter({
    name: "sentinel_requests_total",
    help: "Total number of requests processed",
    labelNames: ["agent_id", "decision", "threat_type"]
  });

  public readonly blockedRequests = new prometheus.Counter({
    name: "sentinel_blocked_requests_total",
    help: "Total number of blocked requests",
    labelNames: ["threat_type", "rule_id"]
  });

  public readonly cacheHits = new prometheus.Counter({
    name: "sentinel_cache_hits_total",
    help: "Number of cache hits"
  });

  public readonly cacheMisses = new prometheus.Counter({
    name: "sentinel_cache_misses_total",
    help: "Number of cache misses"
  });

  // Histograms
  public readonly requestDuration = new prometheus.Histogram({
    name: "sentinel_request_duration_seconds",
    help: "Request processing duration",
    labelNames: ["layer"],
    buckets: [0.01, 0.05, 0.1, 0.5, 1, 2, 5]
  });

  public readonly llmLatency = new prometheus.Histogram({
    name: "sentinel_llm_latency_seconds",
    help: "LLM analysis latency",
    labelNames: ["model", "tier"],
    buckets: [0.1, 0.5, 1, 2, 5, 10]
  });

  public readonly riskScoreDistribution = new prometheus.Histogram({
    name: "sentinel_risk_score",
    help: "Distribution of risk scores",
    buckets: [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
  });

  // Gauges
  public readonly agentReputation = new prometheus.Gauge({
    name: "sentinel_agent_reputation",
    help: "Current agent reputation scores",
    labelNames: ["agent_id"]
  });

  public readonly activeAgents = new prometheus.Gauge({
    name: "sentinel_active_agents",
    help: "Number of active agents"
  });

  public readonly llmQueueSize = new prometheus.Gauge({
    name: "sentinel_llm_queue_size",
    help: "Number of requests waiting for LLM analysis"
  });

  private constructor() {
    // Enable default metrics (CPU, memory, etc.)
    prometheus.collectDefaultMetrics({
      prefix: "sentinel_"
    });
  }

  public static getInstance(): SentinelMetrics {
    if (!SentinelMetrics.instance) {
      SentinelMetrics.instance = new SentinelMetrics();
    }
    return SentinelMetrics.instance;
  }

  public async getMetrics(): Promise<string> {
    return await prometheus.register.metrics();
  }

  public async getJSON(): Promise<any> {
    const metrics = await prometheus.register.getMetricsAsJSON();
    return metrics;
  }
}

// Usage in middleware:
export class ObservableSentinelGateway extends SentinelGateway {
  private metrics = SentinelMetrics.getInstance();

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
      await super.semanticMiddleware(req, res, next);

      const context = (req as any).sentinelContext;

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

      // Record decision
      this.metrics.requestsTotal.inc({
        agent_id: context.agent.id,
        decision: context.decision.action.type,
        threat_type: context.analysis.threatType
      });

      if (context.decision.action.type === "deny") {
        this.metrics.blockedRequests.inc({
          threat_type: context.analysis.threatType,
          rule_id: context.decision.matchedRule?.id || "unknown"
        });
      }
    } finally {
      timer();
    }
  }

  // Expose metrics endpoint
  public setupMetricsEndpoint(): void {
    this.app.get("/metrics", async (req, res) => {
      res.set("Content-Type", prometheus.register.contentType);
      res.end(await this.metrics.getMetrics());
    });
  }
}
