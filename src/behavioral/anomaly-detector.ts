import { Request, Response, NextFunction } from "express";
import { Redis } from "ioredis";
import { SentinelGateway } from "../gateway/sentinel.js";

interface AgentProfile {
  id: string;

  // Temporal patterns
  avgRequestsPerHour: number;
  typicalActiveHours: number[]; // [0-23]

  // Request patterns
  commonPaths: Map<string, number>; // path -> frequency
  avgPayloadSize: number;
  stdPayloadSize: number;

  // Behavioral baseline
  avgTimeBetweenRequests: number;
  requestMethods: Map<string, number>; // GET -> 80%, POST -> 20%

  lastUpdated: Date;
}

export class AnomalyDetector {
  private redis: Redis;
  private readonly PROFILE_TTL = 86400 * 30; // 30 days

  constructor(redis: Redis) {
    this.redis = redis;
  }

  /**
   * Build or update agent behavioral profile
   */
  async updateProfile(agentId: string, request: { path: string; method: string; body: unknown; timestamp: number }): Promise<void> {
    const profileKey = `profile:${agentId}`;
    const profile = (await this.getProfile(agentId)) || this.createEmptyProfile(agentId);

    // Update temporal patterns
    const hour = new Date(request.timestamp).getHours();
    if (!profile.typicalActiveHours.includes(hour)) {
      profile.typicalActiveHours.push(hour);
    }

    // Update path frequency
    const currentFreq = profile.commonPaths.get(request.path) || 0;
    profile.commonPaths.set(request.path, currentFreq + 1);

    // Update payload size statistics
    const payloadSize = JSON.stringify(request.body).length;
    const n = profile.avgPayloadSize === 0 ? 1 : 2; // Simple running average
    profile.avgPayloadSize = (profile.avgPayloadSize + payloadSize) / n;

    // Update request method distribution
    const methodCount = profile.requestMethods.get(request.method) || 0;
    profile.requestMethods.set(request.method, methodCount + 1);

    profile.lastUpdated = new Date();

    await this.saveProfile(agentId, profile);
  }

  /**
   * Detect if current request is anomalous
   */
  async detectAnomaly(
    agentId: string,
    request: { path: string; method: string; body: unknown; timestamp: number }
  ): Promise<{
    isAnomalous: boolean;
    score: number;
    reasons: string[];
  }> {
    const profile = await this.getProfile(agentId);

    if (!profile) {
      // New agent - no baseline yet
      return {
        isAnomalous: false,
        score: 0,
        reasons: ["No baseline established"]
      };
    }

    const anomalies: { reason: string; score: number }[] = [];

    // 1. Temporal anomaly
    const hour = new Date(request.timestamp).getHours();
    if (!profile.typicalActiveHours.includes(hour)) {
      anomalies.push({
        reason: `Unusual time: ${hour}:00 (typical: ${profile.typicalActiveHours.join(", ")})`,
        score: 0.3
      });
    }

    // 2. Path anomaly
    const pathFreq = profile.commonPaths.get(request.path) || 0;
    const totalRequests = Array.from(profile.commonPaths.values()).reduce((a, b) => a + b, 0);
    const pathProbability = totalRequests > 0 ? pathFreq / totalRequests : 0;

    if (pathProbability < 0.05) {
      // Path seen in less than 5% of requests
      anomalies.push({
        reason: `Rare path: ${request.path} (seen in ${(pathProbability * 100).toFixed(1)}% of requests)`,
        score: 0.4
      });
    }

    // 3. Payload size anomaly (z-score)
    const payloadSize = JSON.stringify(request.body).length;
    const zScore = Math.abs((payloadSize - profile.avgPayloadSize) / (profile.stdPayloadSize || 1));

    if (zScore > 3) {
      // More than 3 standard deviations
      anomalies.push({
        reason: `Unusual payload size: ${payloadSize} bytes (avg: ${profile.avgPayloadSize.toFixed(0)})`,
        score: Math.min(zScore / 10, 0.5)
      });
    }

    // 4. Request rate anomaly
    const recentRate = await this.getRecentRequestRate(agentId, 300); // Last 5 minutes
    if (recentRate > profile.avgRequestsPerHour * 3) {
      anomalies.push({
        reason: `High request rate: ${recentRate} req/5min (avg: ${profile.avgRequestsPerHour}/hour)`,
        score: 0.6
      });
    }

    // 5. Method anomaly
    const methodFreq = profile.requestMethods.get(request.method) || 0;
    const methodProbability = totalRequests > 0 ? methodFreq / totalRequests : 0;

    if (methodProbability < 0.1 && methodFreq > 0) {
      anomalies.push({
        reason: `Rare method: ${request.method} (used in ${(methodProbability * 100).toFixed(1)}% of requests)`,
        score: 0.25
      });
    }

    // Aggregate anomaly score
    const totalScore = anomalies.reduce((sum, a) => sum + a.score, 0);
    const normalizedScore = Math.min(totalScore, 1.0);

    return {
      isAnomalous: normalizedScore > 0.5,
      score: normalizedScore,
      reasons: anomalies.map((a) => a.reason)
    };
  }

  private async getRecentRequestRate(agentId: string, windowSeconds: number): Promise<number> {
    const key = `history:${agentId}:requests`;
    const now = Date.now();
    const windowStart = now - windowSeconds * 1000;

    // Count requests in time window
    const count = await this.redis.zcount(key, windowStart, now);

    return count;
  }

  private async getProfile(agentId: string): Promise<AgentProfile | null> {
    const key = `profile:${agentId}`;
    const data = await this.redis.get(key);

    if (!data) return null;

    const parsed = JSON.parse(data);

    return {
      ...parsed,
      commonPaths: new Map(parsed.commonPaths),
      requestMethods: new Map(parsed.requestMethods),
      lastUpdated: new Date(parsed.lastUpdated)
    };
  }

  private async saveProfile(agentId: string, profile: AgentProfile): Promise<void> {
    const key = `profile:${agentId}`;

    const serialized = {
      ...profile,
      commonPaths: Array.from(profile.commonPaths.entries()),
      requestMethods: Array.from(profile.requestMethods.entries())
    };

    await this.redis.setex(key, this.PROFILE_TTL, JSON.stringify(serialized));
  }

  private createEmptyProfile(agentId: string): AgentProfile {
    return {
      id: agentId,
      avgRequestsPerHour: 0,
      typicalActiveHours: [],
      commonPaths: new Map(),
      avgPayloadSize: 0,
      stdPayloadSize: 0,
      avgTimeBetweenRequests: 0,
      requestMethods: new Map(),
      lastUpdated: new Date()
    };
  }
}

// Integration in Gazorpazorp Gateway:
export class EnhancedSentinelGateway extends SentinelGateway {
  private anomalyDetector: AnomalyDetector;

  constructor(config: any) {
    super(config);
    this.anomalyDetector = new AnomalyDetector(this.redis);
  }

  protected async semanticMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
    const context = (req as any).sentinelContext;

    // Run standard semantic analysis
    await super.semanticMiddleware(req, res, next);

    // Add anomaly detection
    const anomaly = await this.anomalyDetector.detectAnomaly(context.agent.id, {
      path: req.path,
      method: req.method,
      body: req.body,
      timestamp: Date.now()
    });

    // Update profile for future comparisons
    await this.anomalyDetector.updateProfile(context.agent.id, {
      path: req.path,
      method: req.method,
      body: req.body,
      timestamp: Date.now()
    });

    // Increase risk score if anomalous
    if (anomaly.isAnomalous) {
      context.analysis.riskScore = Math.min(context.analysis.riskScore + anomaly.score * 20, 100);
      context.analysis.explanation += ` [Behavioral anomaly detected: ${anomaly.reasons.join(", ")}]`;
    }

    // Continue to policy middleware
  }
}
