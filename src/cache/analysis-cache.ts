import { createHash } from "crypto";
import { Redis } from "ioredis";
import { AnalysisResult, IntentAnalyzer } from "../semantic/intent-analyzer.js";

interface CacheConfig {
  ttl: number; // seconds
  keyPrefix: string;
  enableStats: boolean;
}

export class AnalysisCache {
  private redis: Redis;
  private config: CacheConfig;
  private stats = {
    hits: 0,
    misses: 0,
    sets: 0
  };

  constructor(redis: Redis, config: Partial<CacheConfig> = {}) {
    this.redis = redis;
    this.config = {
      ttl: config.ttl || 3600,
      keyPrefix: config.keyPrefix || "analysis:",
      enableStats: config.enableStats ?? true
    };
  }

  /**
   * Generate cache key from request
   * Normalizes IDs and similar patterns for better hit rate
   */
  private generateKey(request: { method: string; path: string; body: unknown }): string {
    // Normalize path - replace numeric IDs with :id
    const normalizedPath = request.path
      .replace(/\/\d+/g, "/:id")
      .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, ":uuid");

    // Hash body content
    const bodyHash = createHash("sha256").update(JSON.stringify(request.body)).digest("hex");

    const composite = JSON.stringify({
      method: request.method,
      path: normalizedPath,
      bodyHash
    });

    const key = createHash("sha256").update(composite).digest("hex");

    return `${this.config.keyPrefix}${key}`;
  }

  async get(request: { method: string; path: string; body: unknown }): Promise<AnalysisResult | null> {
    const key = this.generateKey(request);

    const cached = await this.redis.get(key);

    if (cached) {
      if (this.config.enableStats) this.stats.hits++;
      return JSON.parse(cached) as AnalysisResult;
    }

    if (this.config.enableStats) this.stats.misses++;
    return null;
  }

  async set(request: { method: string; path: string; body: unknown }, result: AnalysisResult): Promise<void> {
    const key = this.generateKey(request);

    await this.redis.setex(key, this.config.ttl, JSON.stringify(result));

    if (this.config.enableStats) this.stats.sets++;
  }

  async invalidate(pattern?: string): Promise<number> {
    const searchPattern = pattern || `${this.config.keyPrefix}*`;
    const keys = await this.redis.keys(searchPattern);

    if (keys.length === 0) return 0;

    return await this.redis.del(...keys);
  }

  getStats() {
    const total = this.stats.hits + this.stats.misses;
    const hitRate = total > 0 ? (this.stats.hits / total) * 100 : 0;

    return {
      ...this.stats,
      hitRate: `${hitRate.toFixed(2)}%`,
      total
    };
  }

  resetStats(): void {
    this.stats = { hits: 0, misses: 0, sets: 0 };
  }
}

// Usage in IntentAnalyzer:
export class CachedIntentAnalyzer extends IntentAnalyzer {
  private cache: AnalysisCache;

  constructor(config: any, redis: Redis) {
    super(config);
    this.cache = new AnalysisCache(redis, {
      ttl: 1800, // 30 minutes
      enableStats: true
    });
  }

  async analyzeIntent(
    request: { method: string; path: string; body: unknown },
    agentContext: { reputation: number; history: string[] }
  ): Promise<AnalysisResult> {
    // Try cache first
    const cached = await this.cache.get(request);
    if (cached) {
      return {
        ...cached,
        explanation: `[CACHED] ${cached.explanation}`
      };
    }

    // Cache miss - do real analysis
    const result = await super.analyzeIntent(request, agentContext);

    // Cache for future
    await this.cache.set(request, result);

    return result;
  }
}
