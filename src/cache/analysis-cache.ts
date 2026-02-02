import { createHash } from "crypto";
import { Redis } from "ioredis";
import { AnalysisResult, IntentAnalyzer } from "../semantic/intent-analyzer.js";

interface CacheConfig {
  ttl: number; // seconds
  keyPrefix: string;
  enableStats: boolean;
}

/**
 * Reputation bucket for cache segmentation.
 * This prevents cache poisoning where a high-reputation agent's
 * cached "safe" result could be returned for a low-reputation agent.
 *
 * Security consideration: An attacker with stolen high-reputation credentials
 * could poison the cache with "safe" results. By segmenting the cache by
 * reputation bucket, we ensure that analysis results are only reused for
 * agents with similar trust levels.
 */
type ReputationBucket = "untrusted" | "low" | "medium" | "high" | "trusted";

function getReputationBucket(reputation: number): ReputationBucket {
  if (reputation >= 90) return "trusted";
  if (reputation >= 70) return "high";
  if (reputation >= 50) return "medium";
  if (reputation >= 30) return "low";
  return "untrusted";
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
   * Generate cache key from request and reputation bucket.
   * Normalizes IDs and similar patterns for better hit rate.
   *
   * SECURITY: The reputation bucket is included in the key to prevent
   * cache poisoning attacks where a malicious actor with valid credentials
   * could seed the cache with "safe" results.
   */
  private generateKey(
    request: { method: string; path: string; body: unknown },
    reputationBucket: ReputationBucket
  ): string {
    // Normalize path - replace UUIDs first, then numeric IDs
    const normalizedPath = request.path
      .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, ":uuid")
      .replace(/\/\d+(?=\/|$)/g, "/:id");

    // Hash body content
    const bodyHash = createHash("sha256").update(JSON.stringify(request.body)).digest("hex");

    const composite = JSON.stringify({
      method: request.method,
      path: normalizedPath,
      bodyHash,
      reputationBucket // Include reputation bucket in cache key
    });

    const key = createHash("sha256").update(composite).digest("hex");

    return `${this.config.keyPrefix}${key}`;
  }

  async get(
    request: { method: string; path: string; body: unknown },
    reputation: number
  ): Promise<AnalysisResult | null> {
    const bucket = getReputationBucket(reputation);
    const key = this.generateKey(request, bucket);

    const cached = await this.redis.get(key);

    if (cached) {
      if (this.config.enableStats) this.stats.hits++;
      return JSON.parse(cached) as AnalysisResult;
    }

    if (this.config.enableStats) this.stats.misses++;
    return null;
  }

  async set(
    request: { method: string; path: string; body: unknown },
    result: AnalysisResult,
    reputation: number
  ): Promise<void> {
    const bucket = getReputationBucket(reputation);
    const key = this.generateKey(request, bucket);

    await this.redis.setex(key, this.config.ttl, JSON.stringify(result));

    if (this.config.enableStats) this.stats.sets++;
  }

  /**
   * Invalidate cache entries matching a pattern.
   * Uses SCAN instead of KEYS to avoid blocking Redis on large datasets.
   */
  async invalidate(pattern?: string): Promise<number> {
    const searchPattern = pattern || `${this.config.keyPrefix}*`;
    let cursor = "0";
    let deleted = 0;

    do {
      const [newCursor, keys] = await this.redis.scan(cursor, "MATCH", searchPattern, "COUNT", 100);
      cursor = newCursor;

      if (keys.length > 0) {
        deleted += await this.redis.del(...keys);
      }
    } while (cursor !== "0");

    return deleted;
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
    // Try cache first - now includes reputation bucket for security
    const cached = await this.cache.get(request, agentContext.reputation);
    if (cached) {
      return {
        ...cached,
        explanation: `[CACHED] ${cached.explanation}`
      };
    }

    // Cache miss - do real analysis
    const result = await super.analyzeIntent(request, agentContext);

    // Cache for future - segmented by reputation bucket
    await this.cache.set(request, result, agentContext.reputation);

    return result;
  }
}
