// src/utils/metrics.ts
import { Redis } from "ioredis";

export class MetricsCollector {
  private redis: Redis;

  constructor(redis: Redis) {
    this.redis = redis;
  }

  async increment(metric: string, tags: Record<string, string> = {}): Promise<void> {
    const key = `metrics:${metric}`;
    await this.redis.hincrby(key, JSON.stringify(tags), 1);
  }

  async recordTiming(metric: string, valueMs: number): Promise<void> {
    const key = `metrics:${metric}:timing`;
    await this.redis.lpush(key, valueMs);
    await this.redis.ltrim(key, 0, 999);
  }
}
