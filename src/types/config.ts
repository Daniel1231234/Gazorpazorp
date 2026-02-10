// src/types/config.ts

export interface GatewayConfig {
  port: number;
  backendUrl: string;
  redisUrl: string;
  llmDeepModel: string;
  llmFastModel: string;
}

export interface LLMConfig {
  deepModel: string;
  fastModel: string;
  ollamaHost?: string;
  timeout?: number;
  maxRetries?: number;
}

export interface AnomalyDetectorConfig {
  timeWindowMs?: number;
  maxHistorySize?: number;
  anomalyThreshold?: number;
}

export interface CacheConfig {
  ttlSeconds?: number;
  maxCacheSize?: number;
}
