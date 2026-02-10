// src/utils/config-loader.ts
import { readFileSync, existsSync } from "fs";
import { resolve } from "path";
import { z } from "zod";
import { logger } from "./logger.js";

/**
 * Configuration schema with validation
 */
const ConfigSchema = z.object({
  gateway: z.object({
    port: z.number().int().min(1).max(65535).default(3000),
    backendUrl: z.string().url(),
    maxPayloadSize: z.number().int().positive().default(1048576), // 1MB
    corsEnabled: z.boolean().default(false),
    corsOrigins: z.array(z.string()).default([])
  }),

  redis: z.object({
    url: z.string().default("redis://localhost:6379"),
    keyPrefix: z.string().default("gazorpazorp:"),
    connectionTimeout: z.number().int().positive().default(5000)
  }),

  llm: z.object({
    deepModel: z.string().default("llama3:8b"),
    fastModel: z.string().default("tinyllama"),
    ollamaHost: z.string().url().default("http://localhost:11434"),
    timeout: z.number().int().positive().default(10000),
    maxRetries: z.number().int().min(0).default(3)
  }),

  security: z.object({
    rateLimiting: z.object({
      enabled: z.boolean().default(true),
      maxRequestsPerMinute: z.number().int().positive().default(100),
      challengeVerificationMaxPerMinute: z.number().int().positive().default(10)
    }),
    challenges: z.object({
      enabled: z.boolean().default(true),
      ttlSeconds: z.number().int().positive().default(300),
      proofOfWorkDifficulty: z.number().int().min(1).max(10).default(4)
    }),
    circuitBreaker: z.object({
      failureThreshold: z.number().int().positive().default(5),
      successThreshold: z.number().int().positive().default(3),
      timeoutMs: z.number().int().positive().default(30000)
    })
  }),

  observability: z.object({
    metricsEnabled: z.boolean().default(true),
    metricsPort: z.number().int().min(1).max(65535).default(9090),
    logLevel: z.enum(["error", "warn", "info", "debug"]).default("info"),
    structuredLogging: z.boolean().default(true)
  })
});

export type GazorpazorpConfig = z.infer<typeof ConfigSchema>;

/**
 * Config loader with support for JSON/YAML files and environment variable overrides
 */
export class ConfigLoader {
  private static readonly CONFIG_PATHS = [
    "config.json",
    "config.yaml",
    "config.yml",
    process.env.CONFIG_FILE || ""
  ];

  /**
   * Load configuration from file with environment variable overrides
   */
  static load(): GazorpazorpConfig {
    let configData: any = {};

    // Try to load from file
    const configPath = this.findConfigFile();
    if (configPath) {
      logger.info("Loading configuration", { path: configPath });
      try {
        const fileContent = readFileSync(configPath, "utf-8");
        configData = JSON.parse(fileContent);
      } catch (error) {
        logger.error("Failed to parse config file", { path: configPath, error });
        throw new Error(`Failed to parse config file: ${configPath}`);
      }
    } else {
      logger.warn("No config file found, using defaults and environment variables");
    }

    // Apply environment variable overrides
    const envOverrides = this.getEnvironmentOverrides();
    const mergedConfig = this.deepMerge(configData, envOverrides);

    // Validate configuration
    try {
      const validated = ConfigSchema.parse(mergedConfig);
      logger.info("Configuration loaded successfully", {
        port: validated.gateway.port,
        backendUrl: validated.gateway.backendUrl,
        logLevel: validated.observability.logLevel
      });
      return validated;
    } catch (error) {
      if (error instanceof z.ZodError) {
        const issues = error.issues || [];
        logger.error("Configuration validation failed", {
          errors: issues.map((e: z.ZodIssue) => `${e.path.join(".")}: ${e.message}`)
        });
        throw new Error(`Configuration validation failed: ${issues[0]?.message || "Unknown error"}`);
      }
      throw error;
    }
  }

  /**
   * Find the first existing config file
   */
  private static findConfigFile(): string | null {
    for (const path of this.CONFIG_PATHS) {
      if (path && existsSync(resolve(path))) {
        return resolve(path);
      }
    }
    return null;
  }

  /**
   * Extract configuration overrides from environment variables
   */
  private static getEnvironmentOverrides(): any {
    const env = process.env;

    return {
      gateway: {
        ...(env.PORT && { port: parseInt(env.PORT, 10) }),
        ...(env.BACKEND_URL && { backendUrl: env.BACKEND_URL }),
        ...(env.MAX_PAYLOAD_SIZE && { maxPayloadSize: parseInt(env.MAX_PAYLOAD_SIZE, 10) }),
        ...(env.CORS_ENABLED && { corsEnabled: env.CORS_ENABLED === "true" }),
        ...(env.CORS_ORIGINS && { corsOrigins: env.CORS_ORIGINS.split(",") })
      },

      redis: {
        ...(env.REDIS_URL && { url: env.REDIS_URL }),
        ...(env.REDIS_KEY_PREFIX && { keyPrefix: env.REDIS_KEY_PREFIX })
      },

      llm: {
        ...(env.LLM_DEEP_MODEL && { deepModel: env.LLM_DEEP_MODEL }),
        ...(env.LLM_FAST_MODEL && { fastModel: env.LLM_FAST_MODEL }),
        ...(env.OLLAMA_HOST && { ollamaHost: env.OLLAMA_HOST }),
        ...(env.LLM_TIMEOUT && { timeout: parseInt(env.LLM_TIMEOUT, 10) })
      },

      security: {
        rateLimiting: {
          ...(env.RATE_LIMIT_ENABLED && { enabled: env.RATE_LIMIT_ENABLED === "true" }),
          ...(env.MAX_REQUESTS_PER_MINUTE && { maxRequestsPerMinute: parseInt(env.MAX_REQUESTS_PER_MINUTE, 10) })
        },
        challenges: {
          ...(env.CHALLENGES_ENABLED && { enabled: env.CHALLENGES_ENABLED === "true" })
        }
      },

      observability: {
        ...(env.METRICS_ENABLED && { metricsEnabled: env.METRICS_ENABLED === "true" }),
        ...(env.METRICS_PORT && { metricsPort: parseInt(env.METRICS_PORT, 10) }),
        ...(env.LOG_LEVEL && { logLevel: env.LOG_LEVEL })
      }
    };
  }

  /**
   * Deep merge two objects
   */
  private static deepMerge(target: any, source: any): any {
    const result = { ...target };

    for (const key in source) {
      if (source[key] !== undefined && source[key] !== null) {
        if (typeof source[key] === "object" && !Array.isArray(source[key])) {
          result[key] = this.deepMerge(result[key] || {}, source[key]);
        } else {
          result[key] = source[key];
        }
      }
    }

    return result;
  }

  /**
   * Generate example configuration file content
   */
  static generateExample(): string {
    const example: Partial<GazorpazorpConfig> = {
      gateway: {
        port: 3000,
        backendUrl: "http://localhost:8080",
        maxPayloadSize: 1048576,
        corsEnabled: false,
        corsOrigins: []
      },
      redis: {
        url: "redis://localhost:6379",
        keyPrefix: "gazorpazorp:",
        connectionTimeout: 5000
      },
      llm: {
        deepModel: "llama3:8b",
        fastModel: "tinyllama",
        ollamaHost: "http://localhost:11434",
        timeout: 10000,
        maxRetries: 3
      },
      security: {
        rateLimiting: {
          enabled: true,
          maxRequestsPerMinute: 100,
          challengeVerificationMaxPerMinute: 10
        },
        challenges: {
          enabled: true,
          ttlSeconds: 300,
          proofOfWorkDifficulty: 4
        },
        circuitBreaker: {
          failureThreshold: 5,
          successThreshold: 3,
          timeoutMs: 30000
        }
      },
      observability: {
        metricsEnabled: true,
        metricsPort: 9090,
        logLevel: "info",
        structuredLogging: true
      }
    };

    return JSON.stringify(example, null, 2);
  }
}
