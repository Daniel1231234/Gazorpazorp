import { THREAT_PATTERNS, ThreatType } from "./patterns.js";
import { ANALYSIS_PROMPT } from "./prompts/analysis.js";
import { z } from "zod";
import { CircuitBreaker } from "../utils/circuit-breaker.js";

const LlmResponseSchema = z.object({
  isMalicious: z.boolean(),
  confidence: z.number().min(0).max(1),
  threatType: z.string().optional(),
  explanation: z.string(),
  riskScore: z.number().min(0).max(100)
});

export interface AnalysisResult {
  isMalicious: boolean;
  confidence: number; // 0-1
  threatType?: ThreatType;
  explanation: string;
  suggestedAction: "allow" | "block" | "challenge" | "rate_limit";
  riskScore: number; // 0-100
}

export class IntentAnalyzer {
  private deepModel: string;
  private fastModel: string;
  private readonly MAX_CONTENT_LENGTH = 10000; // 10KB limit for LLM input
  private circuitBreaker: CircuitBreaker;

  constructor(config: { deepModel: string; fastModel: string }) {
    this.deepModel = config.deepModel;
    this.fastModel = config.fastModel;

    // Initialize circuit breaker for LLM service
    this.circuitBreaker = new CircuitBreaker({
      failureThreshold: 5, // Open after 5 consecutive failures
      successThreshold: 3, // Close after 3 consecutive successes
      timeout: 30000, // Wait 30 seconds before half-open
      name: "LLM Service"
    });
  }

  /**
   * Sanitize input before sending to LLM to prevent prompt injection.
   * Removes control characters, limits length, and escapes special sequences.
   */
  private sanitizeForLLM(input: string): string {
    return (
      input
        // Remove control characters (except newline and tab)
        .replace(/[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F-\x9F]/g, "")
        // Remove Unicode direction override characters (used in prompt injection)
        .replace(/[\u202A-\u202E\u2066-\u2069]/g, "")
        // Limit length to prevent resource exhaustion
        .substring(0, this.MAX_CONTENT_LENGTH)
        // Escape potential LLM instruction markers
        .replace(/###|```|<\|endoftext\|>|<\|im_end\|>/g, (match) => `[${match}]`)
    );
  }

  /**
   * Fast pre-screening with regex patterns
   */
  private preScreen(content: string): {
    suspicious: boolean;
    matchedThreats: ThreatType[];
  } {
    const matchedThreats: ThreatType[] = [];

    for (const [threatType, patterns] of Object.entries(THREAT_PATTERNS)) {
      for (const pattern of patterns) {
        if (pattern.test(content)) {
          matchedThreats.push(threatType as ThreatType);
          break;
        }
      }
    }

    return {
      suspicious: matchedThreats.length > 0,
      matchedThreats
    };
  }

  /**
   * Deep analysis using Local LLM
   */
  async analyzeIntent(
    request: { method: string; path: string; body: unknown },
    agentContext: { reputation: number; history: string[] }
  ): Promise<AnalysisResult> {
    // Sanitize request body before analysis
    const rawContent = JSON.stringify(request.body);
    const content = this.sanitizeForLLM(rawContent);

    // Step 1: Fast pre-screening
    const preScreenResult = this.preScreen(content);

    // Step 2: Determine Tiered Analysis Strategy
    // Tier A: Skip (High trust, no patterns)
    if (!preScreenResult.suspicious && agentContext.reputation > 95) {
      return {
        isMalicious: false,
        confidence: 0.95,
        explanation: "Tier A: Trusted agent, no suspicious patterns detected (Analysis skipped)",
        suggestedAction: "allow",
        riskScore: 5
      };
    }

    // Step 3: Choose Model
    // Deep model for suspicious patterns, untrusted agents, or large payloads
    const needsDeepAnalysis = preScreenResult.suspicious || agentContext.reputation < 40 || content.length > 1000;
    const modelToUse = needsDeepAnalysis ? this.deepModel : this.fastModel;
    const tier = needsDeepAnalysis ? "Deep" : "Fast";

    // Step 4: LLM Analysis with sanitized inputs
    const prompt = ANALYSIS_PROMPT.replace("{{method}}", this.sanitizeForLLM(request.method))
      .replace("{{path}}", this.sanitizeForLLM(request.path))
      .replace("{{content}}", content)
      .replace("{{reputation}}", agentContext.reputation.toString())
      .replace("{{flags}}", preScreenResult.matchedThreats.join(", ") || "None");

    try {
      // Use circuit breaker to protect against LLM service failures
      const result = await this.circuitBreaker.execute(async () => {
        const response = await fetch("http://localhost:11434/api/generate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            model: modelToUse,
            prompt: prompt,
            stream: false,
            format: "json"
          }),
          signal: AbortSignal.timeout(10000) // 10 second timeout
        });

        if (!response.ok) {
          throw new Error(`LLM service returned ${response.status}`);
        }

        return response.json();
      });

      // Parse and Validate LLM response using Zod
      const rawAnalysis = JSON.parse(result.response);
      const validation = LlmResponseSchema.safeParse(rawAnalysis);

      if (!validation.success) {
        throw new Error(`Invalid LLM response structure: ${validation.error.message}`);
      }

      const analysis = validation.data;

      return {
        isMalicious: analysis.isMalicious,
        confidence: analysis.confidence,
        threatType: (analysis.threatType as ThreatType) || "none",
        explanation: `Tier ${tier}: ${analysis.explanation}`,
        suggestedAction: this.determineAction(analysis.riskScore, agentContext.reputation),
        riskScore: analysis.riskScore
      };
    } catch (error) {
      // LLM Service Failure (circuit open, timeout, or service error)
      const circuitState = this.circuitBreaker.getState();
      const isCircuitOpen = circuitState === "OPEN";

      // If circuit is open, log the issue
      if (isCircuitOpen) {
        console.warn("Circuit breaker OPEN - LLM service unavailable");
      }

      // Implement Fail-Closed / Robust Fallback
      if (preScreenResult.suspicious) {
        return {
          isMalicious: true,
          confidence: 0.8,
          threatType: preScreenResult.matchedThreats[0],
          explanation: "LLM analysis unavailable. Blocked due to suspicious RegEx patterns.",
          suggestedAction: "block",
          riskScore: 90
        };
      }

      // If reputation is low, we fail-closed (block or challenge)
      if (agentContext.reputation < 60) {
        return {
          isMalicious: true,
          confidence: 0.5,
          explanation: "LLM analysis unavailable. Blocked untrusted agent (Reputation < 60) during service outage.",
          suggestedAction: "block",
          riskScore: 80
        };
      }

      if (agentContext.reputation < 85) {
        return {
          isMalicious: false,
          confidence: 0.4,
          explanation: "LLM analysis unavailable. Issuing challenge to moderately trusted agent.",
          suggestedAction: "challenge",
          riskScore: 50
        };
      }

      // Only high-reputation agents are allowed to pass through during downtime
      return {
        isMalicious: false,
        confidence: 0.3,
        explanation: "LLM analysis unavailable. Allowing trusted agent (Fail-Open for high reputation).",
        suggestedAction: "allow",
        riskScore: 20
      };
    }
  }

  private determineAction(riskScore: number, reputation: number): "allow" | "block" | "challenge" | "rate_limit" {
    const adjustedRisk = riskScore - (reputation - 50) * 0.3;

    if (adjustedRisk >= 80) return "block";
    if (adjustedRisk >= 60) return "challenge";
    if (adjustedRisk >= 40) return "rate_limit";
    return "allow";
  }
}
