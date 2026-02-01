import { THREAT_PATTERNS, ThreatType } from "./patterns.js";
import { ANALYSIS_PROMPT } from "./prompts/analysis.js";
import { z } from "zod";

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

  constructor(config: { deepModel: string; fastModel: string }) {
    this.deepModel = config.deepModel;
    this.fastModel = config.fastModel;
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
    const content = JSON.stringify(request.body);

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

    // Step 4: LLM Analysis
    const prompt = ANALYSIS_PROMPT.replace("{{method}}", request.method)
      .replace("{{path}}", request.path)
      .replace("{{content}}", content)
      .replace("{{reputation}}", agentContext.reputation.toString())
      .replace("{{flags}}", preScreenResult.matchedThreats.join(", ") || "None");

    try {
      const response = await fetch("http://localhost:11434/api/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: modelToUse,
          prompt: prompt,
          stream: false,
          format: "json"
        })
      });

      const result = await response.json();

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
      // LLM Service Failure - Implement Fail-Closed / Robust Fallback
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
