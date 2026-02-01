// src/policy/engine.ts
import { Redis } from "ioredis";
import { AgentPermissions } from "../crypto/agent-identity.js";
import { DEFAULT_RULES } from "./rules/defaults.js";

export interface PolicyRule {
  id: string;
  name: string;
  priority: number;
  conditions: PolicyCondition[];
  action: PolicyAction;
  enabled: boolean;
}

export interface PolicyCondition {
  field: string;
  operator: "eq" | "neq" | "gt" | "lt" | "contains" | "matches" | "in";
  value: unknown;
}

export interface PolicyAction {
  type: "allow" | "deny" | "rate_limit" | "log" | "alert" | "challenge";
  params?: Record<string, unknown>;
}

export class PolicyEngine {
  private rules: PolicyRule[] = [];
  private redis: Redis;

  constructor(redis: Redis) {
    this.redis = redis;
    this.loadDefaultRules();
  }

  private loadDefaultRules(): void {
    this.rules = DEFAULT_RULES;
  }

  async evaluate(context: PolicyContext): Promise<PolicyDecision> {
    const sortedRules = [...this.rules].filter((r) => r.enabled).sort((a, b) => a.priority - b.priority);

    for (const rule of sortedRules) {
      if (this.matchesAllConditions(rule.conditions, context)) {
        await this.logDecision(context, rule);

        return {
          action: rule.action,
          matchedRule: rule,
          context
        };
      }
    }

    return {
      action: { type: "allow" },
      matchedRule: null,
      context
    };
  }

  private matchesAllConditions(conditions: PolicyCondition[], context: PolicyContext): boolean {
    return conditions.every((cond) => this.evaluateCondition(cond, context));
  }

  private evaluateCondition(cond: PolicyCondition, context: PolicyContext): boolean {
    const value = this.getNestedValue(context, cond.field);

    switch (cond.operator) {
      case "eq":
        return value === cond.value;
      case "neq":
        return value !== cond.value;
      case "gt":
        return Number(value) > Number(cond.value);
      case "lt":
        return Number(value) < Number(cond.value);
      case "contains":
        return String(value).includes(String(cond.value));
      case "matches":
        return new RegExp(cond.value as string).test(String(value));
      case "in":
        return (cond.value as unknown[]).includes(value);
      default:
        return false;
    }
  }

  private getNestedValue(obj: any, path: string): any {
    return path.split(".").reduce((acc, key) => acc?.[key], obj);
  }

  private async logDecision(context: PolicyContext, rule: PolicyRule): Promise<void> {
    const logEntry = {
      timestamp: new Date().toISOString(),
      agentId: context.agent.id,
      requestPath: context.request.path,
      ruleId: rule.id,
      action: rule.action.type,
      riskScore: context.analysis.riskScore
    };

    await this.redis.lpush("gazorpazorp:audit_log", JSON.stringify(logEntry));
    await this.redis.ltrim("gazorpazorp:audit_log", 0, 99999);
  }
}

export interface PolicyContext {
  agent: {
    id: string;
    reputation: number;
    permissions: AgentPermissions;
  };
  request: {
    method: string;
    path: string;
    body: unknown;
    timestamp: number;
  };
  analysis: {
    riskScore: number;
    isMalicious: boolean;
    threatType: string;
  };
}

export interface PolicyDecision {
  action: PolicyAction;
  matchedRule: PolicyRule | null;
  context: PolicyContext;
}
