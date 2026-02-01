// src/policy/rules/defaults.ts
import { PolicyRule } from "../engine.js";

export const DEFAULT_RULES: PolicyRule[] = [
  {
    id: "block_high_risk",
    name: "Block High Risk Requests",
    priority: 1,
    conditions: [{ field: "analysis.riskScore", operator: "gt", value: 90 }],
    action: { type: "deny", params: { reason: "High risk score detected" } },
    enabled: true
  },
  {
    id: "rate_limit_untrusted",
    name: "Rate Limit Untrusted Agents",
    priority: 10,
    conditions: [{ field: "agent.reputation", operator: "lt", value: 30 }],
    action: {
      type: "rate_limit",
      params: { maxRequests: 10, windowSeconds: 60 }
    },
    enabled: true
  },
  {
    id: "protect_admin",
    name: "Protect Admin Endpoints",
    priority: 5,
    conditions: [
      { field: "request.path", operator: "matches", value: "^/api/admin" },
      { field: "agent.permissions.sensitiveDataAccess", operator: "eq", value: false }
    ],
    action: { type: "deny", params: { reason: "Admin access not permitted" } },
    enabled: true
  },
  {
    id: "challenge_suspicious",
    name: "Challenge Suspicious Requests",
    priority: 20,
    conditions: [
      { field: "analysis.riskScore", operator: "gt", value: 50 },
      { field: "analysis.riskScore", operator: "lt", value: 90 }
    ],
    action: { type: "challenge" },
    enabled: true
  }
];
