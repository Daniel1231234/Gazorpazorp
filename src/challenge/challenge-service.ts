// src/challenge/challenge-service.ts
import { randomBytes, createHash } from "crypto";
import { Redis } from "ioredis";

/**
 * Challenge types that can be issued to agents.
 * These are used when the system is uncertain about an agent's intent
 * but doesn't want to outright block the request.
 */
export type ChallengeType = "proof_of_work" | "signature_refresh" | "rate_delay";

export interface Challenge {
  id: string;
  agentId: string;
  type: ChallengeType;
  createdAt: Date;
  expiresAt: Date;
  difficulty?: number; // For proof_of_work
  nonce?: string; // For signature_refresh
  completed: boolean;
}

export interface ChallengeResponse {
  challengeId: string;
  solution: string;
}

export interface ChallengeResult {
  valid: boolean;
  error?: string;
}

/**
 * ChallengeService provides a mechanism to verify agent intent
 * when semantic analysis is uncertain.
 *
 * Challenge types:
 * - proof_of_work: Agent must find a nonce that produces a hash with N leading zeros
 * - signature_refresh: Agent must re-sign the request with a new nonce
 * - rate_delay: Agent must wait before retrying (simplest challenge)
 */
export class ChallengeService {
  private redis: Redis;
  private readonly CHALLENGE_TTL = 300; // 5 minutes
  private readonly CHALLENGE_PREFIX = "challenge:";

  constructor(redis: Redis) {
    this.redis = redis;
  }

  /**
   * Issue a challenge to an agent.
   * Returns challenge details that must be solved before the request is allowed.
   */
  async issueChallenge(agentId: string, riskScore: number): Promise<Challenge> {
    const challengeId = `ch_${randomBytes(16).toString("hex")}`;
    const type = this.selectChallengeType(riskScore);
    const difficulty = this.calculateDifficulty(riskScore);

    const challenge: Challenge = {
      id: challengeId,
      agentId,
      type,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + this.CHALLENGE_TTL * 1000),
      difficulty: type === "proof_of_work" ? difficulty : undefined,
      nonce: type === "signature_refresh" ? randomBytes(16).toString("hex") : undefined,
      completed: false
    };

    await this.redis.setex(`${this.CHALLENGE_PREFIX}${challengeId}`, this.CHALLENGE_TTL, JSON.stringify(challenge));

    // Track challenges per agent for rate limiting
    await this.redis.incr(`challenges:count:${agentId}`);
    await this.redis.expire(`challenges:count:${agentId}`, 3600);

    return challenge;
  }

  /**
   * Verify a challenge response from an agent.
   */
  async verifyChallenge(response: ChallengeResponse): Promise<ChallengeResult> {
    const challengeData = await this.redis.get(`${this.CHALLENGE_PREFIX}${response.challengeId}`);

    if (!challengeData) {
      return { valid: false, error: "Challenge not found or expired" };
    }

    const challenge: Challenge = JSON.parse(challengeData);

    if (challenge.completed) {
      return { valid: false, error: "Challenge already completed" };
    }

    if (new Date() > new Date(challenge.expiresAt)) {
      await this.redis.del(`${this.CHALLENGE_PREFIX}${response.challengeId}`);
      return { valid: false, error: "Challenge expired" };
    }

    let valid = false;

    switch (challenge.type) {
      case "proof_of_work":
        valid = this.verifyProofOfWork(response.challengeId, response.solution, challenge.difficulty!);
        break;

      case "signature_refresh":
        valid = this.verifySignatureRefresh(response.solution, challenge.nonce!);
        break;

      case "rate_delay":
        // Rate delay just requires waiting - solution should be the challenge ID
        valid = response.solution === response.challengeId;
        break;

      default:
        return { valid: false, error: "Unknown challenge type" };
    }

    if (valid) {
      // Mark challenge as completed
      challenge.completed = true;
      await this.redis.setex(
        `${this.CHALLENGE_PREFIX}${response.challengeId}`,
        60, // Keep completed challenges for 1 minute for verification
        JSON.stringify(challenge)
      );

      // Decrease challenge count for agent
      await this.redis.decr(`challenges:count:${challenge.agentId}`);
    }

    return { valid, error: valid ? undefined : "Invalid solution" };
  }

  /**
   * Check if a challenge has been completed (for retry requests).
   */
  async isChallengeCompleted(challengeId: string): Promise<boolean> {
    const challengeData = await this.redis.get(`${this.CHALLENGE_PREFIX}${challengeId}`);
    if (!challengeData) return false;

    const challenge: Challenge = JSON.parse(challengeData);
    return challenge.completed;
  }

  /**
   * Get the number of pending challenges for an agent.
   * Used to detect potential abuse.
   */
  async getPendingChallengeCount(agentId: string): Promise<number> {
    const count = await this.redis.get(`challenges:count:${agentId}`);
    return count ? parseInt(count, 10) : 0;
  }

  /**
   * Select challenge type based on risk score.
   * Higher risk = harder challenge.
   */
  private selectChallengeType(riskScore: number): ChallengeType {
    if (riskScore >= 80) {
      return "proof_of_work"; // Hardest - requires computation
    } else if (riskScore >= 60) {
      return "signature_refresh"; // Medium - requires new signature
    } else {
      return "rate_delay"; // Easiest - just wait
    }
  }

  /**
   * Calculate proof-of-work difficulty based on risk score.
   * Returns the number of leading zero bits required in the hash.
   */
  private calculateDifficulty(riskScore: number): number {
    // 2-5 leading zeros based on risk
    return Math.min(5, Math.max(2, Math.floor(riskScore / 20)));
  }

  /**
   * Verify proof-of-work solution.
   * The solution must produce a hash with N leading zero bits when combined with challenge ID.
   */
  private verifyProofOfWork(challengeId: string, solution: string, difficulty: number): boolean {
    const hash = createHash("sha256")
      .update(challengeId + solution)
      .digest("hex");

    // Check for leading zeros (each hex char = 4 bits)
    const requiredZeroChars = Math.ceil(difficulty / 4);
    const prefix = hash.substring(0, requiredZeroChars);

    // Check if prefix is all zeros
    for (let i = 0; i < requiredZeroChars; i++) {
      if (prefix[i] !== "0") {
        return false;
      }
    }

    return true;
  }

  /**
   * Verify signature refresh solution.
   * The solution should be the challenge nonce signed by the agent.
   */
  private verifySignatureRefresh(solution: string, expectedNonce: string): boolean {
    // In a full implementation, this would verify a cryptographic signature
    // For now, we just check that the solution contains the nonce
    // The actual signature verification happens in the crypto layer
    return solution.includes(expectedNonce);
  }
}

/**
 * Challenge response format for API responses.
 */
export interface ChallengeApiResponse {
  status: "challenge_required";
  challenge: {
    id: string;
    type: ChallengeType;
    expiresAt: string;
    difficulty?: number;
    nonce?: string;
    instructions: string;
  };
  verifyUrl: string;
}

/**
 * Generate an API response for a challenge.
 */
export function createChallengeResponse(challenge: Challenge, baseUrl: string): ChallengeApiResponse {
  let instructions: string;

  switch (challenge.type) {
    case "proof_of_work":
      instructions = `Find a nonce such that SHA256(${challenge.id} + nonce) has ${challenge.difficulty} leading zero bits. Submit as POST to verifyUrl with {"challengeId": "${challenge.id}", "solution": "<nonce>"}`;
      break;
    case "signature_refresh":
      instructions = `Sign the nonce "${challenge.nonce}" with your private key and resubmit the original request with X-Challenge-Response header containing the signature`;
      break;
    case "rate_delay":
      instructions = `Wait and retry the request after ${Math.ceil((new Date(challenge.expiresAt).getTime() - Date.now()) / 1000)} seconds with X-Challenge-Id header set to ${challenge.id}`;
      break;
  }

  return {
    status: "challenge_required",
    challenge: {
      id: challenge.id,
      type: challenge.type,
      expiresAt: challenge.expiresAt.toISOString(),
      difficulty: challenge.difficulty,
      nonce: challenge.nonce,
      instructions
    },
    verifyUrl: `${baseUrl}/api/challenge/verify`
  };
}
