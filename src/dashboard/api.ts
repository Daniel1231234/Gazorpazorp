// src/dashboard/api.ts
import { Router } from "express";
import { Redis } from "ioredis";

export function createDashboardRouter(redis: Redis): Router {
  const router = Router();

  // Security events timeline
  router.get("/events", async (req, res) => {
    const events = await redis.lrange("gazorpazorp:security_events", 0, 99);
    res.json(events.map((e) => JSON.parse(e)));
  });

  // Agent statistics
  router.get("/agents/:id/stats", async (req, res) => {
    const { id } = req.params;
    const history = await redis.lrange(`agent:${id}:history`, 0, -1);

    const stats = {
      totalRequests: history.length,
      averageRiskScore: 0,
      blockedRequests: 0,
      lastActive: null as Date | null
    };

    if (history.length > 0) {
      const parsed = history.map((h) => JSON.parse(h));
      stats.averageRiskScore = parsed.reduce((sum, h) => sum + h.riskScore, 0) / parsed.length;
      stats.blockedRequests = parsed.filter((h) => h.riskScore > 70).length;
      stats.lastActive = new Date(parsed[0].timestamp);
    }

    res.json(stats);
  });

  // Real-time threat map
  router.get("/threats/live", async (req, res) => {
    // SSE for real-time updates
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");

    const subscriber = redis.duplicate();
    await subscriber.subscribe("gazorpazorp:threats");

    subscriber.on("message", (channel, message) => {
      res.write(`data: ${message}\n\n`);
    });

    req.on("close", () => {
      subscriber.unsubscribe();
      subscriber.disconnect();
    });
  });

  return router;
}
