// src/utils/logger.ts
import winston from "winston";

/**
 * Structured logger using Winston.
 * Provides consistent log formatting, levels, and metadata support.
 */
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss.SSS" }),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
  ),
  defaultMeta: { service: "gazorpazorp-gateway" },
  transports: [
    // Console transport for all environments
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(({ timestamp, level, message, service, ...metadata }) => {
          let msg = `${timestamp} [${level}] [${service}] ${message}`;

          // Add metadata if present
          const metaKeys = Object.keys(metadata);
          if (metaKeys.length > 0) {
            msg += ` ${JSON.stringify(metadata)}`;
          }

          return msg;
        })
      )
    })
  ]
});

// Add file transport in production
if (process.env.NODE_ENV === "production") {
  logger.add(
    new winston.transports.File({
      filename: "logs/error.log",
      level: "error",
      maxsize: 10485760, // 10MB
      maxFiles: 5
    })
  );

  logger.add(
    new winston.transports.File({
      filename: "logs/combined.log",
      maxsize: 10485760, // 10MB
      maxFiles: 5
    })
  );
}

export { logger };
