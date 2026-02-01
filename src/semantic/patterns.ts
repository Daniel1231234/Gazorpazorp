// src/semantic/patterns.ts

export type ThreatType =
  | "prompt_injection"
  | "jailbreak_attempt"
  | "data_exfiltration"
  | "privilege_escalation"
  | "denial_of_service"
  | "sql_injection"
  | "command_injection"
  | "social_engineering"
  | "none";

export const THREAT_PATTERNS: Record<
  Exclude<ThreatType, "none" | "jailbreak_attempt" | "denial_of_service" | "sql_injection" | "social_engineering">,
  RegExp[]
> = {
  prompt_injection: [
    /ignore\s+(all\s+)?previous\s+instructions/i,
    /disregard\s+(the\s+)?above/i,
    /forget\s+(everything|what)\s+(you|I)\s+(told|said)/i,
    /you\s+are\s+now\s+a/i,
    /pretend\s+(you're|to\s+be)/i,
    /act\s+as\s+(if|though)/i,
    /system\s*:\s*/i,
    /\$INST\$/i,
    /<<SYS>>/i
  ],
  data_exfiltration: [
    /show\s+me\s+(all|the)\s+(users?|passwords?|secrets?|keys?|tokens?)/i,
    /dump\s+(the\s+)?(database|db|table)/i,
    /export\s+all/i,
    /list\s+(all\s+)?(api\s+)?keys/i
  ],
  privilege_escalation: [/grant\s+(me\s+)?admin/i, /make\s+me\s+(an?\s+)?admin/i, /elevate\s+(my\s+)?privileges/i, /sudo|root\s+access/i],
  command_injection: [/;\s*(rm|del|drop|truncate|delete)\s/i, /\|\s*(bash|sh|cmd|powershell)/i, /`[^`]+`/, /\$\([^)]+\)/]
};
