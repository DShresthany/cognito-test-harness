import { serve } from "@hono/node-server";
import { config } from "dotenv";
import { createApp } from "./app.js";
import { CognitoLoginManager } from "./cognitoLoginManager.js";

config();

serve({
  fetch: createApp(CognitoLoginManager.fromEnv()).fetch,
  port: 3000,
});

console.log("listening on http://localhost:3000");
