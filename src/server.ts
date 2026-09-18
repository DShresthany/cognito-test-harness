import { serve } from "@hono/node-server";
import { config } from "dotenv";
import { createHarnessComposition } from "./createHarnessComposition.js";

config();

const { app } = await createHarnessComposition({
  reportDiagnostic: {
    report(diagnostic) {
      console.log(JSON.stringify(diagnostic));
    },
  },
});

serve({
  fetch: app.fetch,
  port: 3000,
});

console.log("listening on http://localhost:3000");
