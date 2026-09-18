#!/usr/bin/env npx tsx
import {
  classifyFailedPhase,
  type CiGatePhase,
} from "../src/ciGate.js";

const phase = process.argv[2];
const phases = [
  "typecheck",
  "unit",
  "http",
  "infra-typecheck-and-assertions",
  "synth",
  "validate-manifest-and-preflight",
  "live-cognito",
  "cleanup-secret-files",
] as const satisfies readonly CiGatePhase[];

if (!phase || !(phases as readonly string[]).includes(phase)) {
  console.error(`usage: classify-ci-failure.ts <phase>`);
  process.exitCode = 1;
} else {
  console.log(classifyFailedPhase(phase as CiGatePhase));
}
