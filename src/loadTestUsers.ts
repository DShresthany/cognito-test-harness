import { readFileSync } from "node:fs";
import { parse } from "yaml";

type YamlUser = {
  key: string;
  email: string;
  passwordEnv: string;
};

export type TestUser = {
  key: string;
  email: string;
  password: string;
};

export function loadTestUsers(path = "testData/users.yaml"): TestUser[] {
  const doc = parse(readFileSync(path, "utf8")) as { users: YamlUser[] };
  if (!doc?.users?.length) {
    throw new Error(`No users found in ${path}`);
  }

  return doc.users.map((u) => {
    const password = process.env[u.passwordEnv];
    if (!password) {
      throw new Error(`Missing env ${u.passwordEnv} for user key "${u.key}"`);
    }
    return { key: u.key, email: u.email, password };
  });
}