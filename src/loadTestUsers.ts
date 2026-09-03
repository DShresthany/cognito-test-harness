import { readFileSync } from "node:fs";
import { parse } from "yaml";

type YamlUser = {
  key: string;
  emailPrefix: string;
};

export type TestUser = {
  key: string;
  emailPrefix: string;
};

export function loadTestUsers(path = "testData/users.yaml"): TestUser[] {
  const doc = parse(readFileSync(path, "utf8")) as { users: YamlUser[] };
  if (!doc?.users?.length) {
    throw new Error(`No users found in ${path}`);
  }

  return doc.users.map((user) => {
    if (!user.key || !user.emailPrefix) {
      throw new Error(`Each YAML user needs key and emailPrefix`);
    }
    return { key: user.key, emailPrefix: user.emailPrefix };
  });
}
