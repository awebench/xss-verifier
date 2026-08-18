import { createServer } from "node:net";

import { describe, expect, it } from "vitest";

import { serveResource } from "./server.js";

describe("static resource server", () => {
  it("continues serving only the configured entry document", async () => {
    const port = await freePort();
    const url = new URL(`http://127.0.0.1:${port}/victim.html`);
    const server = await serveResource(url, Buffer.from("<p>victim</p>"));

    try {
      const response = await fetch(`${url.href}?payload=test`);
      expect(response.status).toBe(200);
      await expect(response.text()).resolves.toBe("<p>victim</p>");

      const missing = await fetch(new URL("/other.html", url));
      expect(missing.status).toBe(404);
    } finally {
      await server.close();
    }
  });
});

async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("no TCP port allocated");
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
  return address.port;
}
