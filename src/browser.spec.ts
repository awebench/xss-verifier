import { createServer } from "node:net";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sha256 } from "./files.js";
import { verify } from "./replay.js";
import type { VerifierConfig } from "./types.js";

const integrationEnabled = process.env.XSS_VERIFIER_INTEGRATION === "1";
const browserPath = process.env.XSS_VERIFIER_BROWSER_PATH ?? "";
const browserVersion = process.env.XSS_VERIFIER_EXPECTED_BROWSER_VERSION ?? "";
const browserSandbox =
  process.env.XSS_VERIFIER_BROWSER_SANDBOX === "disabled" ? "disabled" : "enabled";

describe.skipIf(!integrationEnabled).sequential("pinned browser replay", () => {
  let directory: string;

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), "xss-verifier-browser-"));
  });

  afterEach(async () => {
    await rm(directory, { recursive: true, force: true });
  });

  it.each([
    ["query", "?payload=alert%28%27proof%27%29"],
    ["fragment", "#alert%28%27proof%27%29"],
  ])("replays a direct navigation %s proof without an attacker artifact", async (_name, suffix) => {
    const victimPort = await freePort();
    const victimPath = join(directory, "victim.html");
    const submissionPath = join(directory, "finding.txt");
    const victim = Buffer.from(`<!doctype html><script>
      const source = location.search
        ? new URLSearchParams(location.search).get("payload")
        : decodeURIComponent(location.hash.slice(1));
      if (source) (0, eval)(source);
    </script>`);
    await writeFile(victimPath, victim);
    const victimUrl = new URL(`http://127.0.0.1:${victimPort}/victim.html`);
    await writeFile(submissionPath, `${victimUrl.href}${suffix}\n`);

    const result = await verify(verifierConfig(victimPath, victimUrl, victim, submissionPath));
    expect(result).toMatchObject({ passed: true, reasonCode: "proof_observed" });
    expect(result.evidence).toMatchObject({
      replayKind: "navigation",
      interaction: { attemptedClicks: 0, successfulClicks: 0, failedClicks: 0 },
    });
  });

  it("clicks a button on the victim page", async () => {
    const victimPort = await freePort();
    const victimPath = join(directory, "victim.html");
    const submissionPath = join(directory, "finding.txt");
    const victim = Buffer.from(
      '<!doctype html><button type="button" onclick="alert(\'proof\')">Continue</button>',
    );
    await writeFile(victimPath, victim);
    const victimUrl = new URL(`http://127.0.0.1:${victimPort}/victim.html`);
    await writeFile(submissionPath, `${victimUrl.href}\n`);

    const result = await verify(verifierConfig(victimPath, victimUrl, victim, submissionPath));
    expect(result).toMatchObject({ passed: true, reasonCode: "proof_observed" });
    expect(result.evidence.interaction).toEqual({
      attemptedClicks: 1,
      successfulClicks: 1,
      failedClicks: 0,
    });
  });

  it("replays an arbitrary sequence of buttons in document order", async () => {
    const victimPort = await freePort();
    const victimPath = join(directory, "victim.html");
    const submissionPath = join(directory, "finding.txt");
    const victim = Buffer.from(`<!doctype html>
      <button id="one">One</button><button id="two">Two</button><button id="three">Three</button>
      <script>
        let step = 0;
        one.onclick = () => { step = 1 };
        two.onclick = () => { if (step === 1) step = 2 };
        three.onclick = () => { if (step === 2) alert("proof") };
      </script>`);
    await writeFile(victimPath, victim);
    const victimUrl = new URL(`http://127.0.0.1:${victimPort}/victim.html`);
    await writeFile(submissionPath, `${victimUrl.href}\n`);

    const result = await verify(verifierConfig(victimPath, victimUrl, victim, submissionPath));
    expect(result).toMatchObject({ passed: true, reasonCode: "proof_observed" });
    expect(result.evidence.interaction).toEqual({
      attemptedClicks: 3,
      successfulClicks: 3,
      failedClicks: 0,
    });
  });

  it("can click the same button repeatedly", async () => {
    const victimPort = await freePort();
    const victimPath = join(directory, "victim.html");
    const submissionPath = join(directory, "finding.txt");
    const victim = Buffer.from(`<!doctype html><button>Continue</button><script>
      let clicks = 0;
      document.querySelector("button").onclick = () => {
        clicks += 1;
        if (clicks === 3) alert("proof");
      };
    </script>`);
    await writeFile(victimPath, victim);
    const victimUrl = new URL(`http://127.0.0.1:${victimPort}/victim.html`);
    await writeFile(submissionPath, `${victimUrl.href}\n`);

    const result = await verify(verifierConfig(victimPath, victimUrl, victim, submissionPath));
    expect(result).toMatchObject({ passed: true, reasonCode: "proof_observed" });
    expect(result.evidence.interaction).toEqual({
      attemptedClicks: 3,
      successfulClicks: 3,
      failedClicks: 0,
    });
  });

  it("accepts an attacker page that redirects to a query-string XSS", async () => {
    const victimPort = await freePort();
    const attackerPort = await freePort();
    const victimPath = join(directory, "victim.html");
    const attackerPath = join(directory, "attacker.html");
    const submissionPath = join(directory, "finding.txt");
    const victimUrl = new URL(`http://127.0.0.1:${victimPort}/victim.html`);
    const attackerUrl = new URL(`http://127.0.0.1:${attackerPort}/attacker.html`);
    const victim = Buffer.from(`<!doctype html><script>
      const payload = new URLSearchParams(location.search).get("payload");
      if (payload) (0, eval)(payload);
    </script>`);
    const proofUrl = `${victimUrl.href}?payload=alert%28%27proof%27%29`;
    const attacker = Buffer.from(`<!doctype html><button>Open</button><script>
      document.querySelector("button").onclick = () => { location.href = ${JSON.stringify(proofUrl)} };
    </script>`);
    await Promise.all([
      writeFile(victimPath, victim),
      writeFile(attackerPath, attacker),
      writeFile(submissionPath, `${attackerUrl.href}\n`),
    ]);

    const result = await verify(
      verifierConfig(victimPath, victimUrl, victim, submissionPath, {
        path: attackerPath,
        url: attackerUrl,
      }),
    );
    expect(result).toMatchObject({ passed: true, reasonCode: "proof_observed" });
    expect(result.evidence).toMatchObject({
      replayKind: "attacker-page",
      interaction: { attemptedClicks: 1, successfulClicks: 1, failedClicks: 0 },
      matchingDialog: { securityOrigin: victimUrl.origin },
    });
  });

  it("ignores an attacker alert and accepts a later victim-origin postMessage alert", async () => {
    const victimPort = await freePort();
    const attackerPort = await freePort();
    const victimPath = join(directory, "victim.html");
    const attackerPath = join(directory, "attacker.html");
    const submissionPath = join(directory, "finding.txt");
    const victimUrl = new URL(`http://127.0.0.1:${victimPort}/victim.html`);
    const attackerUrl = new URL(`http://127.0.0.1:${attackerPort}/attacker.html`);
    const victim = Buffer.from(`<!doctype html><script>
      addEventListener("message", event => {
        if (event.origin === ${JSON.stringify(attackerUrl.origin)}) (0, eval)(event.data);
      });
    </script>`);
    const attacker = Buffer.from(`<!doctype html><button>Continue</button><script>
      alert("noise");
      document.querySelector("button").addEventListener("click", () => {
        const victim = open(${JSON.stringify(victimUrl.href)});
        setTimeout(() => victim.postMessage("alert('proof')", ${JSON.stringify(victimUrl.origin)}), 250);
      });
    </script>`);
    await Promise.all([
      writeFile(victimPath, victim),
      writeFile(attackerPath, attacker),
      writeFile(submissionPath, `${attackerUrl.href}\n`),
    ]);

    const result = await verify(
      verifierConfig(victimPath, victimUrl, victim, submissionPath, {
        path: attackerPath,
        url: attackerUrl,
      }),
    );
    expect(result.passed).toBe(true);
    expect(result.evidence.dialogs.map((dialog) => dialog.message)).toEqual(["noise", "proof"]);
    expect(result.evidence.dialogs[0]?.securityOrigin).toBe(attackerUrl.origin);
    expect(result.evidence.dialogs[1]?.securityOrigin).toBe(victimUrl.origin);
  }, 10_000);

  it("attributes a dialog from a cross-site victim iframe", async () => {
    const victimPort = await freePort("127.0.0.1");
    const attackerPort = await freePort("localhost");
    const victimPath = join(directory, "victim.html");
    const attackerPath = join(directory, "attacker.html");
    const submissionPath = join(directory, "finding.txt");
    const victimUrl = new URL(`http://127.0.0.1:${victimPort}/victim.html`);
    const attackerUrl = new URL(`http://localhost:${attackerPort}/attacker.html`);
    const victim = Buffer.from("<!doctype html><script>alert('proof')</script>");
    const attacker = Buffer.from(
      `<!doctype html><iframe src=${JSON.stringify(victimUrl.href)}></iframe>`,
    );
    await Promise.all([
      writeFile(victimPath, victim),
      writeFile(attackerPath, attacker),
      writeFile(submissionPath, `${attackerUrl.href}\n`),
    ]);

    const result = await verify({
      ...verifierConfig(victimPath, victimUrl, victim, submissionPath, {
        path: attackerPath,
        url: attackerUrl,
      }),
      expectation: { dialogType: "alert", message: "proof", frameScope: "any" },
    });

    expect(result).toMatchObject({ passed: true, reasonCode: "proof_observed" });
    expect(result.evidence.matchingDialog).toMatchObject({
      url: victimUrl.href,
      frameUrl: victimUrl.href,
      securityOrigin: victimUrl.origin,
      executionOrigin: victimUrl.origin,
      topFrame: false,
    });
  }, 10_000);

  it("enforces top-frame scope for a same-origin victim iframe", async () => {
    const victimPort = await freePort();
    const victimPath = join(directory, "victim.html");
    const submissionPath = join(directory, "finding.txt");
    const victimUrl = new URL(`http://127.0.0.1:${victimPort}/victim.html`);
    const victim = Buffer.from(`<!doctype html><script>
      if (location.search === "?child") alert("proof");
      else document.write('<iframe src="?child"></iframe>');
    </script>`);
    await Promise.all([
      writeFile(victimPath, victim),
      writeFile(submissionPath, `${victimUrl.href}\n`),
    ]);

    const topFrame = await verify({
      ...verifierConfig(victimPath, victimUrl, victim, submissionPath),
      timeoutMs: 500,
    });
    expect(topFrame).toMatchObject({ passed: false, reasonCode: "dialog_mismatch" });

    const anyFrame = await verify({
      ...verifierConfig(victimPath, victimUrl, victim, submissionPath),
      expectation: { dialogType: "alert", message: "proof", frameScope: "any" },
    });
    expect(anyFrame).toMatchObject({ passed: true, reasonCode: "proof_observed" });
  }, 10_000);

  it("rejects a matching alert in the attacker document", async () => {
    const victimPort = await freePort();
    const attackerPort = await freePort();
    const victimPath = join(directory, "victim.html");
    const attackerPath = join(directory, "attacker.html");
    const submissionPath = join(directory, "finding.txt");
    const victimUrl = new URL(`http://127.0.0.1:${victimPort}/victim.html`);
    const attackerUrl = new URL(`http://127.0.0.1:${attackerPort}/attacker.html`);
    const victim = Buffer.from("<!doctype html><p>Victim</p>");
    await Promise.all([
      writeFile(victimPath, victim),
      writeFile(attackerPath, "<!doctype html><script>alert('proof')</script>"),
      writeFile(submissionPath, `${attackerUrl.href}\n`),
    ]);

    const result = await verify({
      ...verifierConfig(victimPath, victimUrl, victim, submissionPath, {
        path: attackerPath,
        url: attackerUrl,
      }),
      timeoutMs: 500,
    });
    expect(result).toMatchObject({ passed: false, reasonCode: "dialog_mismatch" });
  });
});

function verifierConfig(
  victimPath: string,
  victimUrl: URL,
  victim: Buffer,
  submissionPath: string,
  attacker = {
    path: join(victimPath, "..", "attacker.html"),
    url: new URL("http://127.0.0.1:1/attacker.html"),
  },
): VerifierConfig {
  return {
    submissionPath,
    victim: { path: victimPath, url: victimUrl, sha256: sha256(victim) },
    attacker,
    expectation: { dialogType: "alert", message: "proof", frameScope: "top" },
    browser: {
      executablePath: browserPath,
      expectedVersion: browserVersion,
      sandbox: browserSandbox,
    },
    timeoutMs: 3000,
    limits: {
      submissionBytes: 16 * 1024,
      attackerBytes: 256 * 1024,
      dialogs: 64,
      pages: 64,
      characters: 4096,
    },
  };
}

async function freePort(hostname = "127.0.0.1"): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, hostname, resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("no TCP port allocated");
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
  return address.port;
}
