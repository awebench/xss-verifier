import { createServer, type Server } from "node:http";

import { errorMessage, TechnicalError } from "./errors.js";

export interface RunningServer {
  close(): Promise<void>;
}

export async function serveResource(url: URL, bytes: Buffer): Promise<RunningServer> {
  if (url.protocol !== "http:") {
    throw new TechnicalError(`cannot serve unsupported protocol ${url.protocol}`);
  }

  const expectedHost = url.host;
  const server = createServer((request, response) => {
    let requestUrl: URL;
    try {
      requestUrl = new URL(request.url ?? "/", `http://${request.headers.host ?? "invalid"}`);
    } catch {
      response.writeHead(400).end();
      return;
    }

    if (
      request.headers.host !== expectedHost ||
      requestUrl.pathname !== url.pathname ||
      (request.method !== "GET" && request.method !== "HEAD")
    ) {
      response.writeHead(404, {
        "Cache-Control": "no-store",
        "Content-Type": "text/plain; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
      });
      response.end("Not found");
      return;
    }

    response.writeHead(200, {
      "Cache-Control": "no-store",
      "Content-Length": String(bytes.length),
      "Content-Type": "text/html; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
    });
    response.end(request.method === "HEAD" ? undefined : bytes);
  });

  await listen(server, url);
  return {
    close: () => close(server),
  };
}

function listen(server: Server, url: URL): Promise<void> {
  const hostname =
    url.hostname.startsWith("[") && url.hostname.endsWith("]")
      ? url.hostname.slice(1, -1)
      : url.hostname;
  return new Promise((resolve, reject) => {
    const onError = (error: Error): void => {
      server.off("listening", onListening);
      reject(
        new TechnicalError(`cannot bind ${url.origin}: ${errorMessage(error)}`, { cause: error }),
      );
    };
    const onListening = (): void => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(Number(url.port), hostname);
  });
}

function close(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
    server.closeAllConnections();
  });
}
