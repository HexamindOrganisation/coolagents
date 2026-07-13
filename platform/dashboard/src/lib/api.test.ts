/**
 * request() error-message extraction. FastAPI returns two error shapes —
 * a string `detail` (HTTPException) and a validation array `detail: [{msg}]`
 * (422). The latter used to `String()` to "[object Object]"; these lock in
 * readable messages on `ApiError.message` for every page that reads it.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, api } from "./api";

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => vi.restoreAllMocks());

describe("request() error handling", () => {
  it("joins a FastAPI 422 validation array into a readable message", async () => {
    vi.spyOn(window, "fetch").mockResolvedValue(
      jsonResponse(
        {
          detail: [
            { loc: ["body", "ban_type"], msg: "field required", type: "x" },
            { loc: ["body", "target"], msg: "must be a string", type: "y" },
          ],
        },
        422,
      ),
    );

    const err = (await api.listBans("p1").catch((e) => e)) as ApiError;
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(422);
    expect(err.message).toBe("field required; must be a string");
    expect(err.message).not.toContain("[object Object]");
  });

  it("uses a string detail verbatim", async () => {
    vi.spyOn(window, "fetch").mockResolvedValue(
      jsonResponse({ detail: "already exists" }, 409),
    );

    const err = (await api.listBans("p1").catch((e) => e)) as ApiError;
    expect(err.message).toBe("already exists");
  });

  it("falls back to status when there's no usable detail", async () => {
    vi.spyOn(window, "fetch").mockResolvedValue(
      new Response("", { status: 500, statusText: "Internal Server Error" }),
    );

    const err = (await api.listBans("p1").catch((e) => e)) as ApiError;
    expect(err.message).toContain("500");
    expect(err.message).not.toContain("[object Object]");
  });
});
