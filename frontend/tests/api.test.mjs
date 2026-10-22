import test from "node:test";
import assert from "node:assert/strict";
import { createApiClient, validateUrl, validateAssessment } from "../api.js";

const result = {
  url: "https://example.com",
  prediction: "legitimate",
  malicious_probability: 0.268,
  risk_level: "moderate",
  observed_characteristics: [],
};
const json = (data, status = 200) => new Response(JSON.stringify(data), { status });

test("uses only the configured NurtureShield analysis endpoint", async () => {
  const calls = [];
  const analyze = createApiClient({
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return json(result);
    },
  });
  const target = "https://secure-account-verify.example.com/login";
  assert.deepEqual(await analyze(target), result);
  assert.deepEqual(calls.map((call) => call.url), [
    "https://nurtureshield-backend.onrender.com/api/v1/nurtureshield/analyze",
  ]);
  assert.equal(calls[0].options.redirect, "error");
  assert.deepEqual(JSON.parse(calls[0].options.body), { url: target });
});

for (const value of [
  "",
  " ",
  null,
  42,
  "https://",
  "javascript:alert(1)",
  "file:///private/data",
  "http://a b.com",
  "x".repeat(8193),
  "https://example.com\\x",
]) {
  test(`invalid URL rejected without network: ${String(value).slice(0, 35)}`, async () => {
    let calls = 0;
    const analyze = createApiClient({
      fetchImpl: () => {
        calls++;
        throw Error();
      },
    });
    await assert.rejects(analyze(value), (error) => error.code === "validation");
    assert.equal(calls, 0);
  });
}

test("scheme-less, Unicode and IPv6 URLs are accepted without changing text", () => {
  for (const url of ["example.com", "https://bücher.example/سلام", "http://[::1]:8000/a"]) {
    assert.equal(validateUrl(url), url);
  }
});

for (const [status, code] of [
  [403, "forbidden"],
  [422, "validation"],
  [429, "rate"],
  [500, "service"],
  [503, "service"],
]) {
  test(`API status ${status} maps to a safe error`, async () => {
    const analyze = createApiClient({
      fetchImpl: async () => json({ detail: "/secret/private/stack" }, status),
    });
    await assert.rejects(
      analyze("example.com"),
      (error) => error.code === code && !error.message.includes("/secret")
    );
  });
}

test("backend offline, invalid JSON, invalid contract and timeout", async () => {
  await assert.rejects(
    createApiClient({ fetchImpl: async () => { throw Error("private"); } })("example.com"),
    (error) => error.code === "network"
  );
  await assert.rejects(
    createApiClient({ fetchImpl: async () => new Response("broken") })("example.com"),
    (error) => error.code === "response"
  );
  assert.throws(() => validateAssessment({ ...result, malicious_probability: NaN }));
  assert.throws(() => validateAssessment({ ...result, observed_characteristics: [{}] }));
  await assert.rejects(
    createApiClient({
      timeoutMs: 5,
      fetchImpl: (_url, { signal }) =>
        new Promise((_, reject) => signal.addEventListener("abort", () => reject(Error("aborted")))),
    })("example.com"),
    (error) => error.code === "timeout"
  );
});

test("untrusted backend origins are rejected", () => {
  for (const origin of ["http://attacker.example", "https://trusted.example/path", "not-a-url"]) {
    assert.throws(() => createApiClient({ origin }));
  }
});
