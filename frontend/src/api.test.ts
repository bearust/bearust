import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "@/api";

describe("control-plane API helpers", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("uploads certificate material as multipart form data", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      id: 7,
      name: "Internal CA",
      source: "custom",
      covered_hostnames: ["internal.example.com"],
      expiry: "2027-01-01T00:00:00Z",
    }), { status: 201, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);

    const certificate = new File(["certificate"], "certificate.pem", { type: "application/x-pem-file" });
    const key = new File(["private-key"], "private.key", { type: "application/x-pem-file" });
    const result = await api.uploadCertificate({ name: "Internal CA", certificate, key });

    expect(result.id).toBe(7);
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/certificates");
    expect(init.method).toBe("POST");
    expect(init.credentials).toBe("include");
    expect(init.headers).toBeUndefined();
    expect(init.body).toBeInstanceOf(FormData);
    expect((init.body as FormData).get("name")).toBe("Internal CA");
    expect((init.body as FormData).get("certificate")).toBe(certificate);
    expect((init.body as FormData).get("key")).toBe(key);
  });
});
