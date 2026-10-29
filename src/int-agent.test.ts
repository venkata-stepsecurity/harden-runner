import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as crypto from "crypto";
import { findLayer, isValidTag, verifyDigest, OciManifest } from "./int-agent";

const DIGEST_A = "sha256:" + "a".repeat(64);
const DIGEST_B = "sha256:" + "b".repeat(64);

const manifest: OciManifest = {
  layers: [
    {
      mediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
      digest: DIGEST_A,
      size: 1,
      annotations: { "org.opencontainers.image.title": "agent_linux_amd64.tar.gz" },
    },
    {
      mediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
      digest: DIGEST_B,
      size: 1,
      annotations: { "org.opencontainers.image.title": "agent_linux_arm64.tar.gz" },
    },
  ],
};

describe("isValidTag", () => {
  it.each(["latest", "pr-506", "dev-venkat-int-release-ghcr", "a".repeat(40), "v1.2_3"])(
    "accepts %s",
    (tag) => expect(isValidTag(tag)).toBe(true)
  );

  it.each(["", "-x", ".x", "a/b", "a:b", "../x", "a".repeat(129)])(
    "rejects %s",
    (tag) => expect(isValidTag(tag)).toBe(false)
  );
});

describe("findLayer", () => {
  it("returns the layer for each variant", () => {
    expect(findLayer(manifest, "agent_linux_amd64.tar.gz").digest).toBe(DIGEST_A);
    expect(findLayer(manifest, "agent_linux_arm64.tar.gz").digest).toBe(DIGEST_B);
  });

  it("throws when the file is missing", () => {
    expect(() => findLayer(manifest, "agent_linux_riscv64.tar.gz")).toThrow("not found");
    expect(() => findLayer({ layers: [] } as OciManifest, "x")).toThrow("not found");
  });

  it("throws on a non-sha256 digest", () => {
    const m: OciManifest = {
      layers: [{ ...manifest.layers[0], digest: "sha512:" + "a".repeat(128) }],
    };
    expect(() => findLayer(m, "agent_linux_amd64.tar.gz")).toThrow("unsupported digest");
  });
});

describe("verifyDigest", () => {
  const file = path.join(os.tmpdir(), `int-agent-test-${process.pid}`);
  beforeAll(() => fs.writeFileSync(file, "agent"));
  afterAll(() => fs.unlinkSync(file));

  it("matches the file's sha256", () => {
    const digest = "sha256:" + crypto.createHash("sha256").update("agent").digest("hex");
    expect(verifyDigest(file, digest)).toBe(true);
  });

  it("rejects a different digest", () => {
    expect(verifyDigest(file, DIGEST_A)).toBe(false);
  });
});
