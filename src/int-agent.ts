import * as core from "@actions/core";
import * as tc from "@actions/tool-cache";
import * as crypto from "crypto";
import * as fs from "fs";
import { HttpClient } from "@actions/http-client";

// Int builds of step-security/agent, published by its INT Release workflow as
// an OCI artifact with one layer per tarball.
export const INT_AGENT_REGISTRY = "https://ghcr.io";
export const INT_AGENT_REPOSITORY = "step-security/agent/agent-int";

const OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json";

export interface OciDescriptor {
  mediaType: string;
  digest: string;
  size: number;
  annotations?: { [key: string]: string };
}

export interface OciManifest {
  layers: OciDescriptor[];
  annotations?: { [key: string]: string };
}

// isValidTag reports whether tag is a valid OCI tag.
export function isValidTag(tag: string): boolean {
  return /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(tag);
}

// findLayer returns the layer whose title annotation is fileName.
export function findLayer(
  manifest: OciManifest,
  fileName: string
): OciDescriptor {
  const layer = (manifest.layers || []).find(
    (l) => l.annotations?.["org.opencontainers.image.title"] === fileName
  );
  if (!layer) {
    throw new Error(`${fileName} not found in int agent artifact`);
  }
  if (!/^sha256:[a-f0-9]{64}$/.test(layer.digest)) {
    throw new Error(`unsupported digest for ${fileName}: ${layer.digest}`);
  }
  return layer;
}

// verifyDigest returns true if the sha256 of the file matches the OCI digest.
export function verifyDigest(filePath: string, digest: string): boolean {
  const actual =
    "sha256:" +
    crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
  return actual === digest;
}

// downloadIntAgent downloads agent_linux_<variant>.tar.gz from the int agent
// artifact with the given tag, verifies it against its digest and returns the
// local path.
export async function downloadIntAgent(
  variant: string,
  tag: string
): Promise<string> {
  if (!isValidTag(tag)) {
    throw new Error(`invalid int agent tag: ${tag}`);
  }

  const http = new HttpClient("harden-runner");
  const tokenRes = await http.getJson<{ token: string }>(
    `${INT_AGENT_REGISTRY}/token?scope=repository:${INT_AGENT_REPOSITORY}:pull`
  );
  const token = tokenRes.result?.token;
  if (!token) {
    throw new Error(`could not get GHCR token (HTTP ${tokenRes.statusCode})`);
  }

  const manifestRes = await http.getJson<OciManifest>(
    `${INT_AGENT_REGISTRY}/v2/${INT_AGENT_REPOSITORY}/manifests/${tag}`,
    { Authorization: `Bearer ${token}`, Accept: OCI_MANIFEST }
  );
  if (!manifestRes.result) {
    throw new Error(
      `int agent ${INT_AGENT_REPOSITORY}:${tag} not found (HTTP ${manifestRes.statusCode})`
    );
  }

  const fileName = `agent_linux_${variant}.tar.gz`;
  const layer = findLayer(manifestRes.result, fileName);
  const revision =
    manifestRes.result.annotations?.["org.opencontainers.image.revision"] ||
    "unknown";
  core.info(
    `Installing int agent ghcr.io/${INT_AGENT_REPOSITORY}:${tag} (commit ${revision}, ${fileName})`
  );

  // GHCR redirects blob downloads to another host; the client drops the
  // Authorization header on that redirect.
  const downloadPath = await tc.downloadTool(
    `${INT_AGENT_REGISTRY}/v2/${INT_AGENT_REPOSITORY}/blobs/${layer.digest}`,
    undefined,
    `Bearer ${token}`
  );

  if (!verifyDigest(downloadPath, layer.digest)) {
    throw new Error(`digest mismatch for ${fileName}, expected ${layer.digest}`);
  }
  core.info(`✅ Digest verified: ${layer.digest}`);
  return downloadPath;
}
