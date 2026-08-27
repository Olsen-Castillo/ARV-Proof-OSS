'use strict';

const state = {
  manifest: null,
  artifactDigest: null
};

const manifestFile = document.getElementById("manifestFile");
const artifactFile = document.getElementById("artifactFile");
const manifestStatus = document.getElementById("manifestStatus");
const artifactStatus = document.getElementById("artifactStatus");
const comparisonTitle = document.getElementById("comparisonTitle");
const comparisonBadge = document.getElementById("comparisonBadge");
const expectedDigest = document.getElementById("expectedDigest");
const actualDigest = document.getElementById("actualDigest");

function setText(id, value) {
  const element = document.getElementById(id);
  element.textContent = value ?? "-";
}

function normalizeDigest(value) {
  if (typeof value !== "string") return null;
  const normalized = value.toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(normalized)) return null;
  return normalized;
}

function manifestArtifactDigest(manifest) {
  if (!manifest || manifest.artifact_digest === null) return null;
  return normalizeDigest(manifest.artifact_digest.value);
}

function validPortableManifest(manifest) {
  if (!manifest || typeof manifest !== "object") return false;
  if (manifest.schema !== "arv.portable-proof-manifest") return false;
  if (manifest.schema_version !== 1) return false;
  if (!manifest.envelope_digest || typeof manifest.envelope_digest !== "object") return false;
  if (manifest.envelope_digest.algorithm !== "SHA-256") return false;
  if (manifest.envelope_digest.canonicalization !== "ARV-JSON-v1") return false;
  if (!normalizeDigest(manifest.envelope_digest.value)) return false;
  return true;
}

function renderManifest() {
  const manifest = state.manifest;

  if (!manifest) {
    setText("validationId", "-");
    setText("profileId", "-");
    setText("recordedAt", "-");
    setText("fingerprint", "-");
    setText("envelopeDigest", "-");
    setText("verificationUri", "-");
    expectedDigest.textContent = "-";
    return;
  }

  setText("validationId", manifest.validation_id);
  setText("profileId", manifest.profile_id);
  setText("recordedAt", manifest.recorded_at);
  setText("fingerprint", manifest.signer?.public_key_fingerprint);
  setText("envelopeDigest", manifest.envelope_digest?.value);
  setText("verificationUri", manifest.verification_uri);

  const expected = manifestArtifactDigest(manifest);
  expectedDigest.textContent = expected ?? "NOT DISCLOSED";
}

function renderComparison() {
  const expected = manifestArtifactDigest(state.manifest);
  const actual = state.artifactDigest;

  actualDigest.textContent = actual ?? "-";

  comparisonBadge.className = "badge neutral";
  comparisonBadge.textContent = "NOT CHECKED";
  comparisonTitle.textContent = "Waiting for input";

  if (state.manifest && expected === null) {
    comparisonBadge.className = "badge indeterminate";
    comparisonBadge.textContent = "UNDISCLOSED";
    comparisonTitle.textContent = "Artifact digest is not disclosed by this manifest";
    return;
  }

  if (!state.manifest || !actual || !expected) return;

  if (actual === expected) {
    comparisonBadge.className = "badge match";
    comparisonBadge.textContent = "MATCH";
    comparisonTitle.textContent = "Selected artifact bytes match the disclosed SHA-256 digest";
    return;
  }

  comparisonBadge.className = "badge mismatch";
  comparisonBadge.textContent = "MISMATCH";
  comparisonTitle.textContent = "Selected artifact bytes do not match the disclosed SHA-256 digest";
}

async function sha256File(file) {
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    throw new Error("WEB_CRYPTO_UNAVAILABLE");
  }

  const bytes = await file.arrayBuffer();
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  const octets = Array.from(new Uint8Array(digest));
  return octets.map((value) => value.toString(16).padStart(2, "0")).join("");
}

manifestFile.addEventListener("change", async () => {
  state.manifest = null;
  manifestStatus.textContent = "No manifest loaded.";

  const file = manifestFile.files?.[0];
  if (!file) {
    renderManifest();
    renderComparison();
    return;
  }

  try {
    const text = await file.text();
    const manifest = JSON.parse(text);

    if (!validPortableManifest(manifest)) {
      throw new Error("INVALID_PORTABLE_MANIFEST");
    }

    state.manifest = manifest;
    manifestStatus.textContent = "Portable Proof Manifest V1 loaded locally: " + file.name;
  } catch (error) {
    manifestStatus.textContent = "Manifest rejected: " + String(error.message || error);
  }

  renderManifest();
  renderComparison();
});

artifactFile.addEventListener("change", async () => {
  state.artifactDigest = null;
  artifactStatus.textContent = "No artifact loaded.";

  const file = artifactFile.files?.[0];
  if (!file) {
    renderComparison();
    return;
  }

  try {
    artifactStatus.textContent = "Calculating SHA-256 locally...";
    state.artifactDigest = await sha256File(file);
    artifactStatus.textContent = "SHA-256 calculated locally: " + file.name;
  } catch (error) {
    artifactStatus.textContent = "Artifact hashing failed: " + String(error.message || error);
  }

  renderComparison();
});

renderManifest();
renderComparison();
