"use strict";

// Package-safe PH-X8 projection. It contains reviewed contract digests and
// non-sensitive gate states/counts only: never live evidence refs, waivers,
// session nuclei, local paths, device identifiers, or credentials.

const crypto = require("node:crypto");
const {
  PLANE_PHYSICAL_GRAPH_ID,
  PLANE_PHYSICAL_PRODUCTION_NONWAIVABLE_HIL_NODE_IDS,
  PLANE_PHYSICAL_REVIEWED_HYPEREDGE_REGISTRY_SHA256,
  PLANE_PHYSICAL_REVIEWED_NODE_CONTRACT_REGISTRY_SHA256,
  planePhysicalHyperedgeRegistryDigest,
  planePhysicalNodeContractDigest,
  planePhysicalNodeContractRegistryDigest,
} = require("./plane-physical-release-contracts.js");

const SNAPSHOT_VERSION = 1;
const GRAPH_VERSION = "v0.3-proposed (2026-07-17)";
const REVIEWED_SNAPSHOT_SHA256 =
  "7e01ae284ac7afcb5364f358f3f0d3e8b143895f76eca761b6c066a56c2b03de";

const NODE_CONTRACT_DIGESTS = Object.freeze({
  "PH-C1": "b92c8485e1c3502cdc1778a5212fac743338cba1af1f847ad177a55c5ae9c68e",
  "PH-C10": "a885c9ddea1f995194abc6fdc4fe8c88a78bc00f0dac9192b6b96fb85859f9b3",
  "PH-C2": "ceec2a0d0956f9fa35e0afcd7de04bd96f0941e567e9358e22f91ca86ac58d6f",
  "PH-C3": "c12d05131418d59eb0598ffc58369a211dc8c4754c3edd4d0015d41753ffbce9",
  "PH-C4": "abdd4b8df786eaec23a82f8945c623b617c71bc1dd7e8d3a4fb291f8a7c7a6cd",
  "PH-C5": "41913ef121dafca9d6328651f1b990dedccdfdf459478900ae0d7f8f55869390",
  "PH-C6": "000b0f4eb7105054710d2a1a5dfd4a6764b09bfb0c6ce5895fb00b6a19fbe4a8",
  "PH-C7": "8f539a898aa2852240d8fffb9fbba163187a2472dba8afe56f6d0196009baf4c",
  "PH-C8": "4f74b68817a8946f04a48efc1edcb4cb8bdbaa09553083fab78200983bcecc27",
  "PH-C9": "a91293035f4557f3985db8f15e42c4512e9f2487033c1e0df2608132ea68a73b",
  "PH-I1": "aaa3eb544397eed1df41909b288b1f656febbe437ccca8f9893e75eb7605de50",
  "PH-I2": "da78e2a3eb2477aa3e08c90a241e512504511fdecb23ce23ee3c0f5ab4d16c41",
  "PH-I3": "e990cd8bd9805b38dad8923cca9023fa0d84d7375459cea2ac92e28cf058f3f4",
  "PH-I4": "1641f1d46481a958104103cad35a41d2fb18be4aa91f8941ecf5847523e3628e",
  "PH-I5": "9b731000ecd95a7f0ee4056aff64cb10c7ad36ea9631b641af1fe6c31e50e4e2",
  "PH-IP1": "a0ce90a11cfd4e5ae2cc0e10155579fe20ee1794f0c9b8477912fd458c0d0e45",
  "PH-IP2": "856e32dd68e3e8a0482324f7774856897fc38c124a26889f86532bfbd23acd13",
  "PH-IP3": "a7c75a1b652742e27d92b0fba5e155f179be500eb74c29db240e9481fc578740",
  "PH-P0": "04f05ccd57dcc0950abad43b1a51aafbfa15b45e8f88caa6c390d7cbea30c3b3",
  "PH-P1": "95cda2c7172987cacd872fa07d98f95ac90580c0fc84052347befccd8f9fb163",
  "PH-P2": "104a54f159a3b003130d2587ebb22dcb704d2dbcb2dfbfad0de1184f921a7a27",
  "PH-P3": "27f4564d1ed006e35af0e782ad721a9a5ba819ea91758ffadcce263257e21596",
  "PH-P4": "539bf8a3de986f4ec5408b7c6c169774753287a22448197ff7004ff28b9dc845",
  "PH-P5": "d6a8faa92d38f8bff485aec87ec76c5d906a0ba55fa2181b19506269eff52f63",
  "PH-P6": "f8d3d9c4201c20b49991d1b89811d13a8866433be22aa5614650af2dc16368ef",
  "PH-P7": "6f5554544465c87d46708f48d2e49e1589a86339ba73cb214c51650861eb3098",
  "PH-P8": "9adff98d7513ee9eeabe20a21d68d5a021de69e6e1f14934e678f2a180b5eb7a",
  "PH-P9": "3fa26c4c36407e728053dc525d91a2b8f5aaa3144994157f0f3d11ee9bc97fde",
  "PH-S1": "2c5025b770a8205808ed2534eb15f2490948bd8a6b9225237f1ad675d0abb0c0",
  "PH-S10": "51fa7099752530a7bf71dcf41b57b291892f01e262230af2e4454357e272cf83",
  "PH-S11": "0ca4688db97a1733ab7046201cc8b3fe6260ef05b315e50a1184c1eef9976a3f",
  "PH-S12": "f0318618f800420deaffa763af7c78edf26d13f29d4d126dc66468f11c76feb6",
  "PH-S2": "3cd2e338dc45e178fba915afd0cc6f7b1b054a50716ddb552ae54c938c83feda",
  "PH-S3": "24737ed501e73cd942880ea902d00f8ffcf2fe4fc56f8ce674140d96ccaa0283",
  "PH-S4": "b40fae47c101eb9f1f970822ed44f68dff397c850385460e62f5441f37eed7b3",
  "PH-S5": "9069d3c4614a2958397be76f91febd3e768434365706495057fc2e1eea6a004b",
  "PH-S6": "aa664fcb2395f07475a01dc713fb81a4fef67512c4cad1fa47d3f4e1f3e9a6c4",
  "PH-S7": "7202bdaf4c0ad41f3baf3b6ba9bf5141817c1d34020dbb154392c8d771ad2dc1",
  "PH-S8": "75eb37f5950588801dc4cc79d3ace21c835faf77626d4ad905b1e2ce6e8eb38c",
  "PH-S9": "ec9ad45c939ce3a386ae714f13dc245c54c8d99303228e2a53d8eed4e7495aa8",
  "PH-X1": "8820662e049c2fe4f848e8432e055a1330e826130776ebf39ddbd58fb4021c08",
  "PH-X2": "6c5279bb8c01b2882463ef82953f7a25e9a677aa752aee03008497b07bec163d",
  "PH-X3": "94b49788d6b8f203de6434ee656a51270e0d20a08a8832d233306f905876c378",
  "PH-X4": "d94e35865e54ab830699648c2a16e5c61b79cd31d437e04253db1aecc51e9033",
  "PH-X5": "89cee57703f86a85186a2d7347467b7034815b48efa745cd6a296366f1ab614d",
  "PH-X6": "8f10db14aac4f33c6b8b96644c2c5ae3c8eb63183aa5d5f83c11e653b6345979",
  "PH-X7": "55cbbb731766ddadcd4b2589e680647fa90dbe12553e697f12ba014c5815aa33",
  "PH-X8": "5375873bd49bd1f8fea1bb01ed463596e08075600053cd75cd9c507d75e110ef",
});

const PREDECESSORS = Object.freeze({
  "PH-C1": Object.freeze(["PH-I2", "PH-I3", "PH-IP3", "PH-P4", "PH-S9", "PH-X6", "PH-X7"]),
  "PH-C10": Object.freeze(["PH-C1", "PH-C2", "PH-C3", "PH-C4", "PH-C5", "PH-C6", "PH-C7", "PH-C8", "PH-C9", "PH-I3", "PH-I4", "PH-I5", "PH-P6", "PH-P7", "PH-P9", "PH-S10", "PH-S12", "PH-X2", "PH-X5"]),
  "PH-C2": Object.freeze(["PH-C1", "PH-IP3", "PH-P5", "PH-S5"]),
  "PH-C3": Object.freeze(["PH-C2", "PH-I3", "PH-P4"]),
  "PH-C4": Object.freeze(["PH-C2", "PH-P4", "PH-P5", "PH-S6"]),
  "PH-C5": Object.freeze(["PH-C2", "PH-P4", "PH-P5", "PH-S6"]),
  "PH-C6": Object.freeze(["PH-C1", "PH-P4", "PH-P9", "PH-S6"]),
  "PH-C7": Object.freeze(["PH-C1", "PH-IP3", "PH-P4", "PH-S5"]),
  "PH-C8": Object.freeze(["PH-I4", "PH-IP2", "PH-P0", "PH-S10", "PH-S6"]),
  "PH-C9": Object.freeze(["PH-C8", "PH-I5", "PH-S10", "PH-S9"]),
  "PH-I1": Object.freeze(["PH-IP3", "PH-P0", "PH-S4"]),
  "PH-I2": Object.freeze(["PH-IP1", "PH-S8"]),
  "PH-I3": Object.freeze(["PH-I1", "PH-I2", "PH-S12", "PH-S9"]),
  "PH-I4": Object.freeze(["PH-IP2", "PH-IP3", "PH-S6"]),
  "PH-I5": Object.freeze(["PH-C8", "PH-I2", "PH-I4", "PH-S8"]),
  "PH-IP1": Object.freeze(["PH-S2", "PH-S8"]),
  "PH-IP2": Object.freeze(["PH-S5", "PH-S6"]),
  "PH-IP3": Object.freeze(["PH-S10", "PH-S3", "PH-S5"]),
  "PH-P0": Object.freeze(["PH-S4"]),
  "PH-P1": Object.freeze(["PH-S4"]),
  "PH-P2": Object.freeze(["PH-P1", "PH-S4"]),
  "PH-P3": Object.freeze(["PH-P2", "PH-S3", "PH-S7"]),
  "PH-P4": Object.freeze(["PH-P8"]),
  "PH-P5": Object.freeze(["PH-P3", "PH-P4", "PH-P7", "PH-S5", "PH-S7"]),
  "PH-P6": Object.freeze(["PH-P2", "PH-P4", "PH-P7", "PH-S3", "PH-S7"]),
  "PH-P7": Object.freeze(["PH-IP3", "PH-P3", "PH-P8", "PH-X2"]),
  "PH-P8": Object.freeze(["PH-P1", "PH-S1", "PH-S4"]),
  "PH-P9": Object.freeze(["PH-C8", "PH-P4", "PH-P5", "PH-P7", "PH-S11", "PH-S3", "PH-S6", "PH-X6", "PH-X7"]),
  "PH-S10": Object.freeze(["PH-S5"]),
  "PH-S11": Object.freeze(["PH-I3", "PH-S3", "PH-S4", "PH-S7", "PH-S9"]),
  "PH-S12": Object.freeze(["PH-S10", "PH-S6", "PH-S8"]),
  "PH-S3": Object.freeze(["PH-P0", "PH-S1", "PH-S2", "PH-S4", "PH-S7"]),
  "PH-S6": Object.freeze(["PH-S10", "PH-S5"]),
  "PH-S7": Object.freeze(["PH-P0", "PH-S4"]),
  "PH-S9": Object.freeze(["PH-S1", "PH-S2", "PH-S6", "PH-S8"]),
  "PH-X1": Object.freeze(["PH-I3", "PH-S9"]),
  "PH-X2": Object.freeze(["PH-IP3", "PH-S1", "PH-S5"]),
  "PH-X3": Object.freeze(["PH-P3", "PH-P4", "PH-X1", "PH-X2"]),
  "PH-X4": Object.freeze(["PH-C10", "PH-C8", "PH-C9", "PH-I5", "PH-P0", "PH-S11", "PH-S4", "PH-S9", "PH-X3"]),
  "PH-X5": Object.freeze(["PH-C1", "PH-C2", "PH-C3", "PH-C4", "PH-C5", "PH-C6", "PH-C7", "PH-C8", "PH-P6", "PH-P7", "PH-P9", "PH-X6", "PH-X7"]),
  "PH-X6": Object.freeze(["PH-C8", "PH-IP1", "PH-P5", "PH-S11", "PH-X1", "PH-X2"]),
  "PH-X7": Object.freeze(["PH-C8", "PH-P5", "PH-P7", "PH-S11", "PH-S3", "PH-S4", "PH-S7", "PH-X6"]),
  "PH-X8": Object.freeze(["PH-C10", "PH-S12", "PH-X3", "PH-X4", "PH-X5", "PH-X7"]),
});

const NODE_STATUS_BY_ID = new Map([
  ["PH-S1", "in_review"],
  ["PH-S2", "in_review"],
  ["PH-S4", "in_review"],
  ["PH-S5", "in_review"],
  ["PH-S8", "in_review"],
]);
const ENGINEERING_FAILED_NODE_IDS = new Set([
  "PH-IP3",
  "PH-S3",
  "PH-S7",
  "PH-X3",
  "PH-X6",
  "PH-X7",
  "PH-X8",
]);
const NONWAIVABLE_NODE_IDS = new Set(PLANE_PHYSICAL_PRODUCTION_NONWAIVABLE_HIL_NODE_IDS);

function digestJson(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function snapshotBasis() {
  return {
    schema_version: SNAPSHOT_VERSION,
    graph_id: PLANE_PHYSICAL_GRAPH_ID,
    graph_version: GRAPH_VERSION,
    node_contract_registry_sha256: PLANE_PHYSICAL_REVIEWED_NODE_CONTRACT_REGISTRY_SHA256,
    hyperedge_registry_sha256: PLANE_PHYSICAL_REVIEWED_HYPEREDGE_REGISTRY_SHA256,
    nodes: Object.keys(NODE_CONTRACT_DIGESTS).sort().map((nodeId) => ({
      node_id: nodeId,
      node_contract_sha256: NODE_CONTRACT_DIGESTS[nodeId],
      predecessors: PREDECESSORS[nodeId] || [],
      status: NODE_STATUS_BY_ID.get(nodeId) || "blocked",
      engineering_state: ENGINEERING_FAILED_NODE_IDS.has(nodeId) ? "failed" : "pending",
      engineering_evidence_count: 0,
      hil_state: NONWAIVABLE_NODE_IDS.has(nodeId) ? "pending" : "not_required",
      hil_evidence_count: 0,
      hil_waiver_present: false,
      review_evidence_count: 0,
    })),
  };
}

const basis = snapshotBasis();
const PACKAGED_RELEASE_SNAPSHOT = deepFreeze({
  ...basis,
  snapshot_sha256: digestJson(basis),
});

function compilePlanePhysicalReleaseSnapshot(nodesDocument, hyperedgesDocument) {
  const nodes = [...nodesDocument.nodes].sort((left, right) => left.id.localeCompare(right.id));
  const compiled = {
    schema_version: SNAPSHOT_VERSION,
    graph_id: nodesDocument.graph_id,
    graph_version: nodesDocument.version,
    node_contract_registry_sha256: planePhysicalNodeContractRegistryDigest(nodesDocument),
    hyperedge_registry_sha256: planePhysicalHyperedgeRegistryDigest(hyperedgesDocument),
    nodes: nodes.map((node) => {
      const gate = nodesDocument.gate_tracking[node.id];
      return {
        node_id: node.id,
        node_contract_sha256: planePhysicalNodeContractDigest(node),
        predecessors: [...node.predecessors].sort(),
        status: node.status,
        engineering_state: gate.engineering_state,
        engineering_evidence_count: gate.engineering_evidence_refs.length,
        hil_state: gate.hil_state,
        hil_evidence_count: gate.hil_evidence_refs.length,
        hil_waiver_present: gate.hil_waiver_ref !== null,
        review_evidence_count: node.review_evidence.length,
      };
    }),
  };
  return deepFreeze({ ...compiled, snapshot_sha256: digestJson(compiled) });
}

function assertPackagedPlanePhysicalReleaseSnapshot(input = PACKAGED_RELEASE_SNAPSHOT) {
  if (!input || input.schema_version !== SNAPSHOT_VERSION
      || input.graph_id !== PLANE_PHYSICAL_GRAPH_ID
      || input.node_contract_registry_sha256 !== PLANE_PHYSICAL_REVIEWED_NODE_CONTRACT_REGISTRY_SHA256
      || input.hyperedge_registry_sha256 !== PLANE_PHYSICAL_REVIEWED_HYPEREDGE_REGISTRY_SHA256
      || digestJson({
        schema_version: input.schema_version,
        graph_id: input.graph_id,
        graph_version: input.graph_version,
        node_contract_registry_sha256: input.node_contract_registry_sha256,
        hyperedge_registry_sha256: input.hyperedge_registry_sha256,
        nodes: input.nodes,
      }) !== input.snapshot_sha256
      || input.snapshot_sha256 !== REVIEWED_SNAPSHOT_SHA256) {
    throw new Error("packaged Plane-PH release snapshot is not the reviewed PH-X8 projection");
  }
  return input;
}

module.exports = {
  PLANE_PHYSICAL_PACKAGED_RELEASE_SNAPSHOT: PACKAGED_RELEASE_SNAPSHOT,
  PLANE_PHYSICAL_REVIEWED_RELEASE_SNAPSHOT_SHA256: REVIEWED_SNAPSHOT_SHA256,
  assertPackagedPlanePhysicalReleaseSnapshot,
  compilePlanePhysicalReleaseSnapshot,
};
