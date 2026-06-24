#!/usr/bin/env node

const {execFileSync} = require("node:child_process");
const {existsSync, mkdirSync, readFileSync, writeFileSync} = require("node:fs");
const {createHash} = require("node:crypto");
const {join} = require("node:path");

const rpcUrl = process.env.RPC_URL || "http://127.0.0.1:8545";
const privateKey =
  process.env.DEPLOYER_PRIVATE_KEY ||
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const manifest = "gasUsed/shrincs-gas-vector/Cargo.toml";
const cacheDir = "gasUsed/.shrincs-tree-cache";
const vectorCacheDir = "gasUsed/.vector-cache/128s-q20-shrincs-measurements-v3";
const gasLimit = process.env.GAS_LIMIT || "30000000";

function run(command, args, options = {}) {
  return execFileSync(command, args, {
    encoding: "utf8",
    stdio: options.stdio || ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      SHRINCS_TREE_CACHE_DIR: cacheDir,
    },
  }).trim();
}

function runJson(command, args) {
  const output = run(command, args);
  const firstBrace = output.indexOf("{");
  if (firstBrace === -1) {
    throw new Error(`expected JSON from ${command}: ${output}`);
  }
  return JSON.parse(output.slice(firstBrace));
}

function vector(mode, arg) {
  mkdirSync(vectorCacheDir, {recursive: true});
  const key = createHash("sha256").update(JSON.stringify({mode, arg: arg || ""})).digest("hex");
  const cachePath = join(vectorCacheDir, `${mode}-${key}.txt`);
  if (existsSync(cachePath)) return readFileSync(cachePath, "utf8").trim();
  const args = ["run", "--release", "--offline", "--quiet", "--manifest-path", manifest, "--", mode];
  if (arg) args.push(arg);
  const output = run("cargo", args);
  writeFileSync(cachePath, `${output}\n`);
  return output;
}

function forgeCreate(contract, constructorArgs = []) {
  const deployer = run("cast", ["wallet", "address", "--private-key", privateKey]);
  const nonce = run("cast", ["nonce", "--rpc-url", rpcUrl, deployer]);
  const computed = run("cast", ["compute-address", "--nonce", nonce, deployer]);
  const address = computed.match(/0x[0-9a-fA-F]{40}/)?.[0];
  if (!address) throw new Error(`could not compute deployment address from: ${computed}`);
  const args = ["create", "--rpc-url", rpcUrl, "--private-key", privateKey, "--broadcast", "--json", contract];
  if (constructorArgs.length) {
    args.push("--constructor-args", ...constructorArgs);
  }
  runJson("forge", args);
  return address;
}

function castCall(address, calldata) {
  return run("cast", ["call", "--rpc-url", rpcUrl, address, calldata]);
}

function assertCallTrue(address, calldata, label) {
  const result = castCall(address, calldata).toLowerCase();
  if (!result.endsWith("1".padStart(64, "0"))) {
    throw new Error(`${label} eth_call did not return true: ${result}`);
  }
}

function castSend(address, calldata) {
  const sent = runJson("cast", [
    "send",
    "--rpc-url",
    rpcUrl,
    "--private-key",
    privateKey,
    "--gas-limit",
    gasLimit,
    "--json",
    address,
    calldata,
  ]);
  const gasUsed = receiptGasUsed(sent);
  if (gasUsed !== undefined) return gasUsed;
  const hash = sent.transactionHash || sent.hash;
  if (!hash) throw new Error(`could not find tx hash in ${JSON.stringify(sent)}`);
  const receipt = runJson("cast", ["receipt", "--rpc-url", rpcUrl, "--json", hash]);
  const receiptGas = receiptGasUsed(receipt);
  if (receiptGas === undefined) throw new Error(`could not find gasUsed in ${JSON.stringify(receipt)}`);
  return receiptGas;
}

function receiptGasUsed(receipt) {
  const value = receipt.gasUsed || receipt.receipt?.gasUsed;
  if (value === undefined) return undefined;
  return typeof value === "string" && value.startsWith("0x") ? Number.parseInt(value, 16) : Number(value);
}

function castUint(address, signature) {
  const result = run("cast", ["call", "--rpc-url", rpcUrl, address, signature]);
  return BigInt(result);
}

function main() {
  const probe = forgeCreate("gasUsed/ShrincsReceiptProbe.sol:ShrincsReceiptProbe");
  const statelessCommitment = vector("stateless-commitment");
  const statefulCommitment = vector("stateful-commitment");
  const statefulAccount = forgeCreate(
    "contracts/examples/ShrincsAccountVerifierExample.sol:ShrincsAccountVerifierExample",
    [statefulCommitment],
  );
  const statelessAccount = forgeCreate(
    "contracts/examples/ShrincsAccountVerifierExample.sol:ShrincsAccountVerifierExample",
    [statelessCommitment],
  );

  const statefulAccountCall = vector("stateful-account-call", statefulAccount);
  const statefulLibraryCall = vector("stateful-library-call", statefulAccount);
  const statefulRawCall = vector("stateful-raw-call", statefulAccount);
  const statelessAccountCall = vector("stateless-account-call", statelessAccount);
  const statelessLibraryCall = vector("stateless-library-call", statelessAccount);
  const statelessRawCall = vector("stateless-raw-call", statelessAccount);

  assertCallTrue(probe, statefulRawCall, "stateful raw");
  assertCallTrue(probe, statefulLibraryCall, "stateful library");
  assertCallTrue(statefulAccount, statefulAccountCall, "stateful account");
  assertCallTrue(probe, statelessRawCall, "stateless raw");
  assertCallTrue(probe, statelessLibraryCall, "stateless library");
  assertCallTrue(statelessAccount, statelessAccountCall, "stateless account");

  const statefulAccountGas = castSend(statefulAccount, statefulAccountCall);
  const statefulNonce = castUint(statefulAccount, "nonce()(uint256)");
  const nextLeaf = castUint(statefulAccount, "nextStatefulLeafIndex()(uint32)");
  if (statefulNonce !== 1n || nextLeaf !== 2n) {
    throw new Error(`stateful account state did not advance: nonce=${statefulNonce} nextLeaf=${nextLeaf}`);
  }
  const statelessAccountGas = castSend(statelessAccount, statelessAccountCall);
  const statelessNonce = castUint(statelessAccount, "nonce()(uint256)");
  const used = castUint(statelessAccount, "statelessSignaturesUsed()(uint64)");
  if (statelessNonce !== 1n || used !== 1n) {
    throw new Error(`stateless account state did not advance: nonce=${statelessNonce} statelessSignaturesUsed=${used}`);
  }

  const statefulLibraryGas = castSend(probe, statefulLibraryCall);
  const statefulRawGas = castSend(probe, statefulRawCall);
  const statelessLibraryGas = castSend(probe, statelessLibraryCall);
  const statelessRawGas = castSend(probe, statelessRawCall);

  console.log(`receipt gas stateful account verifyStatefulAction success: ${statefulAccountGas}`);
  console.log(`receipt gas stateful SHRINCS.verifyStateful success: ${statefulLibraryGas}`);
  console.log(`receipt gas stateful SHRINCS.verifyStatefulUncheckedMessage success: ${statefulRawGas}`);
  console.log(`receipt gas stateless account verifyStatelessAction success: ${statelessAccountGas}`);
  console.log(`receipt gas stateless SHRINCS.verifyStateless success: ${statelessLibraryGas}`);
  console.log(`receipt gas stateless SHRINCS.verifyStatelessUncheckedMessage success: ${statelessRawGas}`);
}

main();
