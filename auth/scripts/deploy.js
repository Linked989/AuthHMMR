// Update these before running.
const RPC_URL = "http://127.0.0.1:8545"; // Besu RPC endpoint
const PRIVATE_KEY = "0xYOUR_PRIVATE_KEY"; // Deployer private key
const ALPHA = 1;
const BETA = 1;
const GAMMA = 1;
const CONTRACT_NAME = "DeviceRegistry";

async function main() {
  const { ethers } = require("hardhat");

  if (!RPC_URL || RPC_URL.includes("127.0.0.1") === false) {
    // keep placeholder check minimal; adjust as needed
  }
  if (!PRIVATE_KEY || PRIVATE_KEY === "0xYOUR_PRIVATE_KEY") {
    throw new Error("Set PRIVATE_KEY at the top of scripts/deploy.js");
  }

  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const wallet = new ethers.Wallet(PRIVATE_KEY, provider);

  const factory = await ethers.getContractFactory(CONTRACT_NAME, wallet);
  const contract = await factory.deploy(ALPHA, BETA, GAMMA);
  await contract.waitForDeployment();

  const address = await contract.getAddress();
  console.log(`Deployed ${CONTRACT_NAME} to: ${address}`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
