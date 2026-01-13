// Update these before running.
const RPC_URL = "http://127.0.0.1:8545"; // Besu RPC endpoint
const PRIVATE_KEY = "0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63"; // Deployer private key
const CONTRACT_ADDRESS = "0xYOUR_CONTRACT_ADDRESS";
const CONTRACT_NAME = "DeviceRegistry";

async function main() {
  const { ethers } = require("hardhat");

  if (!PRIVATE_KEY || PRIVATE_KEY === "0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63") {
    throw new Error("Set PRIVATE_KEY at the top of scripts/clear_devices.js");
  }
  if (!CONTRACT_ADDRESS || CONTRACT_ADDRESS === "0xYOUR_CONTRACT_ADDRESS") {
    throw new Error("Set CONTRACT_ADDRESS at the top of scripts/clear_devices.js");
  }

  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const wallet = new ethers.Wallet(PRIVATE_KEY, provider);

  const contract = await ethers.getContractAt(CONTRACT_NAME, CONTRACT_ADDRESS, wallet);
  const devices = await contract.getAllDevices();

  console.log(`Found ${devices.length} device(s). Removing...`);
  for (const dev of devices) {
    const uuid = dev.uuid;
    console.log(`Removing ${uuid}`);
    const tx = await contract.removeDevice(uuid);
    await tx.wait();
  }

  console.log("Done.");
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
