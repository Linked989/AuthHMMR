// Update these before running.
const RPC_URL = "http://127.0.0.1:8545"; // Besu RPC endpoint
const PRIVATE_KEY = "0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63"; // Deployer private key
const ALPHA = 1;
const BETA = 1;
const GAMMA = 1;
const CONTRACT_NAME = "DeviceRegistry";

async function main() {
  const hre = require("hardhat");
  const { ethers, network } = hre;

  console.log("======================================");
  console.log(`Deploying ${CONTRACT_NAME}`);
  console.log("Network:          ", network.name);

  if (!PRIVATE_KEY || PRIVATE_KEY === "0xYOUR_PRIVATE_KEY") {
    throw new Error("Set PRIVATE_KEY at the top of scripts/deploy.js");
  }

  const provider = new ethers.providers.JsonRpcProvider(RPC_URL);
  const deployer = new ethers.Wallet(PRIVATE_KEY, provider);

  console.log("Deployer address: ", deployer.address);
  const balance = await deployer.getBalance();
  console.log("Deployer balance: ", ethers.utils.formatEther(balance), "ETH");

  const Factory = await ethers.getContractFactory(CONTRACT_NAME, deployer);
  const contract = await Factory.deploy(ALPHA, BETA, GAMMA);
  console.log("Deploy tx sent. Hash:", contract.deployTransaction.hash);

  const receipt = await contract.deployTransaction.wait();

  console.log("--------------------------------------");
  console.log(`${CONTRACT_NAME} deployed!`);
  console.log("Contract address:  ", contract.address);
  console.log("Owner (on-chain):  ", await contract.owner());
  console.log("Block number:      ", receipt.blockNumber);
  console.log("Gas used:          ", receipt.gasUsed.toString());
  console.log("Tx hash:           ", receipt.transactionHash);
  console.log("======================================");

  console.log("\nDeployment summary JSON:");
  console.log(
    JSON.stringify(
      {
        network: network.name,
        deployer: deployer.address,
        contract: contract.address,
        txHash: receipt.transactionHash,
        blockNumber: receipt.blockNumber.toString(),
      },
      null,
      2
    )
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
