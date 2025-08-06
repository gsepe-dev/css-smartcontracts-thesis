import { ethers } from "hardhat";

async function main() {
  console.log("Deploying PodAuthorization...");

  const PodAuthorizationFactory = await ethers.getContractFactory("PodAuthorization");
  const podAuthorization = await PodAuthorizationFactory.deploy();

  console.log(`PodAuthorization deployed to: ${podAuthorization.target}`);
}

main().catch((error) => {
  console.error("Deployment failed:", error);
  process.exitCode = 1;
});
