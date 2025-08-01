import { expect } from "chai";
import { ethers } from "hardhat";

describe("PodAuthorization", function () {
  let podAuth: any;
  let owner: any;
  let user: any;
  const contractHash = "hash_123";
  const appId = "app_xyz";
  const futureTime = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now

  beforeEach(async () => {
    [owner, user] = await ethers.getSigners();
    const PodAuthFactory = await ethers.getContractFactory("PodAuthorization");
    podAuth = await PodAuthFactory.deploy();
    await podAuth.waitForDeployment();
  });

  it("should grant authorization and emit event", async () => {
    const tx = await podAuth.connect(user).grantAuthorization(contractHash, appId, futureTime);
    const receipt = await tx.wait();

    const event = receipt.logs
      .map((log: any) => {
        try {
          return podAuth.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((parsed: { name: string; }) => parsed?.name === "AuthorizationUpdated");
    
    console.log(event);

    expect(event).to.not.be.undefined;
    expect(event?.args.action).to.equal("grant");

    const isAuth = await podAuth.isAuthorized(await user.getAddress(), contractHash);
    expect(isAuth).to.be.true;
  });

  it("should revoke authorization and emit event", async () => {
    await podAuth.connect(user).grantAuthorization(contractHash, appId, futureTime);
    const tx = await podAuth.connect(user).revokeAuthorization(contractHash);
    const receipt = await tx.wait();

    const event = receipt.logs
      .map((log: any) => {
        try {
          return podAuth.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((parsed: { name: string; }) => parsed?.name === "AuthorizationUpdated");

    console.log(event);
    
    expect(event?.args?.action).to.equal("revoke");

    const isAuth = await podAuth.isAuthorized(await user.getAddress(), contractHash);
    expect(isAuth).to.be.false;
  });

  it("should return correct authorization details", async () => {
    await podAuth.connect(user).grantAuthorization(contractHash, appId, futureTime);
    const details = await podAuth.getAuthorizationDetails(await user.getAddress(), contractHash);

    expect(details.appId).to.equal(appId);
    expect(details.validUntil).to.equal(futureTime);
    expect(details.granted).to.be.true;
  });

  it("should handle expired authorization", async () => {
    const pastTime = Math.floor(Date.now() / 1000) - 100;
    await expect(
      podAuth.connect(user).grantAuthorization(contractHash, appId, pastTime)
    ).to.be.revertedWith("Authorization must be in the future");
  });

  it("should reject revocation if no prior grant", async () => {
    await expect(
      podAuth.connect(user).revokeAuthorization(contractHash)
    ).to.be.revertedWith("No active authorization");
  });

  it("should log events to user history", async () => {
    await podAuth.connect(user).grantAuthorization(contractHash, appId, futureTime);
    await podAuth.connect(user).revokeAuthorization(contractHash);

    const history = await podAuth.getUserHistory(await user.getAddress());
    expect(history.length).to.equal(2);
    expect(history[0].action).to.equal("grant");
    expect(history[1].action).to.equal("revoke");
  });
});

