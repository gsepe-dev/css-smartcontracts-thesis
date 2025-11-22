# css-smartcontracts-thesis

This project contains the **PodAuthorization** smart contract, developed using Hardhat.

It includes the contract source code, tests, and deployment scripts.

**PodAuthorization** is a Solidity smart contract developed as part of my academic **research thesis** exploring blockchain-based consent management systems.  

It integrates with a customized fork of the [**Community Solid Server**](https://github.com/gsepe-dev/CommunitySolidServer/tree/riccy), enabling decentralized, verifiable consent tracking for applications accessing user data.

By leveraging Ricardian contracts and on-chain event logging, the project aims to enhance transparency, user autonomy, and auditability within Solid Pod environments.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

Before running any commands, clean the dependencies:

```shell
npm cache clean --force
rm -rf node_modules package-lock.json
```

### Installing

Then install the correct dependencies:

```shell
npm install --save-dev hardhat
```

### Running the tests

```shell
npx hardhat compile
npx hardhat test
```

### Deploy

Before deploying, start the local hardhat node:

```shell
npx hardhat node
```

Now deploy the contract:

```shell
npx hardhat run scripts/deploy.ts --network localhost
```

## Built With

* [Hardhat](https://hardhat.org/) - Ethereum development environment;
* [npm](https://www.npmjs.com/) - Tool for installing and managing JavaScript modules and packages for Node.js applications.

## License

This project is licensed under the MIT License
