# Sample Hardhat Project

This project demonstrates a basic Hardhat use case. It comes with a sample contract, a test for that contract, and a Hardhat Ignition module that deploys that contract.

Try running some of the following tasks:

```shell
npx hardhat help
npx hardhat test
REPORT_GAS=true npx hardhat test
npx hardhat node
npx hardhat ignition deploy ./ignition/modules/Lock.ts
```

## Testing with Foundry

### Installation

1. Install Foundry:
```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

2. Initialize Foundry in your project:
```bash
forge init --no-commit
```

3. Install dependencies:
```bash
forge install foundry-rs/forge-std
```

### Running Tests

Run the tests with:
```bash
forge test -vv
```

The `-vv` flag increases verbosity to show more test details. Use `-vvv` for even more detailed output including stack traces.
