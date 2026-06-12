// This deployment module intentionally deploys only the SHRINCS example wrapper.
// Use the separate WOTSPlus module when you want the legacy WOTS+ library.

import {buildModule} from "@nomicfoundation/hardhat-ignition/modules";

const ZERO_BYTES32 = "0x0000000000000000000000000000000000000000000000000000000000000000";

const ShrincsAccountVerifierExampleModule = buildModule("ShrincsAccountVerifierExampleModule", (m) => {
  const initialShrincsPublicKey = m.getParameter("initialShrincsPublicKey", ZERO_BYTES32);
  const shrincsAccountVerifierExample = m.contract("ShrincsAccountVerifierExample", [initialShrincsPublicKey]);

  return {shrincsAccountVerifierExample};
});

export default ShrincsAccountVerifierExampleModule;
