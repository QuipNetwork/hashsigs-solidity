// This deployment module intentionally deploys only the legacy WOTS+ library.
// Use the separate SHRINCS module when you want the example SHRINCS wrapper.

import {buildModule} from "@nomicfoundation/hardhat-ignition/modules";

const WOTSPlusModule = buildModule("WOTSPlusModule", (m) => {
  const wotsPlus = m.contract("WOTSPlus");

  return {wotsPlus};
});

export default WOTSPlusModule;
