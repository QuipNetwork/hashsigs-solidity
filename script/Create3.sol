// Copyright (C) 2026 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

/// @title Create3
/// @notice Minimal CREATE3 primitive. A deployed contract's address
/// depends only on (deployer, salt) — NOT on its init code — so the
/// verifier bytecode can change (recompile, profile) without moving the
/// address (maintainer decision Q5). Deploy-only helper (script/), never
/// part of the on-chain verifier surface.
/// @dev CREATE3 = CREATE2 a fixed minimal proxy, then have that proxy
/// CREATE the child at its nonce 1. The child address therefore depends
/// only on the proxy address (a function of deployer + salt + the fixed
/// proxy code) and the constant nonce 1. Proxy runtime `363d3d37363d34f0`
/// is CALLDATACOPY(child init code) then CREATE. The canonical deploys go
/// through the pre-deployed CreateX singleton (DeployBase.s.sol), whose
/// CREATE3 uses this exact proxy, so `addressOf` doubles as the local,
/// RPC-free predictor for CreateX children (deployer = CREATEX, salt =
/// the GUARDED salt); CreateXCreate3.t.sol anchors that equivalence to a
/// real on-chain CreateX deployment. `deploy` remains as the test-harness
/// primitive for exercising CREATE3 semantics locally.
///
/// This library applies NO salt guard, deliberately: it takes an
/// already-guarded salt and does pure proxy math. That is what keeps its
/// known-answer test valid across a change of guard mode, and why the
/// guard policy lives separately in script/CreateXSalt.sol.
library Create3 {
    // Fixed CREATE3 proxy init code (deploys the 8-byte runtime
    // `363d3d37363d34f0` = copy calldata, then CREATE with it). This is
    // the canonical CREATE3 proxy; its bytes are structural, not derived
    // from any spec parameter, and CreateX embeds the same constant.
    bytes internal constant PROXY_INIT_CODE =
        hex"67363d3d37363d34f03d5260086018f3";

    /// @notice Deploy `initCode` deterministically from address(this).
    /// @param salt The deployment salt (child address = f(this, salt)).
    /// @param initCode The child contract creation code.
    /// @return deployed The deployed child address.
    function deploy(bytes32 salt, bytes memory initCode)
        internal
        returns (address deployed)
    {
        bytes memory proxyInit = PROXY_INIT_CODE;
        address proxy;
        // CREATE2 the fixed proxy. Memory-safe: reads the proxyInit
        // buffer (length-prefixed at proxyInit, data at proxyInit+0x20);
        // create2 writes no caller memory.
        assembly ("memory-safe") {
            proxy := create2(0, add(proxyInit, 0x20), mload(proxyInit), salt)
        }
        require(proxy != address(0), "Create3: proxy deploy failed");

        deployed = addressOf(salt, address(this));
        // Call the proxy with the child init code as calldata; the proxy
        // runtime CREATEs the child at its nonce 1.
        (bool ok,) = proxy.call(initCode);
        require(
            ok && deployed.code.length != 0, "Create3: child deploy failed"
        );
    }

    /// @notice Predict the CREATE3 child address for (deployer, salt).
    /// @param salt The deployment salt.
    /// @param deployer The address that performs the CREATE3 deploy.
    /// @return The predicted child contract address.
    function addressOf(bytes32 salt, address deployer)
        internal
        pure
        returns (address)
    {
        // proxy = CREATE2(deployer, salt, keccak256(PROXY_INIT_CODE)).
        address proxy = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            hex"ff",
                            deployer,
                            salt,
                            keccak256(PROXY_INIT_CODE)
                        )
                    )
                )
            )
        );
        // child = CREATE(proxy, nonce = 1) = keccak256(rlp([proxy, 1])).
        // RLP of a 20-byte address + the byte 0x01 is
        // 0xd6 0x94 <20-byte proxy> 0x01.
        return address(
            uint160(
                uint256(
                    keccak256(abi.encodePacked(hex"d694", proxy, hex"01"))
                )
            )
        );
    }
}
