// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {FORSMinusC} from "../contracts/FORSMinusC.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";

contract Issue08ForsShapeHarness {
    function verifyShape(
        bytes calldata pkSeed,
        bytes calldata hypertreeRoot,
        FORSMinusC.ForsSignature calldata signature
    ) external view returns (bool ok) {
        (,,, ok) = FORSMinusC.verifyForsCAndReturnRoot(
            pkSeed, hypertreeRoot, bytes("issue08-shape"), signature
        );
    }
}

contract Issue08ForsShapeValidationTest is Test {
    Issue08ForsShapeHarness internal harness;

    function setUp() public {
        harness = new Issue08ForsShapeHarness();
    }

    function testRejectsShortEntriesWithoutReverting() public view {
        uint256 signedTrees = uint256(SHRINCSParams.NUM_FORS_TREES) - 1;
        FORSMinusC.ForsSignature memory signature =
            _signature(signedTrees - 1, new bytes(32));
        assertFalse(_verify(signature));
    }

    function testRejectsLongEntriesWithoutReverting() public view {
        uint256 signedTrees = uint256(SHRINCSParams.NUM_FORS_TREES) - 1;
        FORSMinusC.ForsSignature memory signature =
            _signature(signedTrees + 1, new bytes(32));
        assertFalse(_verify(signature));
    }

    // line-length: allow — forge fmt keeps the descriptive name
    function testFuzzRejectsEveryWrongRandomizerLength(bytes calldata randomizer)
        public
        view
    {
        vm.assume(randomizer.length != 32);
        uint256 signedTrees = uint256(SHRINCSParams.NUM_FORS_TREES) - 1;
        FORSMinusC.ForsSignature memory signature =
            _signature(signedTrees, randomizer);
        assertFalse(_verify(signature));
    }

    function _verify(FORSMinusC.ForsSignature memory signature)
        internal
        view
        returns (bool)
    {
        return harness.verifyShape(
            abi.encodePacked(bytes32(uint256(1))),
            abi.encodePacked(bytes32(uint256(2))),
            signature
        );
    }

    function _signature(uint256 entriesLength, bytes memory randomizer)
        internal
        pure
        returns (FORSMinusC.ForsSignature memory)
    {
        return FORSMinusC.ForsSignature({
            randomizer: randomizer,
            counter: 0,
            entries: new FORSMinusC.ForsEntry[](entriesLength)
        });
    }
}
