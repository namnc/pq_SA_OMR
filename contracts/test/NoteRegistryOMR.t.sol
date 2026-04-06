// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {NoteRegistryOMR} from "../src/NoteRegistryOMR.sol";

contract NoteRegistryOMRTest is Test {
    NoteRegistryOMR public registry;

    event NotePostedOMR(uint64 indexed noteId, uint256 indexed epoch,
        bytes32 commitment, bytes16 nonce, bytes pastaCt);

    function setUp() public {
        registry = new NoteRegistryOMR();
    }

    function test_postNoteOMR() public {
        bytes32 commitment = keccak256("omr-note");
        bytes16 nonce = bytes16(uint128(42));
        registry.postNoteOMR(commitment, nonce, new bytes(128));
        assertEq(registry.nextNoteId(), 1);
    }

    function test_postNoteOMR_rejectsBadCtLength() public {
        vm.expectRevert("pastaCt must be 128 bytes");
        registry.postNoteOMR(keccak256("bad"), bytes16(uint128(1)), new bytes(64));
    }

    function test_postNoteOMR_rejectsZeroCommitment() public {
        vm.expectRevert("zero commitment");
        registry.postNoteOMR(bytes32(0), bytes16(uint128(1)), new bytes(128));
    }

    function test_postNoteOMR_emitsEvent() public {
        bytes32 commitment = keccak256("event-test");
        bytes16 nonce = bytes16(uint128(99));
        bytes memory pastaCt = new bytes(128);
        pastaCt[0] = 0xAB;

        vm.expectEmit(true, true, false, true);
        emit NotePostedOMR(0, 0, commitment, nonce, pastaCt);
        registry.postNoteOMR(commitment, nonce, pastaCt);
    }

    function test_noteIdIncrements() public {
        registry.postNoteOMR(keccak256("a"), bytes16(uint128(1)), new bytes(128));
        registry.postNoteOMR(keccak256("b"), bytes16(uint128(2)), new bytes(128));
        registry.postNoteOMR(keccak256("c"), bytes16(uint128(3)), new bytes(128));
        assertEq(registry.nextNoteId(), 3);
    }

    function test_epochAdvances() public {
        registry.postNoteOMR(keccak256("a"), bytes16(uint128(1)), new bytes(128));
        assertEq(registry.currentEpoch(), 0);
        vm.roll(block.number + 7201);
        registry.postNoteOMR(keccak256("b"), bytes16(uint128(2)), new bytes(128));
        assertEq(registry.currentEpoch(), 1);
    }

    function test_gasPostNoteOMR() public {
        uint256 g = gasleft();
        registry.postNoteOMR(keccak256("gas"), bytes16(uint128(42)), new bytes(128));
        emit log_named_uint("postNoteOMR gas", g - gasleft());
    }
}
