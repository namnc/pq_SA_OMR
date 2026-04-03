// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {NoteRegistryOMR} from "../src/NoteRegistryOMR.sol";

contract NoteRegistryOMRTest is Test {
    NoteRegistryOMR public registry;
    address sender = address(0x1);
    address recipient = address(0x2);
    address vault = address(0x3);

    event NotePostedOMR(uint64 indexed noteId, uint256 indexed epoch,
        bytes32 commitment, bytes16 nonce, bytes pvwClue);

    function setUp() public {
        registry = new NoteRegistryOMR(vault);
        vm.deal(sender, 10 ether);
        vm.deal(recipient, 10 ether);
    }

    // --- postNoteOMR ---

    function test_postNoteOMR() public {
        bytes32 commitment = keccak256("omr-note");
        bytes16 nonce = bytes16(uint128(42));
        bytes memory pvwClue = new bytes(52);

        vm.prank(sender);
        registry.postNoteOMR(commitment, nonce, pvwClue);

        assertEq(registry.nextNoteId(), 1);
        assertEq(registry.noteCommitments(0), commitment);
    }

    function test_postNoteOMR_rejectsBadClueLength() public {
        vm.prank(sender);
        vm.expectRevert("pvwClue must be 52 bytes");
        registry.postNoteOMR(keccak256("bad"), bytes16(uint128(1)), new bytes(50));
    }

    function test_postNoteOMR_rejectsZeroCommitment() public {
        vm.prank(sender);
        vm.expectRevert("zero commitment");
        registry.postNoteOMR(bytes32(0), bytes16(uint128(1)), new bytes(52));
    }

    function test_postNoteOMR_emitsEvent() public {
        bytes32 commitment = keccak256("event-test");
        bytes16 nonce = bytes16(uint128(99));
        bytes memory pvwClue = new bytes(52);
        pvwClue[0] = 0xAB;

        vm.prank(sender);
        vm.expectEmit(true, true, false, true);
        emit NotePostedOMR(0, 0, commitment, nonce, pvwClue);
        registry.postNoteOMR(commitment, nonce, pvwClue);
    }

    function test_postNoteOMR_respectsMinFee() public {
        registry.setMinSenderFee(0.001 ether);

        vm.prank(sender);
        vm.expectRevert("below min sender fee");
        registry.postNoteOMR(keccak256("fee"), bytes16(uint128(1)), new bytes(52));

        vm.prank(sender);
        registry.postNoteOMR{value: 0.001 ether}(keccak256("fee"), bytes16(uint128(1)), new bytes(52));
        assertEq(registry.nextNoteId(), 1);
    }

    function test_postNoteOMR_forwardsFee() public {
        uint256 vaultBefore = vault.balance;
        vm.prank(sender);
        registry.postNoteOMR{value: 0.001 ether}(keccak256("paid"), bytes16(uint128(1)), new bytes(52));
        assertEq(vault.balance, vaultBefore + 0.001 ether);
    }

    // --- Shared noteId counter ---

    function test_noteIdSharedBetweenPostTypes() public {
        registry.postNote(keccak256("a"), bytes16(uint128(1)), new bytes(632));
        registry.postNoteOMR(keccak256("b"), bytes16(uint128(2)), new bytes(52));
        registry.postNote(keccak256("c"), bytes16(uint128(3)), new bytes(632));
        assertEq(registry.nextNoteId(), 3);
    }

    // --- OMR notes can be spent ---

    function test_spendOMRNote() public {
        registry.postNoteOMR(keccak256("sp"), bytes16(uint128(1)), new bytes(52));

        vm.prank(recipient);
        registry.spendNote(0, keccak256("null-omr"));

        assertTrue(registry.spent(0));
        assertTrue(registry.nullifiers(keccak256("null-omr")));
    }

    // --- Gas measurement ---

    function test_postNoteOMR_gasMeasurement() public {
        bytes32 commitment = keccak256("gas-test");
        bytes16 nonce = bytes16(uint128(42));
        bytes memory pvwClue = new bytes(52);

        vm.prank(sender);
        uint256 gasBefore = gasleft();
        registry.postNoteOMR(commitment, nonce, pvwClue);
        uint256 gasUsed = gasBefore - gasleft();

        // Log gas for comparison with postNote
        emit log_named_uint("postNoteOMR gas", gasUsed);
        // Should be similar to postNote but with 52 B pvwClue instead of 632 B ciphertext
    }

    function test_postNote_gasMeasurement() public {
        bytes32 commitment = keccak256("gas-test-std");
        bytes16 nonce = bytes16(uint128(42));
        bytes memory ciphertext = new bytes(632);

        vm.prank(sender);
        uint256 gasBefore = gasleft();
        registry.postNote(commitment, nonce, ciphertext);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("postNote gas", gasUsed);
    }
}
