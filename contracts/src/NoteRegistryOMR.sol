// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title NoteRegistryOMR — OMR detection log with Pasta-4 encrypted entries
/// @notice Logs Pasta-4 encrypted PVW detection signals for oblivious message retrieval.
///         The FHE server transciphers Pasta-4 → BFV to evaluate detection homomorphically.
///         No fees, no spending logic. Gas is the only cost.
contract NoteRegistryOMR {
    uint64 public nextNoteId;
    uint256 public currentEpoch;
    uint256 public epochStartBlock;
    uint256 public constant BLOCKS_PER_EPOCH = 7200;

    /// @notice OMR note: Pasta-4 ciphertext of PVW detection signal on calldata.
    event NotePostedOMR(
        uint64 indexed noteId,
        uint256 indexed epoch,
        bytes32 commitment,
        bytes16 nonce,
        bytes pastaCt
    );

    constructor() {
        epochStartBlock = block.number;
    }

    /// @notice Post a note with a Pasta-4 encrypted detection signal.
    /// @param commitment Note commitment hash (32 bytes)
    /// @param nonce Per-note nonce (16 bytes, first 8 bytes also used as Pasta-4 nonce)
    /// @param pastaCt Pasta-4 ciphertext of PVW detection signal (128 bytes = 32 elements × 4 bytes)
    function postNoteOMR(
        bytes32 commitment,
        bytes16 nonce,
        bytes calldata pastaCt
    ) external {
        require(commitment != bytes32(0), "zero commitment");
        require(pastaCt.length == 128, "pastaCt must be 128 bytes");
        _advanceEpoch();
        uint64 noteId = nextNoteId++;
        emit NotePostedOMR(noteId, currentEpoch, commitment, nonce, pastaCt);
    }

    function _advanceEpoch() internal {
        uint256 elapsed = block.number - epochStartBlock;
        if (elapsed >= BLOCKS_PER_EPOCH) {
            uint256 skip = elapsed / BLOCKS_PER_EPOCH;
            currentEpoch += skip;
            epochStartBlock += skip * BLOCKS_PER_EPOCH;
        }
    }
}
