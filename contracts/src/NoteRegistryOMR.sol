// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title NoteRegistryOMR — Extends NoteRegistry with OMR detection clues
/// @notice Adds postNoteOMR for notes with PVW detection clues on calldata.
///         The encrypted note and Pasta-4 signal go to blob/sidecar off-chain.
///         Only the 104 B detection data (commitment + nonce + pvwClue) is on calldata.
contract NoteRegistryOMR {
    uint64 public nextNoteId;
    uint256 public currentEpoch;
    uint256 public epochStartBlock;
    uint256 public constant BLOCKS_PER_EPOCH = 7200;

    address public immutable owner;
    address public archivalVault;
    uint256 public minSenderFee;
    uint256 public serverFeePerNote;

    mapping(address => uint256) public balances;
    mapping(uint64 => bytes32) public noteCommitments;
    mapping(uint64 => bool) public archived;
    mapping(uint64 => bool) public spent;
    mapping(bytes32 => bool) public nullifiers;
    mapping(address => bool) public registered;

    // --- Events ---

    /// @notice Standard note (ciphertext on calldata, no OMR)
    event NotePosted(
        uint64 indexed noteId,
        uint256 indexed epoch,
        bytes32 commitment,
        bytes16 nonce,
        bytes ciphertext
    );

    /// @notice OMR note (Pasta-4 encrypted detection signal on calldata)
    event NotePostedOMR(
        uint64 indexed noteId,
        uint256 indexed epoch,
        bytes32 commitment,
        bytes16 nonce,
        bytes pastaCt
    );

    event KeyRegistered(address indexed recipient, bytes pkEc, bytes ekKem);
    event NoteArchived(uint64 indexed noteId, bytes32 commitment, address payer, uint256 fee);
    event BalanceDeposited(address indexed account, uint256 amount);
    event BalanceWithdrawn(address indexed account, uint256 amount);
    event NoteSpent(uint64 indexed noteId, bytes32 nullifier, uint256 feePaid);

    constructor(address _archivalVault) {
        owner = msg.sender;
        epochStartBlock = block.number;
        archivalVault = _archivalVault;
    }

    // =========================================================================
    //  Key registration
    // =========================================================================

    function registerKeys(bytes calldata pkEc, bytes calldata ekKem) external {
        require(pkEc.length == 33, "pkEc must be 33 bytes");
        require(ekKem.length == 1184, "ekKem must be 1184 bytes");
        registered[msg.sender] = true;
        emit KeyRegistered(msg.sender, pkEc, ekKem);
    }

    // =========================================================================
    //  Note posting — standard (ciphertext on calldata)
    // =========================================================================

    function postNote(
        bytes32 commitment,
        bytes16 nonce,
        bytes calldata ciphertext
    ) external payable {
        require(commitment != bytes32(0), "zero commitment");
        require(msg.value >= minSenderFee, "below min sender fee");
        _advanceEpoch();
        uint64 noteId = nextNoteId++;
        noteCommitments[noteId] = commitment;
        emit NotePosted(noteId, currentEpoch, commitment, nonce, ciphertext);
        _handleFee(noteId, commitment);
    }

    // =========================================================================
    //  Note posting — OMR (pvwClue on calldata, ciphertext in blob/sidecar)
    // =========================================================================

    /// @notice Post a note with a Pasta-4 encrypted detection signal for OMR.
    ///         The Pasta-4 ciphertext (64 B) contains the PVW clue encrypted
    ///         under a symmetric key derived from k_pairwise. The FHE server
    ///         transciphers Pasta-4 → BFV to evaluate detection homomorphically.
    /// @param commitment Note commitment hash (32 bytes)
    /// @param nonce 16-byte nonce
    /// @param pastaCt Pasta-4 ciphertext of PVW detection signal (64 bytes)
    function postNoteOMR(
        bytes32 commitment,
        bytes16 nonce,
        bytes calldata pastaCt
    ) external payable {
        require(commitment != bytes32(0), "zero commitment");
        require(pastaCt.length == 64, "pastaCt must be 64 bytes");
        require(msg.value >= minSenderFee, "below min sender fee");
        _advanceEpoch();
        uint64 noteId = nextNoteId++;
        noteCommitments[noteId] = commitment;
        emit NotePostedOMR(noteId, currentEpoch, commitment, nonce, pastaCt);
        _handleFee(noteId, commitment);
    }

    // =========================================================================
    //  Archival, subscription, spend (same as pq_SA NoteRegistry)
    // =========================================================================

    function archiveNote(uint64 noteId) external payable {
        require(noteCommitments[noteId] != bytes32(0), "note does not exist");
        require(!archived[noteId], "already archived");
        require(msg.value > 0, "must send archival fee");
        _handleFee(noteId, noteCommitments[noteId]);
    }

    function depositBalance() external payable {
        require(msg.value > 0, "must send value");
        balances[msg.sender] += msg.value;
        emit BalanceDeposited(msg.sender, msg.value);
    }

    function withdrawBalance(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        (bool sent,) = msg.sender.call{value: amount}("");
        require(sent, "withdraw failed");
        emit BalanceWithdrawn(msg.sender, amount);
    }

    function spendNote(uint64 noteId, bytes32 nullifier) external {
        require(noteCommitments[noteId] != bytes32(0), "note does not exist");
        require(!spent[noteId], "note already spent");
        require(!nullifiers[nullifier], "nullifier already used");

        spent[noteId] = true;
        nullifiers[nullifier] = true;

        uint256 fee = serverFeePerNote;
        if (fee > 0 && archivalVault != address(0)) {
            require(balances[msg.sender] >= fee, "insufficient balance for fee");
            balances[msg.sender] -= fee;
            (bool sent,) = archivalVault.call{value: fee}("");
            require(sent, "fee transfer failed");
        }

        emit NoteSpent(noteId, nullifier, fee);
    }

    // =========================================================================
    //  Admin
    // =========================================================================

    function setArchivalVault(address _archivalVault) external {
        require(msg.sender == owner, "not owner");
        archivalVault = _archivalVault;
    }

    function setServerFeePerNote(uint256 _fee) external {
        require(msg.sender == owner, "not owner");
        serverFeePerNote = _fee;
    }

    function setMinSenderFee(uint256 _fee) external {
        require(msg.sender == owner, "not owner");
        minSenderFee = _fee;
    }

    // =========================================================================
    //  Internal
    // =========================================================================

    function _handleFee(uint64 noteId, bytes32 commitment) internal {
        if (msg.value > 0) {
            if (archivalVault != address(0)) {
                archived[noteId] = true;
                (bool sent,) = archivalVault.call{value: msg.value}("");
                require(sent, "fee transfer failed");
                emit NoteArchived(noteId, commitment, msg.sender, msg.value);
            } else {
                (bool sent,) = msg.sender.call{value: msg.value}("");
                require(sent, "refund failed");
            }
        }
    }

    function _advanceEpoch() internal {
        while (block.number >= epochStartBlock + BLOCKS_PER_EPOCH) {
            currentEpoch++;
            epochStartBlock += BLOCKS_PER_EPOCH;
        }
    }
}
