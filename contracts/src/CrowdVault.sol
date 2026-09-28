// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CrowdVault
/// @notice Crowdfunding vault where releasing the pot and publishing the campaign
///         decryption key are the same transaction.
///
/// Goods are encrypted off-chain to the campaign public key X = x·G (secp256k1).
/// Once contributions reach `threshold`, anyone holding x can call `claim(x)`.
/// The contract checks x·G == X, sends the pot to the fixed `recipient`, and x is
/// then public in calldata and in the `Claimed` event, so everyone can decrypt.
///
/// Because the payout destination is fixed, front-running a claim is harmless:
/// whoever submits x, the money still goes to `recipient`.
///
/// Phases:
///   Open    - contribute or withdraw freely.
///   Locked  - threshold reached; withdrawals frozen for `claimWindow` seconds,
///             at most MAX_CLAIM_WINDOW (30 days).
///   Claimed - key revealed, pot released. Terminal.
///   Expired - window passed with no claim; contributors withdraw. Terminal.
///
/// Deploy through CrowdVaultFactory, which records genuine vaults, and send a
/// small value (1 wei is enough) with the deployment: it is forwarded to the
/// recipient to prove the recipient can accept ETH.
contract CrowdVault {
    // ---------------------------------------------------------------- secp256k1
    uint256 private constant P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 private constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 private constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    /// @dev G.y is even, so the recovery id for R = G is 27.
    uint8 private constant GV = 27;

    /// @notice The longest claim window allowed: backers' funds can never be
    ///         frozen for longer than this after the goal is reached.
    uint256 public constant MAX_CLAIM_WINDOW = 30 days;

    enum Phase {
        Open,
        Locked,
        Claimed,
        Expired
    }

    // ---------------------------------------------------------------- config
    address payable public immutable recipient;
    uint256 public immutable threshold;
    uint256 public immutable claimWindow; // in seconds
    uint256 public immutable keyX; // campaign public key, affine x
    uint256 public immutable keyY; // campaign public key, affine y
    address public immutable keyAddress; // keccak-address of (keyX, keyY)

    // ---------------------------------------------------------------- state
    mapping(address => uint256) public contributionOf;
    uint256 public totalContributed;
    uint256 public lockedAt; // timestamp the goal was reached; 0 while Open
    bool public claimed;
    uint256 public revealedKey; // x, once claimed
    uint256 public releasedAmount; // the whole pot, fixed at the claim
    uint256 public pendingPayout; // owed to recipient if the push transfer failed

    uint256 private _entered = 1;

    // ---------------------------------------------------------------- events
    event Contributed(address indexed contributor, uint256 amount, uint256 total);
    event Withdrawn(address indexed contributor, uint256 amount, uint256 total);
    event Locked(uint256 at, uint256 deadline);
    event Claimed(uint256 key, address indexed claimant, uint256 amount);
    event PayoutReleased(address indexed recipient, uint256 amount);

    // ---------------------------------------------------------------- errors
    error BadConfig();
    error KeyNotOnCurve();
    error RecipientCheckFailed();
    error WrongPhase(Phase current);
    error ZeroAmount();
    error NothingToWithdraw();
    error InvalidKey();
    error TransferFailed();
    error Reentrancy();

    modifier nonReentrant() {
        if (_entered != 1) revert Reentrancy();
        _entered = 2;
        _;
        _entered = 1;
    }

    constructor(address payable recipient_, uint256 threshold_, uint256 claimWindow_, uint256 keyX_, uint256 keyY_)
        payable
    {
        if (recipient_ == address(0) || threshold_ == 0 || claimWindow_ == 0 || claimWindow_ > MAX_CLAIM_WINDOW) {
            revert BadConfig();
        }
        if (!_onCurve(keyX_, keyY_)) revert KeyNotOnCurve();
        recipient = recipient_;
        threshold = threshold_;
        claimWindow = claimWindow_;
        keyX = keyX_;
        keyY = keyY_;
        keyAddress = address(uint160(uint256(keccak256(abi.encodePacked(keyX_, keyY_)))));

        // Prove the recipient accepts ETH, so a payout can never be stuck.
        if (msg.value == 0) revert RecipientCheckFailed();
        (bool ok,) = recipient_.call{value: msg.value}("");
        if (!ok) revert RecipientCheckFailed();
    }

    // ================================================================ views

    function phase() public view returns (Phase) {
        if (claimed) return Phase.Claimed;
        if (lockedAt == 0) return Phase.Open;
        if (block.timestamp > lockedAt + claimWindow) return Phase.Expired;
        return Phase.Locked;
    }

    /// @notice Last timestamp at which `claim` is accepted (0 while Open).
    function deadline() public view returns (uint256) {
        return lockedAt == 0 ? 0 : lockedAt + claimWindow;
    }

    /// @notice One-call snapshot for frontends.
    function status(address who)
        external
        view
        returns (
            Phase phase_,
            uint256 total_,
            uint256 threshold_,
            uint256 deadline_,
            uint256 mine_,
            uint256 key_,
            uint256 now_,
            uint256 released_
        )
    {
        return (
            phase(),
            totalContributed,
            threshold,
            deadline(),
            contributionOf[who],
            revealedKey,
            block.timestamp,
            releasedAmount
        );
    }

    /// @notice True iff x is the secret behind the campaign key (x·G == X).
    function isCampaignSecret(uint256 x) public view returns (bool) {
        if (x == 0 || x >= N) return false;
        return _mulG(x) == keyAddress;
    }

    // ================================================================ actions

    /// @notice Add funds. The contribution that reaches the threshold locks the
    ///         vault in the same transaction, so no withdrawal can slip in between.
    function contribute() public payable nonReentrant {
        Phase ph = phase();
        if (ph != Phase.Open) revert WrongPhase(ph);
        if (msg.value == 0) revert ZeroAmount();

        contributionOf[msg.sender] += msg.value;
        uint256 total = totalContributed + msg.value;
        totalContributed = total;
        emit Contributed(msg.sender, msg.value, total);

        if (total >= threshold) {
            lockedAt = block.timestamp;
            emit Locked(block.timestamp, block.timestamp + claimWindow);
        }
    }

    /// @notice Take back your whole contribution. Allowed while Open or Expired.
    function withdraw() external nonReentrant {
        Phase ph = phase();
        if (ph != Phase.Open && ph != Phase.Expired) revert WrongPhase(ph);

        uint256 amount = contributionOf[msg.sender];
        if (amount == 0) revert NothingToWithdraw();

        // Effects before interaction.
        contributionOf[msg.sender] = 0;
        totalContributed -= amount;
        emit Withdrawn(msg.sender, amount, totalContributed);

        (bool ok,) = msg.sender.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    /// @notice Reveal the campaign secret and release the pot to `recipient`.
    ///         Anyone may call; the payout destination is fixed.
    function claim(uint256 x) external nonReentrant {
        Phase ph = phase();
        if (ph != Phase.Locked) revert WrongPhase(ph);
        if (!isCampaignSecret(x)) revert InvalidKey();

        // Effects before interaction. The payout is the whole balance, so ETH
        // force-sent to the vault is swept to the recipient too.
        claimed = true;
        revealedKey = x;
        totalContributed = 0;
        uint256 amount = address(this).balance;
        releasedAmount = amount;
        emit Claimed(x, msg.sender, amount);

        // Push; if the recipient rejects ETH the claim still stands and the
        // payout can be pulled later via `releasePayout`.
        _tryPayout();
    }

    /// @notice Retry sending the pot to `recipient` after a failed push, or
    ///         sweep ETH force-sent after the claim.
    function releasePayout() external nonReentrant {
        if (!claimed) revert WrongPhase(phase());
        if (address(this).balance == 0) revert NothingToWithdraw();
        if (!_tryPayout()) revert TransferFailed();
    }

    receive() external payable {
        contribute();
    }

    // ================================================================ internals

    function _tryPayout() private returns (bool ok) {
        uint256 amount = address(this).balance;
        pendingPayout = 0;
        (ok,) = recipient.call{value: amount}("");
        if (ok) {
            emit PayoutReleased(recipient, amount);
        } else {
            pendingPayout = amount;
        }
    }

    /// @dev Returns the Ethereum address of x·G using the ecrecover precompile.
    ///      ecrecover(h, v, r, s) = r⁻¹·(s·R − h·G). With R = G (r = Gx, v = 27),
    ///      h = 0 and s = x·Gx mod n, the result is x·G.
    function _mulG(uint256 x) private pure returns (address) {
        uint256 s = mulmod(x, GX, N);
        return ecrecover(bytes32(0), GV, bytes32(GX), bytes32(s));
    }

    function _onCurve(uint256 x, uint256 y) private pure returns (bool) {
        if (x >= P || y >= P) return false;
        uint256 lhs = mulmod(y, y, P);
        uint256 rhs = addmod(mulmod(mulmod(x, x, P), x, P), 7, P);
        return lhs == rhs;
    }
}
