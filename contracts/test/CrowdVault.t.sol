// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {CrowdVault} from "../src/CrowdVault.sol";
import {CrowdVaultFactory} from "../src/CrowdVaultFactory.sol";

contract Reenterer {
    CrowdVault public vault;
    uint256 public hits;

    constructor(CrowdVault v) {
        vault = v;
    }

    function fund() external payable {
        vault.contribute{value: msg.value}();
    }

    function pull() external {
        vault.withdraw();
    }

    receive() external payable {
        hits++;
        if (hits < 3) {
            try vault.withdraw() {} catch {}
        }
    }
}

contract ToggleRecipient {
    bool public accept = true;

    function setAccept(bool a) external {
        accept = a;
    }

    receive() external payable {
        require(accept, "no");
    }
}

contract NoReceive {}

contract CrowdVaultTest is Test {
    CrowdVaultFactory factory;
    CrowdVault vault;
    address payable recipient = payable(makeAddr("recipient"));
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    uint256 constant SECRET = 0xA11CE5EC2E7;
    uint256 constant THRESHOLD = 10 ether;
    uint256 constant WINDOW = 2 days;

    function _key() internal returns (uint256, uint256) {
        Vm.Wallet memory w = vm.createWallet(SECRET);
        return (w.publicKeyX, w.publicKeyY);
    }

    function _create(address payable to, uint256 threshold, uint256 window) internal returns (CrowdVault) {
        (uint256 kx, uint256 ky) = _key();
        return factory.create{value: 1}(to, threshold, window, kx, ky);
    }

    function setUp() public {
        vm.warp(1_700_000_000);
        factory = new CrowdVaultFactory();
        vault = _create(recipient, THRESHOLD, WINDOW);
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
    }

    function _lock() internal {
        vm.prank(alice);
        vault.contribute{value: 4 ether}();
        vm.prank(bob);
        vault.contribute{value: 7 ether}();
    }

    // ------------------------------------------------------------ configuration

    function test_factoryRecordsGenuineVaults() public {
        assertTrue(factory.isVault(address(vault)));
        (uint256 kx, uint256 ky) = _key();
        CrowdVault direct = new CrowdVault{value: 1}(recipient, THRESHOLD, WINDOW, kx, ky);
        assertFalse(factory.isVault(address(direct)));
    }

    function test_recipientReceivesTheProbe() public view {
        assertEq(recipient.balance, 1);
        assertEq(address(vault).balance, 0);
    }

    function test_rejectsRecipientThatCannotTakeEth() public {
        NoReceive nr = new NoReceive();
        vm.expectRevert(CrowdVault.RecipientCheckFailed.selector);
        _create(payable(address(nr)), THRESHOLD, WINDOW);
    }

    function test_requiresTheProbeValue() public {
        (uint256 kx, uint256 ky) = _key();
        vm.expectRevert(CrowdVault.RecipientCheckFailed.selector);
        factory.create(recipient, THRESHOLD, WINDOW, kx, ky);
    }

    function test_claimWindowIsCapped() public {
        _create(recipient, THRESHOLD, 30 days);
        vm.expectRevert(CrowdVault.BadConfig.selector);
        _create(recipient, THRESHOLD, 30 days + 1);
        vm.expectRevert(CrowdVault.BadConfig.selector);
        _create(recipient, THRESHOLD, 0);
    }

    function test_rejectsOffCurveKey() public {
        vm.expectRevert(CrowdVault.KeyNotOnCurve.selector);
        factory.create{value: 1}(recipient, 1, 1, 1, 1);
    }

    // ------------------------------------------------------------ key check

    function test_keyCheck_acceptsSecret() public view {
        assertTrue(vault.isCampaignSecret(SECRET));
    }

    function test_keyCheck_rejectsOthers() public view {
        assertFalse(vault.isCampaignSecret(SECRET + 1));
        assertFalse(vault.isCampaignSecret(0));
        assertFalse(vault.isCampaignSecret(type(uint256).max));
    }

    function testFuzz_keyCheck_matchesVmAddr(uint256 x) public {
        x = bound(x, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        Vm.Wallet memory w = vm.createWallet(x);
        CrowdVault v = factory.create{value: 1}(recipient, 1, 1, w.publicKeyX, w.publicKeyY);
        assertTrue(v.isCampaignSecret(x));
        assertEq(v.keyAddress(), w.addr);
    }

    // ------------------------------------------------------------ open phase

    function test_contributeAndWithdraw() public {
        vm.prank(alice);
        vault.contribute{value: 3 ether}();
        assertEq(vault.contributionOf(alice), 3 ether);
        assertEq(vault.totalContributed(), 3 ether);
        vm.prank(alice);
        vault.withdraw();
        assertEq(vault.contributionOf(alice), 0);
        assertEq(vault.totalContributed(), 0);
        assertEq(alice.balance, 100 ether);
    }

    function test_receiveCountsAsContribution() public {
        vm.prank(alice);
        (bool ok,) = address(vault).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(vault.contributionOf(alice), 1 ether);
    }

    function test_cannotWithdrawTwice() public {
        vm.startPrank(alice);
        vault.contribute{value: 1 ether}();
        vault.withdraw();
        vm.expectRevert(CrowdVault.NothingToWithdraw.selector);
        vault.withdraw();
        vm.stopPrank();
    }

    // ------------------------------------------------------------ locking

    function test_crossingThresholdLocksInSameTx() public {
        _lock();
        assertEq(uint8(vault.phase()), uint8(CrowdVault.Phase.Locked));
        assertEq(vault.lockedAt(), block.timestamp);
        assertEq(vault.deadline(), block.timestamp + WINDOW);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CrowdVault.WrongPhase.selector, CrowdVault.Phase.Locked));
        vault.withdraw();

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(CrowdVault.WrongPhase.selector, CrowdVault.Phase.Locked));
        vault.contribute{value: 1 ether}();
    }

    // ------------------------------------------------------------ claim

    function test_claimPaysRecipientAndRevealsKey() public {
        _lock();
        vm.warp(block.timestamp + 1 hours);
        uint256 before = recipient.balance;

        vm.expectEmit(true, true, true, true);
        emit CrowdVault.Claimed(SECRET, address(this), 11 ether);
        vault.claim(SECRET);

        assertEq(recipient.balance - before, 11 ether);
        assertEq(vault.releasedAmount(), 11 ether);
        assertEq(vault.revealedKey(), SECRET);
        assertEq(uint8(vault.phase()), uint8(CrowdVault.Phase.Claimed));
        assertEq(address(vault).balance, 0);
    }

    function test_claimRejectsWrongKey() public {
        _lock();
        vm.expectRevert(CrowdVault.InvalidKey.selector);
        vault.claim(SECRET + 1);
    }

    function test_claimRejectedWhileOpen() public {
        vm.expectRevert(abi.encodeWithSelector(CrowdVault.WrongPhase.selector, CrowdVault.Phase.Open));
        vault.claim(SECRET);
    }

    function test_claimOnlyOnce() public {
        _lock();
        vault.claim(SECRET);
        vm.expectRevert(abi.encodeWithSelector(CrowdVault.WrongPhase.selector, CrowdVault.Phase.Claimed));
        vault.claim(SECRET);
    }

    function test_claimAtLastSecondOfWindow() public {
        _lock();
        vm.warp(vault.deadline());
        vault.claim(SECRET);
        assertEq(vault.releasedAmount(), 11 ether);
    }

    function test_frontRunnerStillPaysRecipient() public {
        _lock();
        address mev = makeAddr("mev");
        uint256 before = recipient.balance;
        vm.prank(mev);
        vault.claim(SECRET);
        assertEq(recipient.balance - before, 11 ether);
        assertEq(mev.balance, 0);
    }

    function test_forcedEthIsSweptToRecipient() public {
        _lock();
        vm.deal(address(vault), address(vault).balance + 3 ether); // as if force-sent
        uint256 before = recipient.balance;
        vault.claim(SECRET);
        assertEq(recipient.balance - before, 14 ether);
        assertEq(vault.releasedAmount(), 14 ether);
    }

    // ------------------------------------------------------------ expiry

    function test_expiryUnfreezesWithdrawals() public {
        _lock();
        vm.warp(vault.deadline() + 1);
        assertEq(uint8(vault.phase()), uint8(CrowdVault.Phase.Expired));

        vm.expectRevert(abi.encodeWithSelector(CrowdVault.WrongPhase.selector, CrowdVault.Phase.Expired));
        vault.claim(SECRET);

        vm.prank(alice);
        vault.withdraw();
        vm.prank(bob);
        vault.withdraw();
        assertEq(alice.balance, 100 ether);
        assertEq(bob.balance, 100 ether);
        assertEq(address(vault).balance, 0);
    }

    function test_noContributionsAfterExpiry() public {
        _lock();
        vm.warp(vault.deadline() + 1);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CrowdVault.WrongPhase.selector, CrowdVault.Phase.Expired));
        vault.contribute{value: 1 ether}();
    }

    // ------------------------------------------------------------ safety

    function test_reentrantWithdrawGetsNothingExtra() public {
        Reenterer r = new Reenterer(vault);
        r.fund{value: 2 ether}();
        vm.prank(alice);
        vault.contribute{value: 3 ether}();
        r.pull();
        assertEq(address(r).balance, 2 ether);
        assertEq(address(vault).balance, 3 ether);
        assertEq(vault.totalContributed(), 3 ether);
    }

    function test_recipientThatLaterRejectsCanPullLater() public {
        ToggleRecipient tr = new ToggleRecipient();
        CrowdVault v = _create(payable(address(tr)), 1 ether, WINDOW);
        vm.prank(alice);
        v.contribute{value: 2 ether}();

        tr.setAccept(false);
        v.claim(SECRET); // push fails, claim still stands
        assertTrue(v.claimed());
        assertEq(v.pendingPayout(), 2 ether);

        tr.setAccept(true);
        v.releasePayout();
        assertEq(address(tr).balance, 2 ether + 1);
        assertEq(v.pendingPayout(), 0);
    }

    function testFuzz_accountingNeverExceedsDeposits(uint96 a, uint96 b) public {
        vm.assume(a > 0 && b > 0);
        vm.deal(alice, a);
        vm.deal(bob, b);
        vm.prank(alice);
        vault.contribute{value: a}();
        if (vault.phase() == CrowdVault.Phase.Open) {
            vm.prank(bob);
            vault.contribute{value: b}();
        }
        assertEq(vault.totalContributed(), address(vault).balance);
        assertEq(vault.totalContributed(), vault.contributionOf(alice) + vault.contributionOf(bob));
    }
}
