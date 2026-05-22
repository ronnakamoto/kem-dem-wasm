// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {X25519KeyRegistry} from "../X25519KeyRegistry.sol";

/// ERC-1271 wallet that always accepts a signature. Used to test the
/// happy path of `registerFor` with a contract account.
contract AlwaysValid1271 {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0x1626ba7e;
    }
}

/// ERC-1271 wallet that returns 1 KiB of raw return data whose first
/// 32 bytes encode the magic value `bytes4(0x1626ba7e)` (left-aligned,
/// right-padded with zeros). The remainder is junk. The registry must
/// only inspect the first 32 bytes and ignore the rest (S4).
contract OversizedReturn1271 {
    function isValidSignature(bytes32, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        assembly {
            let buf := mload(0x40)
            // Encode bytes4(0x1626ba7e) in the high 4 bytes of the
            // first 32-byte word (this is how Solidity ABI-encodes a
            // bytes4 return value).
            mstore(
                buf,
                0x1626ba7e00000000000000000000000000000000000000000000000000000000
            )
            // Bytes 32..1024 are left zero (fresh memory). Return all
            // 1024 bytes, oversizing the declared return type.
            return(buf, 1024)
        }
    }
}

/// ERC-1271 wallet whose first 32 bytes of return data do NOT match
/// the magic value, but contain it later in the buffer. The registry
/// must reject this — only the first 32 bytes count.
contract DelayedMagicReturn1271 {
    function isValidSignature(bytes32, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        assembly {
            let buf := mload(0x40)
            // First 32 bytes: all 0xff (junk).
            mstore(
                buf,
                0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
            )
            // Bytes 32..64: the magic value. Registry must NOT find it here.
            mstore(
                add(buf, 32),
                0x1626ba7e00000000000000000000000000000000000000000000000000000000
            )
            return(buf, 1024)
        }
    }
}

/// ERC-1271 wallet that always rejects.
contract AlwaysReject1271 {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0xffffffff;
    }
}

contract X25519KeyRegistryTest is Test {
    X25519KeyRegistry internal registry;

    // EOA fixture (anvil's first default key)
    uint256 internal constant ALICE_PK =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    address internal alice;

    bytes32 internal constant PUBKEY_V1 =
        0x1111111111111111111111111111111111111111111111111111111111111111;
    bytes32 internal constant PUBKEY_V2 =
        0x2222222222222222222222222222222222222222222222222222222222222222;
    bytes32 internal constant PUBKEY_V3 =
        0x3333333333333333333333333333333333333333333333333333333333333333;

    function setUp() public {
        registry = new X25519KeyRegistry();
        alice = vm.addr(ALICE_PK);
    }

    // ─── S1: getLatest distinguishes "revoked latest" from "unknown" ──

    function test_GetLatest_RevertsWithUnknownVersion_WhenNeverRegistered() public {
        vm.expectRevert(X25519KeyRegistry.UnknownVersion.selector);
        registry.getLatest(alice);
    }

    function test_GetLatest_ReturnsLatest_AfterRegister() public {
        vm.prank(alice);
        registry.register(1, PUBKEY_V1);

        X25519KeyRegistry.Record memory r = registry.getLatest(alice);
        assertEq(r.pubkey, PUBKEY_V1);
        assertFalse(r.revoked);
    }

    function test_GetLatest_RevertsWithLatestRevoked_AfterRevokingLatest() public {
        vm.startPrank(alice);
        registry.register(1, PUBKEY_V1);
        registry.revoke(1);
        vm.stopPrank();

        vm.expectRevert(
            abi.encodeWithSelector(X25519KeyRegistry.LatestRevoked.selector, uint32(1))
        );
        registry.getLatest(alice);
    }

    function test_GetLatest_RecoversAfterRegisteringHigherVersion() public {
        vm.startPrank(alice);
        registry.register(1, PUBKEY_V1);
        registry.revoke(1);
        registry.register(2, PUBKEY_V2);
        vm.stopPrank();

        X25519KeyRegistry.Record memory r = registry.getLatest(alice);
        assertEq(r.pubkey, PUBKEY_V2);
    }

    // ─── S2: register is not monotonic — orphaned writes are allowed
    // but `latestVersion` is not rolled back. Document the behaviour. ──

    function test_Register_AllowsOutOfOrderVersions() public {
        vm.startPrank(alice);
        registry.register(10, PUBKEY_V1);
        registry.register(3, PUBKEY_V2); // orphaned: latest stays 10
        vm.stopPrank();

        assertEq(registry.latestVersion(alice), 10);
        X25519KeyRegistry.Record memory latest = registry.getLatest(alice);
        assertEq(latest.pubkey, PUBKEY_V1);

        // v=3 is still queryable directly
        X25519KeyRegistry.Record memory v3 = registry.get(alice, 3);
        assertEq(v3.pubkey, PUBKEY_V2);
    }

    function test_Register_RejectsRegisteringSameVersionTwice() public {
        vm.startPrank(alice);
        registry.register(1, PUBKEY_V1);
        vm.expectRevert(X25519KeyRegistry.VersionExists.selector);
        registry.register(1, PUBKEY_V2);
        vm.stopPrank();
    }

    function test_Register_RejectsRegisteringRevokedVersion() public {
        vm.startPrank(alice);
        registry.register(1, PUBKEY_V1);
        registry.revoke(1);
        vm.expectRevert(X25519KeyRegistry.VersionRevoked.selector);
        registry.register(1, PUBKEY_V2);
        vm.stopPrank();
    }

    function test_Register_RejectsEmptyKey() public {
        vm.prank(alice);
        vm.expectRevert(X25519KeyRegistry.EmptyKey.selector);
        registry.register(1, bytes32(0));
    }

    function test_Register_RejectsZeroVersion() public {
        vm.prank(alice);
        vm.expectRevert(X25519KeyRegistry.InvalidVersion.selector);
        registry.register(0, PUBKEY_V1);
    }

    // ─── S3: ECDSA r=0 / s=0 / s>HALF_N / wrong-length rejected ──

    function test_RegisterFor_RejectsZeroR() public {
        bytes memory sig = new bytes(65);
        // r = 0, s = 1, v = 27
        sig[63] = 0x01;
        sig[64] = 0x1b;

        vm.expectRevert(X25519KeyRegistry.InvalidSignature.selector);
        registry.registerFor(alice, 1, PUBKEY_V1, block.timestamp + 1 hours, sig);
    }

    function test_RegisterFor_RejectsZeroS() public {
        bytes memory sig = new bytes(65);
        // r = 1, s = 0, v = 27
        sig[31] = 0x01;
        sig[64] = 0x1b;

        vm.expectRevert(X25519KeyRegistry.InvalidSignature.selector);
        registry.registerFor(alice, 1, PUBKEY_V1, block.timestamp + 1 hours, sig);
    }

    function test_RegisterFor_RejectsHighS() public {
        // Build a valid low-s signature, then flip to high-s and
        // confirm the registry rejects it.
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce = registry.registrationNonce(alice);
        bytes32 digest = _eip712Digest(alice, 1, PUBKEY_V1, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, digest);

        // Flip to high-s.
        uint256 N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 highS = bytes32(N - uint256(s));
        uint8 flippedV = v == 27 ? 28 : 27;

        bytes memory sig = abi.encodePacked(r, highS, flippedV);
        vm.expectRevert(X25519KeyRegistry.InvalidSignature.selector);
        registry.registerFor(alice, 1, PUBKEY_V1, deadline, sig);
    }

    function test_RegisterFor_RejectsWrongLength() public {
        bytes memory sig = new bytes(64);
        vm.expectRevert(X25519KeyRegistry.InvalidSignature.selector);
        registry.registerFor(alice, 1, PUBKEY_V1, block.timestamp + 1 hours, sig);
    }

    function test_RegisterFor_AcceptsValidEoaSignature() public {
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce = registry.registrationNonce(alice);
        bytes32 digest = _eip712Digest(alice, 1, PUBKEY_V1, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, digest);

        bytes memory sig = abi.encodePacked(r, s, v);
        registry.registerFor(alice, 1, PUBKEY_V1, deadline, sig);

        X25519KeyRegistry.Record memory rec = registry.get(alice, 1);
        assertEq(rec.pubkey, PUBKEY_V1);
        assertEq(registry.registrationNonce(alice), nonce + 1);
    }

    function test_RegisterFor_RejectsReplayedSignature() public {
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce = registry.registrationNonce(alice);
        bytes32 digest = _eip712Digest(alice, 1, PUBKEY_V1, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        registry.registerFor(alice, 1, PUBKEY_V1, deadline, sig);

        // Same sig, same nonce → rejected on second call (also blocked
        // by VersionExists since the slot is taken).
        vm.expectRevert();
        registry.registerFor(alice, 1, PUBKEY_V2, deadline, sig);
    }

    function test_RegisterFor_RejectsExpiredDeadline() public {
        uint256 deadline = block.timestamp;
        bytes memory sig = new bytes(65);
        sig[31] = 0x01;
        sig[63] = 0x01;
        sig[64] = 0x1b;

        vm.warp(block.timestamp + 1);
        vm.expectRevert(X25519KeyRegistry.Expired.selector);
        registry.registerFor(alice, 1, PUBKEY_V1, deadline, sig);
    }

    function test_RegisterFor_RejectsZeroAccount() public {
        bytes memory sig = new bytes(65);
        sig[31] = 0x01;
        sig[63] = 0x01;
        sig[64] = 0x1b;

        vm.expectRevert(X25519KeyRegistry.InvalidAddress.selector);
        registry.registerFor(address(0), 1, PUBKEY_V1, block.timestamp + 1 hours, sig);
    }

    // ─── S4: ERC-1271 with oversized return data ──

    function test_RegisterFor_AcceptsValidErc1271Signature() public {
        AlwaysValid1271 wallet = new AlwaysValid1271();
        bytes memory sig = hex"deadbeef"; // contents irrelevant

        registry.registerFor(address(wallet), 1, PUBKEY_V1, block.timestamp + 1 hours, sig);

        X25519KeyRegistry.Record memory rec = registry.get(address(wallet), 1);
        assertEq(rec.pubkey, PUBKEY_V1);
    }

    function test_RegisterFor_RejectsErc1271WithWrongMagic() public {
        AlwaysReject1271 wallet = new AlwaysReject1271();
        bytes memory sig = hex"deadbeef";

        vm.expectRevert(X25519KeyRegistry.InvalidSignature.selector);
        registry.registerFor(address(wallet), 1, PUBKEY_V1, block.timestamp + 1 hours, sig);
    }

    function test_RegisterFor_AcceptsErc1271WithOversizedReturnData() public {
        // S4: a wallet that returns 1 KiB starting with the magic
        // value must still be accepted, since the registry reads only
        // the first 32 bytes (the bytes4 selector, left-padded).
        OversizedReturn1271 wallet = new OversizedReturn1271();
        bytes memory sig = hex"deadbeef";

        registry.registerFor(address(wallet), 1, PUBKEY_V1, block.timestamp + 1 hours, sig);

        X25519KeyRegistry.Record memory rec = registry.get(address(wallet), 1);
        assertEq(rec.pubkey, PUBKEY_V1);
    }

    function test_RegisterFor_RejectsErc1271WithDelayedMagic() public {
        // S4 (negative): the magic value appearing AFTER the first 32
        // bytes of return data must not be honoured. Only the first
        // word is decoded as bytes4.
        DelayedMagicReturn1271 wallet = new DelayedMagicReturn1271();
        bytes memory sig = hex"deadbeef";

        vm.expectRevert(X25519KeyRegistry.InvalidSignature.selector);
        registry.registerFor(address(wallet), 1, PUBKEY_V1, block.timestamp + 1 hours, sig);
    }

    // ─── Revocation ──

    function test_Revoke_RevertsForUnknownVersion() public {
        vm.prank(alice);
        vm.expectRevert(X25519KeyRegistry.UnknownVersion.selector);
        registry.revoke(1);
    }

    function test_Revoke_RevertsIfAlreadyRevoked() public {
        vm.startPrank(alice);
        registry.register(1, PUBKEY_V1);
        registry.revoke(1);
        vm.expectRevert(X25519KeyRegistry.VersionRevoked.selector);
        registry.revoke(1);
        vm.stopPrank();
    }

    function test_IsRegistered_FalseAfterRevoke() public {
        vm.startPrank(alice);
        registry.register(1, PUBKEY_V1);
        assertTrue(registry.isRegistered(alice, 1));
        registry.revoke(1);
        assertFalse(registry.isRegistered(alice, 1));
        vm.stopPrank();
    }

    // ─── Fork safety: domain separator recomputes on chain id change ──

    function test_DomainSeparator_RecomputesOnChainIdChange() public {
        bytes32 d0 = registry.DOMAIN_SEPARATOR();
        vm.chainId(424242);
        bytes32 d1 = registry.DOMAIN_SEPARATOR();
        assertTrue(d0 != d1, "domain separator must change with chain id (fork safety)");
    }

    // ─── EIP-712 digest builder, mirrors the contract internals ──

    function _eip712Digest(
        address account,
        uint32 version,
        bytes32 pubkey,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                registry.REGISTER_TYPEHASH(),
                account,
                version,
                pubkey,
                nonce,
                deadline
            )
        );
        return keccak256(
            abi.encodePacked("\x19\x01", registry.DOMAIN_SEPARATOR(), structHash)
        );
    }
}
