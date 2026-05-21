// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title  HPKE X25519 Encryption Key Registry
/// @notice One record per (account, version). EOAs self‑register via
///         `register`; contract / 4337 accounts may register via
///         `registerFor` using EIP‑712 typed‑data signatures.
///
/// @dev    Design decisions:
///         - `bytes32` for the pubkey: X25519 public keys are exactly 32 B.
///         - Per‑account `registrationNonce` makes `registerFor` signatures
///           single‑use, eliminating replay (incl. replay‑after‑revoke).
///         - EIP‑712 typed data so wallets actually agree to sign the
///           digest (raw `eth_sign` over an opaque hash is rejected by
///           every modern wallet UI).
///         - Low‑s normalisation on the ECDSA path (EIP‑2 style) so a
///           single signature has a single canonical form.
///         - `revoked` flag stored in the same struct slot as the
///           timestamp; revoked records cannot be re‑registered for the
///           same version (versions are append‑only forever).
///         - `latestVersion` is a single SLOAD lookup for senders.
///         - Contract is NOT upgradeable. New derivation schemes get a
///           new contract address; `SCHEMA` makes the wire format
///           self‑describing.
contract X25519KeyRegistry {
    // ─── Schema / domain ─────────────────────────────────────────

    /// keccak256("kem-dem-wasm/v1/x25519-pubkey")
    bytes32 public constant SCHEMA =
        keccak256("kem-dem-wasm/v1/x25519-pubkey");

    /// EIP‑712 type hash for the `Register` struct.
    bytes32 public constant REGISTER_TYPEHASH = keccak256(
        "Register(address account,uint32 version,bytes32 pubkey,uint256 nonce,uint256 deadline)"
    );

    /// Stored at construction so wallets show a stable domain.
    /// We re‑bind `chainid` defensively in case of a chain split — if
    /// the chain forks and the chainid changes, signatures from the
    /// pre‑fork chain are invalidated, which is the safe default.
    bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;
    uint256 private immutable _CACHED_CHAIN_ID;

    // ─── Storage ─────────────────────────────────────────────────

    /// One X25519 record per (account, version).
    /// Slot 0: pubkey (full 32 B)
    /// Slot 1: registeredAt (8 B) + revoked (1 B) — packed
    struct Record {
        bytes32 pubkey;
        uint64  registeredAt;
        bool    revoked;
    }

    /// account => version => record. `version` is also the mapping key
    /// so it does not need to live inside `Record`.
    mapping(address => mapping(uint32 => Record)) private _records;

    /// Latest *active* version per account (0 = no key registered).
    mapping(address => uint32) public latestVersion;

    /// Monotonic per‑account nonce consumed by `registerFor`.
    mapping(address => uint256) public registrationNonce;

    // ─── Events ──────────────────────────────────────────────────

    event KeyRegistered(
        address indexed account,
        uint32  indexed version,
        bytes32 pubkey,
        uint256 timestamp
    );

    event KeyRevoked(address indexed account, uint32 indexed version);

    // ─── Errors ──────────────────────────────────────────────────

    error EmptyKey();
    error InvalidVersion();
    error VersionExists();
    error VersionRevoked();
    error UnknownVersion();
    error NotOwner();
    error Expired();
    error InvalidAddress();
    error InvalidSignature();

    // ─── Constructor ─────────────────────────────────────────────

    constructor() {
        _CACHED_CHAIN_ID = block.chainid;
        _CACHED_DOMAIN_SEPARATOR = _buildDomainSeparator();
    }

    /// Returns the EIP‑712 domain separator, recomputing it if the
    /// chain id has changed since construction (fork safety).
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        if (block.chainid == _CACHED_CHAIN_ID) {
            return _CACHED_DOMAIN_SEPARATOR;
        }
        return _buildDomainSeparator();
    }

    function _buildDomainSeparator() private view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes("X25519KeyRegistry")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    // ─── EOA self‑registration ───────────────────────────────────

    /// Register an encryption key for `msg.sender`.
    /// @param version  Monotonically increasing version (start at 1).
    /// @param pubkey   32‑byte X25519 public key.
    function register(uint32 version, bytes32 pubkey) external {
        _write(msg.sender, version, pubkey);
    }

    // ─── Contract / 4337 meta‑tx registration ───────────────────

    /// Register a key on behalf of `account`. The signature MUST be an
    /// EIP‑712 typed signature over the `Register` struct, produced by
    /// the account (ECDSA for EOAs, ERC‑1271 for contract accounts).
    ///
    /// @param account   The account being registered.
    /// @param version   Monotonically increasing version.
    /// @param pubkey    32‑byte X25519 public key.
    /// @param deadline  Block timestamp after which the signature is invalid.
    /// @param sig       EIP‑712 signature.
    function registerFor(
        address account,
        uint32  version,
        bytes32 pubkey,
        uint256 deadline,
        bytes calldata sig
    ) external {
        if (account == address(0)) revert InvalidAddress();
        if (block.timestamp > deadline) revert Expired();

        uint256 nonce = registrationNonce[account];

        bytes32 structHash = keccak256(
            abi.encode(
                REGISTER_TYPEHASH,
                account,
                version,
                pubkey,
                nonce,
                deadline
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash)
        );

        if (!_isValidSignature(account, digest, sig)) revert InvalidSignature();

        // Consume the nonce *before* the write so a re‑entrant
        // callback (via ERC‑1271 staticcall — disallowed but defence
        // in depth) cannot land twice.
        unchecked { registrationNonce[account] = nonce + 1; }

        _write(account, version, pubkey);
    }

    // ─── Lookups ─────────────────────────────────────────────────

    /// Returns the record for the latest active version.
    /// Reverts if no key has been registered or the latest was revoked
    /// without a replacement.
    function getLatest(address account)
        external
        view
        returns (Record memory r)
    {
        uint32 v = latestVersion[account];
        if (v == 0) revert UnknownVersion();
        r = _records[account][v];
        if (r.registeredAt == 0 || r.revoked) revert UnknownVersion();
    }

    /// Returns the record for a specific version. May be a zero
    /// record (never registered) or a record with `revoked = true`.
    function get(address account, uint32 version)
        external
        view
        returns (Record memory)
    {
        return _records[account][version];
    }

    /// Cheap presence check that does not revert.
    function isRegistered(address account, uint32 version)
        external
        view
        returns (bool)
    {
        Record storage r = _records[account][version];
        return r.registeredAt != 0 && !r.revoked;
    }

    // ─── Revocation ──────────────────────────────────────────────

    /// Revoke a previously registered key. The version slot is
    /// permanently marked revoked and cannot be re‑registered — the
    /// caller must use a fresh version number to publish a new key.
    function revoke(uint32 version) external {
        Record storage r = _records[msg.sender][version];
        if (r.registeredAt == 0) revert UnknownVersion();
        if (r.revoked) revert VersionRevoked();

        r.revoked = true;
        emit KeyRevoked(msg.sender, version);
        // We intentionally do NOT roll back `latestVersion`: if the
        // user revokes the latest, `getLatest` will revert until they
        // register a higher version. Avoids unbounded backward scan.
    }

    // ─── Internal write ──────────────────────────────────────────

    function _write(address account, uint32 version, bytes32 pubkey) internal {
        if (version == 0) revert InvalidVersion();
        if (pubkey == bytes32(0)) revert EmptyKey();

        Record storage existing = _records[account][version];
        if (existing.registeredAt != 0) {
            // Either active (VersionExists) or revoked (permanently dead).
            if (existing.revoked) revert VersionRevoked();
            revert VersionExists();
        }

        _records[account][version] = Record({
            pubkey: pubkey,
            registeredAt: uint64(block.timestamp),
            revoked: false
        });

        if (version > latestVersion[account]) {
            latestVersion[account] = version;
        }

        emit KeyRegistered(account, version, pubkey, block.timestamp);
    }

    // ─── Signature validation ────────────────────────────────────

    /// secp256k1 order n / 2. Reject `s > HALF_N` per EIP‑2 to kill
    /// malleability.
    uint256 private constant HALF_N =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /// Validates a signature against `signer`.
    /// - For EOAs: ECDSA `ecrecover` with low‑s enforcement.
    /// - For contracts: ERC‑1271 `isValidSignature(bytes32,bytes)`.
    function _isValidSignature(
        address signer,
        bytes32 digest,
        bytes calldata sig
    ) internal view returns (bool) {
        if (signer.code.length > 0) {
            // Contract account → ERC‑1271
            (bool ok, bytes memory result) = signer.staticcall(
                abi.encodeWithSelector(
                    0x1626ba7e, // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
                    digest,
                    sig
                )
            );
            return ok
                && result.length >= 32
                && abi.decode(result, (bytes4)) == 0x1626ba7e;
        }

        // EOA → ECDSA. Enforce 65‑byte form and low‑s.
        if (sig.length != 65) return false;

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (uint256(s) > HALF_N) return false;            // EIP‑2 malleability guard
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return false;

        address recovered = ecrecover(digest, v, r, s);
        return recovered != address(0) && recovered == signer;
    }
}
