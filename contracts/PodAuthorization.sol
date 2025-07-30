// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./AuthorizationHistory.sol";

/// @title Ricardian Authorization for Solid Pods
/// @notice Manages app-to-pod access using hashed Ricardian contracts
contract PodAuthorization {
    address public owner;

    struct Authorization {
        string appId;
        string contractHash; // SHA-256 hash of Ricardian contract
        uint256 validUntil;
        bool granted;
    }

    mapping(address => mapping(string => Authorization)) public authorizations;

    AuthorizationHistory public historyContract;

    event AuthorizationGranted(address indexed user, string appId, string contractHash, uint256 validUntil);
    event AuthorizationRevoked(address indexed user, string appId);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only admin can perform this action");
        _;
    }

    constructor(address _historyContractAddress) {
        owner = msg.sender;
        historyContract = AuthorizationHistory(_historyContractAddress);
    }

    /// @notice App grant access by submitting contract hash and expiry
    /// @param _appId Unique identifier of the app
    /// @param _contractHash Hash of the Ricardian contract (SHA-256)
    /// @param _validUntil Expiry timestamp of the authorization
    function grantAuthorization(string calldata _appId, string calldata _contractHash, uint256 _validUntil) external {
        require(_validUntil > block.timestamp, "Authorization must be in the future");
        authorizations[msg.sender][_appId] = Authorization(_appId, _contractHash, _validUntil, true);
        emit AuthorizationGranted(msg.sender, _appId, _contractHash, _validUntil);
        historyContract.logAuthorization(msg.sender, _appId, "grant", _contractHash, block.timestamp);
    }

    /// @notice User revokes access for a specific app
    function revokeAuthorization(string calldata _appId) external {
        require(authorizations[msg.sender][_appId].granted, "No active authorization for this app");
        delete authorizations[msg.sender][_appId];
        emit AuthorizationRevoked(msg.sender, _appId);
        historyContract.logAuthorization(msg.sender, _appId, "revoke", "", block.timestamp);
    }

    /// @notice Verifies if a user has valid authorization for a specific app
    /// @param _user Address of the user
    /// @param _appId Identifier of the app
    /// @return True if authorization is active and not expired
    function isAuthorized(address _user, string calldata _appId) external view returns (bool) {
        Authorization memory auth = authorizations[_user][_appId];
        return auth.granted && block.timestamp <= auth.validUntil;
    }

    /// @param _user Address of the user
    /// @param _appId Identifier of the app
    function getAuthorizationDetails(address _user, string calldata _appId) external view returns (
        string memory appId,
        string memory contractHash,
        uint256 validUntil,
        bool granted
    ) {
        Authorization memory auth = authorizations[_user][_appId];
        return (auth.appId, auth.contractHash, auth.validUntil, auth.granted);
    }

    // Optional: allow updating the history contract address securely
    function updateHistoryContract(address _newAddress) external onlyOwner {
        historyContract = AuthorizationHistory(_newAddress);
    }

}
