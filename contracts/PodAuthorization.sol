// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Hash-Based Ricardian Authorization for Solid Pods
/// @notice Manages granular consent using contractHash as central anchor

contract PodAuthorization {
    address public owner;

    struct Authorization {
        string appId;
        string appName;
        uint256 validUntil;
        bool granted;
    }

    struct AuthEvent {
        string action;
        string contractHash;
        uint256 timestamp;
        string appId;
        string appName;
    }

    // Core mapping: user => contractHash => Authorization
    mapping(address => mapping(string => Authorization)) public authorizations;

    // Consent history: user => AuthEvent[]
    mapping(address => AuthEvent[]) private userHistory;

    event AuthorizationUpdated(
        address indexed user,
        string action,
        string contractHash,
        uint256 timestamp
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can perform this action");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Grant access to a Ricardian contract
    function grantAuthorization(
        string calldata _contractHash,
        string calldata _appId,
        string calldata _appName,
        uint256 _validUntil
    ) external {
        require(_validUntil > block.timestamp, "Authorization must be in the future");

        authorizations[msg.sender][_contractHash] = Authorization({
            appId: _appId,
            appName: _appName,
            validUntil: _validUntil,
            granted: true
        });

        logAuthorizationInternal(msg.sender, "grant", _contractHash, _appId, _appName);
    }

    /// @notice Revoke access for a specific Ricardian contract
    function revokeAuthorization(string calldata _contractHash) external {
        Authorization memory auth = authorizations[msg.sender][_contractHash];
        require(auth.granted, "No active authorization");

        logAuthorizationInternal(msg.sender, "revoke", _contractHash, auth.appId, auth.appName);

        delete authorizations[msg.sender][_contractHash];
    }

    /// @notice Check if a user has valid authorization
    function isAuthorized(address _user, string calldata _contractHash) external view returns (bool) {
        Authorization memory auth = authorizations[_user][_contractHash];
        return auth.granted && block.timestamp <= auth.validUntil;
    }

    /// @notice View full metadata for a given contract
    function getAuthorizationDetails(address _user, string calldata _contractHash)
        external
        view
        returns (
            string memory appId,
            string memory appName,
            uint256 validUntil,
            bool granted
        )
    {
        Authorization memory auth = authorizations[_user][_contractHash];
        return (auth.appId, auth.appName, auth.validUntil, auth.granted);
    }

    /// @notice Retrieve full history of grant/revoke events
    function getUserHistory(address _user)
        external
        view
        returns (AuthEvent[] memory)
    {
        return userHistory[_user];
    }

    /// @dev Internal logging for all authorization changes
    function logAuthorizationInternal(
        address _user,
        string memory _action,
        string memory _contractHash,
        string memory _appId,
        string memory _appName
    ) internal {
        userHistory[_user].push(AuthEvent({
            action: _action,
            contractHash: _contractHash,
            timestamp: block.timestamp,
            appId: _appId,
            appName: _appName
        }));

        emit AuthorizationUpdated(_user, _action, _contractHash, block.timestamp);
    }
}