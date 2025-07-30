// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AuthorizationHistory {
    struct AuthEvent {
        string action;
        string contractHash;
        uint256 timestamp;
    }

    mapping(address => mapping(string => AuthEvent[])) private userAppHistory;

    address public podAuthorizationContract;

    event AuthorizationLogged(
        address indexed user,
        string appId,
        string action,
        string contractHash,
        uint256 timestamp
    );

    modifier onlyPodAuthorization() {
        require(msg.sender == podAuthorizationContract, "Unauthorized caller");
        _;
    }

    constructor(address _podAuthorizationContract) {
        podAuthorizationContract = _podAuthorizationContract;
    }

    function logAuthorization(
        address _user,
        string memory _appId,
        string memory _action,
        string memory _contractHash,
        uint256 _timestamp
    ) external onlyPodAuthorization {
        AuthEvent memory newEvent = AuthEvent({
            action: _action,
            contractHash: _contractHash,
            timestamp: _timestamp
        });

        userAppHistory[_user][_appId].push(newEvent);

        emit AuthorizationLogged(
            _user,
            _appId,
            _action,
            _contractHash,
            _timestamp
        );
    }

    function getUserAppHistory(address _user, string memory _appId)
        external
        view
        returns (AuthEvent[] memory)
    {
        return userAppHistory[_user][_appId];
    }

    function getEventCount(address _user, string memory _appId)
        external
        view
        returns (uint256)
    {
        return userAppHistory[_user][_appId].length;
    }
}

