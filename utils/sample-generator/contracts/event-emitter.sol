pragma solidity >= 0.5.0;

contract EventEmitter {
    uint256 public count = 0;

    event release_requested(
        bytes32 indexed rskTxHash,
        bytes32 indexed btcTxHash,
        uint amount
    );

    event other_event(
        bytes32 indexed topic1,
        bytes32 indexed topic2,
        uint position
    );

    function generate(bytes32 rskTxHash, bytes32 btcTxHash, uint amount) public {
        count++;
        emit release_requested(rskTxHash, btcTxHash, amount);
    }

    function generate_with_extra_events(
        bytes32 rskTxHash, bytes32 btcTxHash, uint amount,
        uint total_events,
        uint release_requested_position) public {
        count++;
        for (uint i = 0; i < total_events; i++) {
            if (i == release_requested_position) {
                emit release_requested(rskTxHash, btcTxHash, amount);
            } else {
                emit other_event(rskTxHash, btcTxHash, i);
            }
        }
    }
}
