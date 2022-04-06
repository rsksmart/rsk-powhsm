/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2021 RSK Labs Ltd
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

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
