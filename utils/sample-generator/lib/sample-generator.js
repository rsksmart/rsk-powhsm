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

const init = function(web3) {
    if (web3.rskm == null || web3.rskm.getTransactionReceiptNodesByHash == null) {
        web3.extend({
            property: 'rskm',
            methods: [({
                name: 'getTransactionReceiptNodesByHash',
                call: 'rsk_getTransactionReceiptNodesByHash',
                params: 2
            })]
        });
    }

    if (web3.rskm == null || web3.rskm.getRawTransactionReceiptByHash == null) {
        web3.extend({
            property: 'rskm',
            methods: [({
                name: 'getRawTransactionReceiptByHash',
                call: 'rsk_getRawTransactionReceiptByHash',
                params: 1
            })]
        });
    }

    if (web3.rskm == null || web3.rskm.getRawBlockHeaderByHash == null) {
        web3.extend({
            property: 'rskm',
            methods: [({
                name: 'getRawBlockHeaderByHash',
                call: 'rsk_getRawBlockHeaderByHash',
                params: 1
            })]
        });
    }
}

const generate = function(web3, eventEmitter) {
    init(web3);

    const keccak256 = web3.utils.keccak256.bind(web3.utils);

    const getRskTx = (seed) => keccak256(`rsk-tx-${seed}`);

    const getBtcTx = (seed) => keccak256(`btc-tx-${seed}`);

    const getAmount = (seed) => web3.utils.toBN(keccak256(`amount-${seed}`).substr(0, 22));

    return async (seed, total_events, release_requested_position, btcTx) => {
        const result = {
            params: {
                rskTx: getRskTx(seed),
                btcTx: btcTx || getBtcTx(seed),
                amount: getAmount(seed)
            }
        };

        if (total_events == null || total_events === 1) {
            txReceipt = await eventEmitter.generate(
                result.params.rskTx,
                result.params.btcTx,
                result.params.amount
            );
        } else {
            txReceipt = await eventEmitter.generate_with_extra_events(
                result.params.rskTx,
                result.params.btcTx,
                result.params.amount,
                total_events,
                release_requested_position
            );
        }

        result.receipt = txReceipt.receipt;

        result.rawReceipt = await web3.rskm.getRawTransactionReceiptByHash(result.receipt.transactionHash);

        result.rawBlock = await web3.rskm.getRawBlockHeaderByHash(result.receipt.blockHash);

        result.receiptsTrieProof = await web3.rskm.getTransactionReceiptNodesByHash(result.receipt.blockHash, result.receipt.transactionHash);

        return result;
    };
}

module.exports = generate;
