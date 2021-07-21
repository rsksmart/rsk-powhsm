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
