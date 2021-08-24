# HSM 2 sample proof generation tool

## Prerequisites

- NodeJS >= 12 (or NVM)
- JSON-RPC access to a regtest RSK node

## Setup

Before starting, in a console, run the following commands.

If using NVM, first run:

```
nvm use
```

If you get `N/A: version "N/A" is not yet installed.`, then run:

```
nvm install
nvm use
```

Then (or if NodeJS >= 12 was already installed), run:

```
npm install
```

Last, edit the `truffle-config.js` file, and replace the `networks.rsk` entry with your regtest RSK node's JSON-RPC endpoint information. Then, run:

```
npx truffle console --network rsk
```

If you get the following:

```
truffle(rsk)>
```

then the setup is done.

## Generating samples from the truffle console

Within the truffle console you opened in the previous step (`npx truffle console --network rsk`), issue the following commands:

```
truffle(rsk)> compile --all

truffle(rsk)> ee = await EventEmitter.new()        // (*)

truffle(rsk)> sg = require('./lib/sample-generator')

truffle(rsk)> generate = sg(web3, ee)

(*) If automine is not enabled, you should manually trigger a block mine in order to get the transaction mined.
```

Then, to generate a sample based on the `any-seed-that-you-want` seed (you can use any seed you want), run:

```
truffle(rsk)> sample = await generate('any-seed-that-you-want')   // (*)

(*) If automine is not enabled, you should manually trigger a block mine in order to get the transaction mined.
```

Once the transaction is mined, `sample` will contain the sample.

## Quick sample generation

In order to generate a simple, non-interactive sample, in the command line (outside of truffle), issue:

```
npx truffle exec ./generate.js --network rsk 'any-seed-that-you-want'
```

If automine is not enabled, make sure to mine a block when you see the following:

```
Deploying EventEmitter...
```

and then when you see

```
Generating sample with seed 'any-seed-that-you-want'...
```

The sampe will follow in JSON format.

## What each sample contains

Here is a sample generated with the quick tool (see the previous section):

```
{
  "params": {
    "rskTx": "0x3420f7de3d8943cdfab049406cbf711c32f7e25a41ab84b43f59707589320857",
    "btcTx": "0x9b806559b153f5ca5bd84d648845bd57294005d19684e74a6ead500ea5d72e54",
    "amount": "c2ebae116f3caeba86a"
  },
  "receipt": {
    "transactionHash": "0x112f61e57c48e06c473e2bd638b9565ac4001ce1791af2a211d5d124f6f582f0",
    "transactionIndex": 0,
    "blockHash": "0x8501488133096c03a20fef2f8b7cb47653735d4181bacce641b661d90d8ac048",
    "blockNumber": 28,
    "cumulativeGasUsed": 48738,
    "gasUsed": 48738,
    "contractAddress": null,
    "logs": [
      {
        "logIndex": 0,
        "blockNumber": 28,
        "blockHash": "0x8501488133096c03a20fef2f8b7cb47653735d4181bacce641b661d90d8ac048",
        "transactionHash": "0x112f61e57c48e06c473e2bd638b9565ac4001ce1791af2a211d5d124f6f582f0",
        "transactionIndex": 0,
        "address": "0xc53A82b9B7c9af4801c7d8EA531719E7657aFF3C",
        "id": "log_3820298b",
        "event": "release_requested",
        "args": {
          "0": "0x3420f7de3d8943cdfab049406cbf711c32f7e25a41ab84b43f59707589320857",
          "1": "0x9b806559b153f5ca5bd84d648845bd57294005d19684e74a6ead500ea5d72e54",
          "2": "c2ebae116f3caeba86a",
          "__length__": 3,
          "rskTxHash": "0x3420f7de3d8943cdfab049406cbf711c32f7e25a41ab84b43f59707589320857",
          "btcTxHash": "0x9b806559b153f5ca5bd84d648845bd57294005d19684e74a6ead500ea5d72e54",
          "amount": "c2ebae116f3caeba86a"
        }
      }
    ],
    "from": "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826",
    "to": "0xc53a82b9b7c9af4801c7d8ea531719e7657aff3c",
    "root": "0x01",
    "status": true,
    "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000008008000000000000000000000000008000000000000000000000000000000000400000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000008200000000000000000000000000000001000000000000000000000000000008000000000000080000000000000000000000000000000000000000000000000000000080",
    "rawLogs": [
      {
        "logIndex": 0,
        "blockNumber": 28,
        "blockHash": "0x8501488133096c03a20fef2f8b7cb47653735d4181bacce641b661d90d8ac048",
        "transactionHash": "0x112f61e57c48e06c473e2bd638b9565ac4001ce1791af2a211d5d124f6f582f0",
        "transactionIndex": 0,
        "address": "0xc53A82b9B7c9af4801c7d8EA531719E7657aFF3C",
        "data": "0x000000000000000000000000000000000000000000000c2ebae116f3caeba86a",
        "topics": [
          "0xae7243ebcf685651448802c66ee8d8aaade0e6ca554402ce24adbce5dae2e363",
          "0x3420f7de3d8943cdfab049406cbf711c32f7e25a41ab84b43f59707589320857",
          "0x9b806559b153f5ca5bd84d648845bd57294005d19684e74a6ead500ea5d72e54"
        ],
        "id": "log_3820298b"
      }
    ]
  },
  "rawReceipt": "0xf901aa0182be62b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008008000000000000000000000000008000000000000000000000000000000000400000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000008200000000000000000000000000000001000000000000000000000000000008000000000000080000000000000000000000000000000000000000000000000000000080f89df89b94c53a82b9b7c9af4801c7d8ea531719e7657aff3cf863a0ae7243ebcf685651448802c66ee8d8aaade0e6ca554402ce24adbce5dae2e363a03420f7de3d8943cdfab049406cbf711c32f7e25a41ab84b43f59707589320857a09b806559b153f5ca5bd84d648845bd57294005d19684e74a6ead500ea5d72e54a0000000000000000000000000000000000000000000000c2ebae116f3caeba86a82be6201",
  "rawBlock": "0xf90229a0769a7bacd13aa5cadb57108b9e57adab173acd376965e5d4ea4594bf8d6f7be6a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347945b2427729a74667f6cc9ece0b850004c1b75c636a03aaf995b45c4faea0c670bff0acf4edc4179a2da4acdf1d16cd4d209be653a5ea0241639f43265b53febb23bdc08f4042019b927f052ad8224d49c700d5e585046a00409d59b29550667fc218cd085073023f408199d0889b2e39df8391dbc32c705b9010000000000000000000000000000000000000000002000000000200000000000000000000000000000000000008008000000000000000000000000008000000000000000000000000000000000400000004000000001000000000000000002100000080000020000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000010000000000000000200000080000000100000000000000000000000000000000000001000008200020000000001000000000000018001000000000020000000000000200048100000000000080000000000000000000000000000000000000000000000000000000080011c840094786682be62845e28e71b8087037689ff8a90000080b850711101000000000000000000000000000000000000000000000000000000000000000000e1ae9fe20a970bcfaac28a165ba92c132904539a10254bf12930b2abfdf2a2041ae7285effff7f2157000000",
  "receiptsTrieProof": [
    "0x700600bf8c8d4169034986e1277f010f6cbc7d165c42678657211e447fd9b79c20f0c90001ad",
    "0x4f267006020d29ed637f007e72c240bc9d8519a62a6a7dce2a3c1644900a05d14a379eda360003aa26700600bf8c8d4169034986e1277f010f6cbc7d165c42678657211e447fd9b79c20f0c90001adfda305"
  ]
}
```

All of the `rskTx`, `btcTx` and `amount` underneath the `params` section are solely dependent upon the seed. That is, if the seed is the same, these parameters will be the same. They correspond to the RSK transaction hash, BTC transaction hash and release amount, respectively. The `receipt` field contains the transaction receipt as given by the RSK node when the transaction is mined. The `rawReceipt` contains the data given by the `rsk_getRawTransactionReceiptByHash` JSON-RPC method. The `rawBlock` contains the data given by the `rsk_getRawBlockHeaderByHash` JSON-RPC method. Finally, the `receiptsTrieProof` contains the nodes of the receipt inclusion proof as given by the JSON-RPC method `rsk_getTransactionReceiptNodesByHash`.
