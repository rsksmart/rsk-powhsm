# powHSM blockchain bookkeeping

## Abstract

This document describes the means by which a powHSM stores and updates a partial RSK blockchain state. It also depicts the process by which it can use this state to check whether a given block header is part of the blockchain.

## Specification

### Notation

For simplicity, throughout this document the `==` and `=` symbols have `C` semantics, i.e., `==` denotes the equality operator and `=` denotes the assignment operation.

### HSM state

An *initialized* powHSM device must store the following state information in non-volatile memory. We call this blockchain state `blockchain_state` collectively.

- `best_block` (32 bytes - byte array): The current known best block with sufficient confirmations.
- `newest_valid_block` (32 bytes - byte array): The newest valid block known, regardless of confirmations.
- `ancestor_block` (32 bytes - byte array): The current inclusion process' proved ancestor block.
- `ancestor_receipts_root` (32 bytes - byte array): The current inclusion process' proved ancestor block's receipts root.

Additionally, a powHSM device must store the following mid-state information about the blockchain state, which needn't necessarily be kept in non-volatile memory. We call this transitional information `blockchain_state.updating` collectively. The `.` (dot) notation in variable names below is just a way of grouping related variables together.

- `updating.in_progress` (1 byte - boolean).
- `updating.already_validated` (1 byte - boolean).
- `updating.next_expected_block` (32 bytes - byte array): The current update process' next expected block hash.
- `updating.total_difficulty` (36 bytes - unsigned integer): The current update process' total cumulative difficulty.
- `updating.found_best_block` (1 byte - boolean): Whether the current update process has found a new best block.
- `updating.best_block` (32 bytes - byte array): The current update process' new best block hash.
- `updating.newest_valid_block` (32 bytes - byte array): The current update process' newest valid block hash.

The total amount of information needed to represent an instance of `blockchain_state` is thus 263 bytes, of which only 128 bytes are to be mandatorily stored in non-volatile memory. It is very important to note that any optimizations with respect to the representation and storage of these values can be done as long as the underlying semantics are not jeopardized. For example, saving 2 bytes (for a total of 261 bytes instead of 263) is possible if a single flag-like byte is used for the boolean state variables.

At any point in time, `best_block` is the hash of the currently best known and sufficiently confirmed block by the powHSM device. This "sufficiently confirmed" condition implies an underlying assumption that such block will always be part of the main chain.

The `newest_valid_block` is used for optimization in terms of Proof Of Work validation, i.e., avoiding checking a block header twice.

The `updating.*` variables are used as mid-state for the blockchain updating routine.

At any point in time, the `ancestor_block` is the hash of any ancestor block to `best_block` that was proved to be in the blockchain by the inclusion verification process depicted further down in this document; and `ancestor_receipts_root` is the receipts trie root of that same block.

### Initialization

An *uninitialized* powHSM device must hold the following values for each of the fields of the `blockchain_state`:

- `best_block`: `00...00` (zeroes).
- `newest_valid_block`: `00...00` (zeroes).
- `ancestor_block`: `00...00` (zeroes).
- `ancestor_receipts_root`: `00...00` (zeroes).
- `updating.in_progress`: `false`.
- `updating.already_validated`: `false`.
- `updating.next_expected_block`: `00...00` (zeroes).
- `updating.total_difficulty`: `0`.
- `updating.found_best_block`: `false`.
- `updating.best_block`: `00..00` (zeroes).
- `updating.newest_valid_block`: `00..00` (zeroes).

When transitioning to the *initialized* state, it must set its `best_block` and `newest_valid_block` values to a predefined hash that will correspond to a well-known block hash in the RSK mainnet (also testnet or devnet, depending on the case). These values must be hardcoded into the device's signing firmware. The `updating.` variables must remain unchanged after initialization.

### Updating

In order to update the `blockchain_state` of an *initialized* powHSM device, we define the operations `advanceBlockchain` and `resetAdvanceBlockchain`.

#### Context and preliminaries

The following constants are assumed to be predefined (and hardcoded into the physical device's firmware):

- `MINIMUM_CUMULATIVE_DIFFICULTY`: The minimum cumulative block difficulty to consider a block sufficiently confirmed.
- `MAXIMUM_BLOCK_DIFFICULTY`: The maximum allowed difficulty for any given block.

The following functions are assumed to exist:

- `hash`: Given a block header, it computes its hash.
- `pow_valid`: Given a block header, it returns true iif it has a valid PoW.

Given a current powHSM state where `best_block` corresponds to block `B_best`, `newest_valid_block` corresponds to block `B_newest` (such that `B_newest.number` >= `B_best.number`) and we know `n` blocks `B_0...B_(n-1)` with brothers `Brs_0...Brs_(n-1)`(\*\*) such that `hash(B_best) == B_0.parent_hash` and for each `0 <= i < (n-1)`, `hash(B_i) == B_(i+1).parent_hash` (i.e., the `n` blocks are consecutive, starting with the block that follows `B_best`) and there exists a `0 < k < n` such that `sum_from_k_to_(n-1)(B_j.total_difficulty) >= MINIMUM_CUMULATIVE_DIFFICULTY` (i.e., the last `n-k` blocks have a brother-inclusive cumulative difficulty that is at least `MINIMUM_CUMULATIVE_DIFFICULTY`), we can update the HSM's `best_block` and `newest_valid_block` to correspond to `hash(B_(k-1))` and `hash(B_(n-1))` respectively by invoking `advanceBlockchain` an arbitrary number of times such that, in newest-to-oldest order and without repeating any blocks, we end up communicating all of `B_0...B_(n-1)` and brothers `Brs_0...Brs_(n-1)`. It is paramount to notice that for any block `B_i` with `0 <= i < n`, `B_i.total_difficulty` denotes the sum of block `B_i`'s individual _capped_ difficulty (\*\*\*) plus the individual _capped_ difficulty of each of its brothers (i.e., `min(B_i.difficulty, MAXIMUM_BLOCK_DIFFICULTY) + sum_from_0_to_(#Brs_i)(min(Brs_i_j.difficulty, MAXIMUM_BLOCK_DIFFICULTY))`). It is important to mention that the choice of brothers to send for each block is entirely up to the caller. The more brothers sent for each block, the less total blocks that need to be sent in order to advance the blockchain.

(\*\*) For each block `B_i` with `0 <= i < n`, `Brs_i` is a (possibly empty) set of (distinct) brothers of `B_i`. We say that a Block `B_p` is a brother of block `B_q` iff:
- `B_p.parent_hash == B_q.parent_hash` and,
- `pow_valid(B_p) == true` and,
- `hash(B_p) <> hash(B_q)`
(\*\*\*) For any given block, its _capped_ difficulty is the minimum between the block difficulty itself and the `MAXIMUM_BLOCK_DIFFICULTY` constant defined above.

We define a single invocation of `advanceBlockchain` as follows:

#### Input

The following input must be provided:

- `blocks`: array of `m` instances of a `BlockHeader`, with `0 < m <= n`. Each `BlockHeader` is the binary serialization of a block header as defined by the RSK protocol (it *must* include the bitcoin merged mining header, the bitcoin coinbase transaction and the bitcoin merged mining merkle proof). This `blocks` array is indexed from `0` to `m-1` and blocks must be ordered from newest to oldest, i.e. `blocks[0].parent_hash == hash(blocks[1]); blocks[1].parent_hash == hash(blocks[2]); ...; blocks[m-2].parent_hash == hash(blocks[m-1])`. This order is not assumed, but validated within the operation. Blocks must also be valid, i.e., `pow_valid(blocks[i]) == true for 0 < i < m`. This is also validated within the operation.
- `brothers`: array of `m` arrays of `0` to `10` instances of a `BlockHeader`, with `0 < m <= n`. Each `BlockHeader` is the same serialization as defined for the `blocks` elements. For each `0 <= i < n`, with `p` being the length of `brothers[i]`, it must be the case that for every `0 <= j < p`, `blocks[i].parent_hash == brothers[i][j].parent_hash` and `pow_valid(brothers[i][j]) == true` and `hash(blocks[i]) <> hash(brothers[i][j])` and `j < (p-1) => hash(brothers[i][j]) < hash(brothers[i][j+1])`. These conditions are not assumed, but validated within the operation.

Also, it must be the case (although it is also not assumed and therefore validated) that:

- `blockchain_state.updating.in_progress == false` or,
- `blockchain_state.updating.in_progress == true` and `hash(blocks[0]) == blockchain_state.updating.next_expected_block`

i.e., between invocations, the order of blocks is kept as newest-to-oldest (the first block in a subsequent invocation must correspond to the previous invocation's last block's parent hash).

Last but not least, _in the last invocation of a single advance operation_, it must also be the case (this is also validated before updating the state) that `blocks[m-1].parent_hash == blockchain_state.best_block`, i.e., the last given block header's parent hash must correspond to the best block stored in the current HSM state.

#### Algorithm and output

The following is pseudocode (simile python) for what is the algorithm to be applied in order to update the HSM state.

```
// Check chaining with previous invocation if there's an update in progress
if blockchain_state.updating.in_progress and hash(blocks[0]) != blockchain_state.updating.next_expected_block:
    resetAdvanceBlockchain()
    return -201 // Chaining mismatch w.r.t. previous invocation

// Start a new update if an update process is not already ongoing
if not blockchain_state.updating.in_progress:
    blockchain_state.updating.newest_valid_block = hash(blocks[0])
    blockchain_state.updating.in_progress = true

for i in 0..(m-1) step 1:
    if i < m-1 and blocks[i].parent_hash != hash(blocks[i+1]):
        resetAdvanceBlockchain()
        return -201 // Chaining mismatch

    if hash(blocks[i]) == blockchain_state.newest_valid_block:
        blockchain_state.updating.already_validated = true

    // If we are on (or past) the newest block we already validated, it
    // means that we only need to check correct block chaining,
    // since the PoW validations have succeeded in the past.
    if not blockchain_state.updating.already_validated:
        if not pow_valid(blocks[i]):
            resetAdvanceBlockchain()
            return -202 // PoW invalid

    if not blockchain_state.updating.found_best_block:
        blockchain_state.updating.total_difficulty += min(blocks[i].difficulty, MAXIMUM_BLOCK_DIFFICULTY)

        // Take into account the difficulty of this block's brothers
        if not blockchain_state.updating.found_best_block and len(brothers[i]) > 0:
            for j in range(len(brothers[i])):
                if brothers[i][j].parent_hash != blocks[i].parent_hash:
                    resetAdvanceBlockchain()
                    return -205 // Brother is not a brother of block

                if hash(brothers[i][j]) == hash(blocks[i])
                    resetAdvanceBlockchain()
                    return -205 // Cannot use block as a brother

                if j > 0 and hash(brothers[i][j]) <= hash(brothers[i][j-1]):
                    resetAdvanceBlockchain()
                    return -205 // Brothers must be sorted by hash

                if not pow_valid(brothers[i][j]):
                    resetAdvanceBlockchain()
                    return -205 // Invalid brother

                blockchain_state.updating.total_difficulty += min(brothers[i][j].difficulty, MAXIMUM_BLOCK_DIFFICULTY)

        if blockchain_state.updating.total_difficulty >= MINIMUM_CUMULATIVE_DIFFICULTY:
            blockchain_state.updating.found_best_block = true
            blockchain_state.updating.best_block = hash(blocks[i])

    // Have we reached the current best block with a valid chain?
    // Update the best confirmed block and newest valid block in the HSM state
    if blockchain_state.updating.found_best_block and blocks[i].parent_hash == blockchain_state.best_block:
        blockchain_state.best_block = blockchain_state.updating.best_block
        blockchain_state.newest_valid_block = blockchain_state.updating.newest_valid_block
        resetAdvanceBlockchain()
        return 0 // Success

// If we get to this point, then we haven't yet reached the current best block.
// Update the oldest block within the process and ask for more blocks.
blockchain_state.updating.next_expected_block = blocks[m-1].parent_hash

return 1 // Partial success, need more blocks
```

We define the operation (and also function used in the algorithm above) `resetAdvanceBlockchain` as follows:

```
blockchain_state.updating.in_progress = false
blockchain_state.updating.already_validated = false
blockchain_state.updating.found_best_block = false
blockchain_state.updating.total_difficulty = 0
blockchain_state.updating.next_expected_block = 00...00 (zeroes) (*)
blockchain_state.updating.best_block =  00..00 (zeroes) (*)
blockchain_state.updating.newest_valid_block = 00..00 (zeroes) (*)
return 0 // Success

// (*) This does not actually need to be done,
// except for end-user clarity purposes.
```

#### Output

This operation can either succeed, partially succeed (meaning it needs a further invocation), or fail. This is signalled by an integer. The possible values are:

- `0`: Success. State updated.
- `1`: Partial success. Need the next blocks.
- `-201`: Chaining mismatch.
- `-202`: PoW validation failed.
- `-204`: Invalid input blocks.
- `-205`: Invalid input brothers.

## Updating the known ancestor block

Given a state of the HSM, say `best_block` and `ancestor_block` corresponding to block headers `A` and `B`, and given block header `C` such that it is an ancestor of either `A` or `B` (or both), it is possible to update the `ancestor_block` (and the corresponding `ancestor_receipts_root`) so that it contains the hash of block `C` (and the receipts trie root of block `C`, resp.) using the following chaining verification algorithm. The algorithm requires as input all the block headers between `A` and `C` -- or between `B` and `C` --, inclusively. Let these blocks be provided as input in an array `blocks` of size `m` indexed from `0` to `m-1`. As with the previous algorithm (update of the HSM state), the blocks must be provided in newest-to-oldest order. The operation either succeeds or fails. In case of success, the `ancestor_block` and `ancestor_receipts_root` portion of the blockchain state is updated to contain the hash and receipts trie root of block `C`, respectively. In case of failure, the state remains unaltered. Note that if there are too many blocks between `A` and `C` so that it is impossible to send all blocks at once, one can iteratively use this process to eventually reach block `C` -- that is, use `ancestor_block` as a checkpoint towards `C`.

### Algorithm

The following is also pseudocode (simile python). As with the blockchain update process, the `hash` function is also assumed to be defined and available here.

```
if m < 1:
    return -204 // Invalid input blocks

declare tip = hash(blocks[0])

if tip != blockchain_state.ancestor_block and tip != blockchain_state.best_block:
    return -203 // Tip mismatch

# Note that if m == 1, then this isn't executed at all
for i in 0..(m-2) step 1:
    if blocks[i].parent_hash != hash(blocks[i+1]):
        return -201 // Chaining mismatch

blockchain_state.ancestor_block = hash(blocks[m-1])
blockchain_state.ancestor_receipts_root = blocks[m-1].receipts_trie_root

return 0 // Success
```

### Output

This operation can either succeed or fail. This is signalled by an integer. The possible values are:

- `0`: Success. State updated.
- `-201`: Chaining mismatch.
- `-203`: Tip mismatch.
- `-204`: Invalid or not enough input blocks.

## Proving transaction receipt inclusion

At any point in time, the only block that is considered to be included in the blockchain by the HSM and that also records its trie receipts root is `ancestor_block` (with its corresponding `ancestor_receipts_root`). The trie receipts root can be used to prove the inclusion of any transaction receipt within that block by means of a partial trie that successfully reduces the receipt hash to the root. In case one wishes to prove the inclusion of a transaction within a different block, it _must_ be done by means of first updating the `ancestor_block` with the previously described algorithm and then using that state as a proof of the aforementioned inclusion. So, for example, if one wanted to prove a certain fact of the blockchain dependent on a specific transaction receipt being included in block `B`, one would have to first update `ancestor_block` and `ancestor_receipts_root` to correspond to the hash and trie receipts root of block `B` and then use that as _proof_ of that block being part of the blockchain and thus of that particular transaction receipt being also a part of the blockchain.

## Implementation considerations

The implementation must take into account the limited resources available on the actual hardware, and thus implement the described algorithms as a set of request-response incremental operations without compromising the integrity of the update processes. For example, to process just a single block, many request-response operations might be needed, and that would correspond to a single iteration in either of the above algorithms.

## Miscellaneous

The terms *initialized* and *uninitialized* describe two possible states of a powHSM device. These possible states and the transition between them are out of the scope of this document, excepting the `blockchain_state` update that occurs when the device transitions from the *uninitialized* to the *initialized* state (see the corresponding section above for details).
