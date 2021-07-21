// srlp: Streaming RLP parser.
// Parse RLP contents with no recursion and small memory footprint.
//
// Usage:
// Call rlp_start to initialize the parser with callbacks for:
//  - Byte array started
//  - Byte array chuk received
//  - Byte array finished
//  - List started
//  - List finished
//
// Then feed chunks of RLP with rlp_consume. This function
// will process them and call your callbacks accordingly.

#ifndef __SRLP
#define __SRLP

#include <stddef.h>
#include <stdint.h>

// Constant for values returned by rlp_consume
#define RLP_OK 0
#define RLP_STACK_OVERFLOW (-1)
#define RLP_STACK_UNDERFLOW (-2)
#define RLP_TOO_LONG (-3)

// Max RLP buffer size and stack depth
#define RLP_BUFFER_SIZE 80

// Define your own MAX_RLP_CTX_DEPTH to override the default value
#ifndef MAX_RLP_CTX_DEPTH
#define MAX_RLP_CTX_DEPTH 3
#endif

// Type synonyms for callbacks
typedef void (*rlp_start_cb_t)(const uint16_t size);
typedef void (*rlp_end_cb_t)(void);
typedef void (*rlp_chunk_cb_t)(const uint8_t* chunk, const size_t chunk_size);

// Struct grouping all callbacks
typedef struct {
    rlp_start_cb_t bytearray_start;
    rlp_chunk_cb_t bytearray_chunk;
    rlp_end_cb_t bytearray_end;
    rlp_start_cb_t list_start;
    rlp_end_cb_t list_end;
} rlp_callbacks_t;

/*
 * Initialize the parser.
 *
 * @arg[in] cbs struct holding callbacks to be called by the parser
 */
void rlp_start(const rlp_callbacks_t* cbs);

/*
 * Consume a chunk of bytes.
 *
 * @arg[in] buf: buffer holdoing bytes to be consumed
 * @arg[in] len: number of bytes to consume in buffer
 *
 * @return
 *    RLP_OK if bytes were consumed successfully
 *    RLP_TOO_LONG if len greater than RLP_BUFFER_SIZE
 *    RLP_STACK_OVERFLOW if list nesting level is greater than MAX_RLP_CTX_DEPTH
 *    RLP_STACK_UNDERFLOW if RLP to parse is ill-formed (e.g., [[a])
 */
int rlp_consume(uint8_t* buf, const uint8_t len);

// Does the given single byte string has an RLP prefix?
#define HAS_RLP_PREFIX(first_str_byte) ((first_str_byte) > 0x7f)

/*
 * Guess the length in bytes of the RLP prefix for str of the given size.
 *
 * NOTE: This guessing because for single byte strings we need the str
 * value to determine accurately. For single byte strings, this method
 * always return one. It's up to the caller to take this into account.
 *
 * @arg[in] str_size string size
 */
uint8_t guess_rlp_str_prefix_size(uint16_t str_size);

#endif
