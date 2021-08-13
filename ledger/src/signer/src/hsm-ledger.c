#include "os.h"
#include "hsm.h"

void hsm_ledger_main_loop() {
    volatile unsigned int rx = 0;
    unsigned int tx = 0;

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;) {
        BEGIN_TRY {
            TRY {
                // ensure no race in catch_other if io_exchange throws
                // an error
                rx = tx;
                tx = 0; 
                rx = io_exchange(CHANNEL_APDU, rx);

                tx = hsm_process_apdu(rx);
                THROW(0x9000);
            }
            CATCH_OTHER(e) {
                tx = hsm_process_exception(e, tx);
            }
            FINALLY {
            }
        }
        END_TRY;
    }
}