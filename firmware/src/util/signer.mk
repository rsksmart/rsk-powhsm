SIGNER_FLAGS =

# Convert min required difficulty to what the compiler expects
ifneq ($(TARGET_DIFFICULTY),)
CONVERTED_MRD = $(shell python $(UTIL_DIR)/make-difficulty.py $(TARGET_DIFFICULTY))
$(info Building with min required difficulty set to "$(CONVERTED_MRD)")
SIGNER_FLAGS += -DPARAM_MIN_REQUIRED_DIFFICULTY="$(CONVERTED_MRD)"
endif

# Convert checkpoint to what the compiler expects
ifneq ($(CHECKPOINT),)
CONVERTED_CHKP = $(shell python $(UTIL_DIR)/make-initial-block-hash.py $(CHECKPOINT))
$(info Building with checkpoint set to "$(CONVERTED_CHKP)")
SIGNER_FLAGS += -DPARAM_INITIAL_BLOCK_HASH="$(CONVERTED_CHKP)"
endif

# Specify target network (i.e., REGTEST or TESTNET). Otherwise it defaults to MAINNET.
ifeq ($(NETWORK),REGTEST)
$(info Building for Regtest)
SIGNER_FLAGS += -DREGTEST
endif

ifeq ($(NETWORK),TESTNET)
$(info Building for Testnet)
SIGNER_FLAGS += -DTESTNET
endif

$(info $(SIGNER_FLAGS))