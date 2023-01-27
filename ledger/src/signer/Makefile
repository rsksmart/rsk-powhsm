# The MIT License (MIT)
#
# Copyright (c) 2021 RSK Labs Ltd
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

#*******************************************************************************
#   Ledger Nano S
#   (c) 2016 Ledger
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#*******************************************************************************

ifeq ($(BOLOS_SDK),)
$(error BOLOS_SDK is not set)
endif
include $(BOLOS_SDK)/Makefile.defines

# Main app configuration
APPNAME = "RSK Sign"
APPVERSION = 3
# No flags
APPFLAGS = 0x00
PROG = "app"

# Build configuration
APP_SOURCE_PATH += src ../common/src
SDK_SOURCE_PATH += lib_stusb lib_stusb_impl

DEFINES += APPVERSION=\"$(APPVERSION)\"

DEFINES += OS_IO_SEPROXYHAL IO_SEPROXYHAL_BUFFER_SIZE_B=128
DEFINES += HAVE_BAGL HAVE_SPRINTF
DEFINES += PRINTF\(...\)=

DEFINES += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=7 IO_HID_EP_LENGTH=64 HAVE_USB_APDU

# Compiler, assembler, and linker
CC := $(CLANGPATH)clang
CFLAGS += -O0 -I$(GCC_INCLUDE)
CFLAGS += -Werror

# Convert min required difficulty to what the compiler expects
ifneq ($(TARGET_DIFFICULTY),)
CONVERTED_MRD = $(shell python make-difficulty.py $(TARGET_DIFFICULTY))
$(info Building with min required difficulty set to "$(CONVERTED_MRD)")
CFLAGS += -DPARAM_MIN_REQUIRED_DIFFICULTY="$(CONVERTED_MRD)"
endif

# Convert checkpoint to what the compiler expects
ifneq ($(CHECKPOINT),)
CONVERTED_CHKP = $(shell python make-initial-block-hash.py $(CHECKPOINT))
$(info Building with checkpoint set to "$(CONVERTED_CHKP)")
CFLAGS += -DPARAM_INITIAL_BLOCK_HASH="$(CONVERTED_CHKP)"
endif

# Specify target network (i.e., REGTEST or TESTNET). Otherwise it defaults to MAINNET.
ifeq ($(NETWORK),REGTEST)
$(info Building for Regtest)
CFLAGS += -DREGTEST
endif

ifeq ($(NETWORK),TESTNET)
$(info Building for Testnet)
CFLAGS += -DTESTNET
endif

AS := $(GCCPATH)arm-none-eabi-gcc
AFLAGS +=

LD := $(GCCPATH)arm-none-eabi-gcc
LDFLAGS += -O3 -Os
LDLIBS += -lm -lgcc -lc

# Main rules
all: default icon.hex

icon.hex:
	python $(BOLOS_SDK)/icon.py 16 16 icon.gif hexbitmaponly > icon.hex

# *** Targets to load (aka deploy) and delete the app from the physical device
# *** Don't forget to build the app first!
.PHONY: load delete
load: bin/app.hex
	python -m ledgerblue.loadApp \
		--delete \
		--targetId $(TARGET_ID)  \
		--fileName bin/$(PROG).hex \
		--appFlags $(APPFLAGS) \
		--appName $(APPNAME) \
		--appVersion $(APPVERSION) \
		--icon `cat icon.hex` \
		--path ""

bin/app.hex:
	$(error "Build the app first!")

delete:
	python -m ledgerblue.deleteApp  \
		--targetId $(TARGET_ID)  \
		--appName $(APPNAME)

# Import generic rules from the SDK
include $(BOLOS_SDK)/Makefile.rules
