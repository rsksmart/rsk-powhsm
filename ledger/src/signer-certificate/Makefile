#*******************************************************************************
#   RSK Signer app for Ledger Nano S
#   (c) 2020 RSK
#
#*******************************************************************************

ifeq ($(BOLOS_SDK),)
$(error BOLOS_SDK is not set)
endif
include $(BOLOS_SDK)/Makefile.defines

# Main app configuration
APPNAME = "RSK Certif"
APPVERSION = 1.0.0
APP_LOAD_PARAMS = --appFlags 0x00 $(COMMON_LOAD_PARAMS)
PROG = "app"

# Build configuration
APP_SOURCE_PATH += src
SDK_SOURCE_PATH += lib_stusb lib_stusb_impl

DEFINES += APPVERSION=\"$(APPVERSION)\"

DEFINES += OS_IO_SEPROXYHAL IO_SEPROXYHAL_BUFFER_SIZE_B=128
DEFINES += HAVE_BAGL HAVE_SPRINTF
DEFINES += PRINTF\(...\)=

DEFINES += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=7 IO_HID_EP_LENGTH=64 HAVE_USB_APDU

# Compiler, assembler, and linker
CC := $(CLANGPATH)clang
CFLAGS += -O0 -I$(GCC_INCLUDE)

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
		--appFlags 0x0 \
		--appName $(APPNAME) \
		--appVersion $(APPVERSION) \
		--icon `cat icon.hex` \
		--path "" \
		$(PARAM_SCP)

bin/app.hex:
	$(error "Build the app first!")

delete:
	python -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

# Import generic rules from the SDK
include $(BOLOS_SDK)/Makefile.rules
