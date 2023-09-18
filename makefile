ALIF_ROOTDIR=$(PWD)
ALIF_IDIR=$(ALIF_ROOTDIR)/include
ALIF_HEADERS:=$(shell find $(ALIF_IDIR) -name '*.h')

DEBUG=1

SDE_BUILD_KIT := $(ALIF_ROOTDIR)/sde
PIN_ROOT ?= $(ALIF_ROOTDIR)/sde/pinkit
SDE_ROOT := $(PIN_ROOT)/sde-example
PINPLAY_ROOT := $(PIN_ROOT)/pinplay
CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config


include $(CONFIG_ROOT)/makefile.config
include makefile.rules
include $(TOOLS_ROOT)/Config/makefile.default.rules