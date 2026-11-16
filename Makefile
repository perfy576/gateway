.DEFAULT_GOAL := all
.DELETE_ON_ERROR:

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BUILD_DIR ?= $(ROOT)/build
DEPS_DIR ?= $(ROOT)/.deps
JWT_CPP_SRC ?= $(DEPS_DIR)/jwt-cpp
JWT_REVISION := e71e0c2d584baff06925bbb3aad683f677e4d498
JWT_READY := $(BUILD_DIR)/deps/jwt-cpp.ready
PREFIX ?= /usr/local
DESTDIR ?=
PKG_CONFIG ?= pkg-config
CXXFLAGS ?= -O3 -DNDEBUG
CFLAGS ?= -O3 -DNDEBUG

OPENSSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags openssl)
OPENSSL_LIBS := $(shell $(PKG_CONFIG) --libs openssl)
MARIADB_CFLAGS := $(shell $(PKG_CONFIG) --cflags libmariadb)
MARIADB_LIBS := $(shell $(PKG_CONFIG) --libs libmariadb)
APP_CPPFLAGS = $(CPPFLAGS) -Isrc -Iexamples -isystem $(JWT_CPP_SRC)/include $(OPENSSL_CFLAGS)
APP_CXXFLAGS = $(CXXFLAGS) -std=c++17 -pthread -Wall -Wextra -Wpedantic

include $(ROOT)/mk/workflow.mk

APP_OBJECTS := $(addprefix $(BUILD_DIR)/obj/,src/main.o src/db.o src/security.o src/protocol.o)
EXAMPLE_OBJECT := $(BUILD_DIR)/obj/examples/backend-verify.o
TEST_OBJECT := $(BUILD_DIR)/obj/tests/security.o
SECURITY_OBJECTS := $(BUILD_DIR)/obj/src/security.o $(BUILD_DIR)/obj/src/protocol.o
OBJECTS := $(APP_OBJECTS) $(EXAMPLE_OBJECT) $(TEST_OBJECT)

.PHONY: all deps examples test check install clean help
all: $(BUILD_DIR)/gateway
deps: $(JWT_READY) $(WORKFLOW_READY)
examples: $(BUILD_DIR)/backend-verify
test check: $(BUILD_DIR)/gateway-security-tests $(BUILD_DIR)/backend-verify
	$(BUILD_DIR)/gateway-security-tests

$(JWT_READY): $(ROOT)/tools/fetch-source.sh $(ROOT)/Makefile
	$(SHELL) $(ROOT)/tools/fetch-source.sh https://github.com/Thalhammer/jwt-cpp.git $(JWT_REVISION) $(JWT_CPP_SRC)
	mkdir -p $(@D)
	touch $@

$(BUILD_DIR)/obj/src/main.o: APP_CPPFLAGS += -isystem $(WORKFLOW_INCLUDE) $(MARIADB_CFLAGS)
$(BUILD_DIR)/obj/src/main.o: $(WORKFLOW_HEADERS_READY)
$(BUILD_DIR)/obj/src/db.o: APP_CPPFLAGS += $(MARIADB_CFLAGS)

$(BUILD_DIR)/obj/%.o: $(ROOT)/%.cpp $(ROOT)/Makefile $(JWT_READY)
	mkdir -p $(@D)
	$(CXX) $(APP_CPPFLAGS) $(APP_CXXFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/gateway: $(APP_OBJECTS) $(WORKFLOW_LIBRARY)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $(APP_OBJECTS) $(WORKFLOW_LIBRARY) $(MARIADB_LIBS) $(OPENSSL_LIBS) -pthread $(LDLIBS)

$(BUILD_DIR)/backend-verify: $(EXAMPLE_OBJECT) $(SECURITY_OBJECTS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(OPENSSL_LIBS) -pthread $(LDLIBS)

$(BUILD_DIR)/gateway-security-tests: $(TEST_OBJECT) $(SECURITY_OBJECTS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(OPENSSL_LIBS) -pthread $(LDLIBS)

install: all
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BUILD_DIR)/gateway $(DESTDIR)$(PREFIX)/bin/gateway

clean:
	$(RM) $(OBJECTS) $(OBJECTS:.o=.d) $(WORKFLOW_OBJECTS) $(WORKFLOW_OBJECTS:.o=.d)
	$(RM) $(BUILD_DIR)/gateway $(BUILD_DIR)/backend-verify $(BUILD_DIR)/gateway-security-tests $(WORKFLOW_LIBRARY)
	$(RM) $(JWT_READY) $(WORKFLOW_READY) $(WORKFLOW_HEADERS_READY)

help:
	@printf '%s\n' 'make -j2       Build the gateway and pinned dependencies' 'make test      Build and run security tests' 'make examples  Build the backend verifier example' 'make install   Install the binary; supports PREFIX and DESTDIR' 'make clean     Remove build products; retain downloaded sources' 'Overrides: BUILD_DIR DEPS_DIR WORKFLOW_SRC JWT_CPP_SRC CC CXX CPPFLAGS CFLAGS CXXFLAGS LDFLAGS LDLIBS'

-include $(OBJECTS:.o=.d) $(WORKFLOW_OBJECTS:.o=.d)
