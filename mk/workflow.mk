# Workflow's upstream make entry wraps a generator; compile the pinned Linux sources directly.
WORKFLOW_SRC ?= $(DEPS_DIR)/workflow
WORKFLOW_REVISION := 0f1bbcee057f7549b524ed2f89874e74c95551e1
WORKFLOW_READY := $(BUILD_DIR)/deps/workflow.ready
WORKFLOW_INCLUDE := $(BUILD_DIR)/workflow/include
WORKFLOW_HEADERS_READY := $(BUILD_DIR)/workflow/headers.ready
WORKFLOW_LIBRARY := $(BUILD_DIR)/workflow/libworkflow.a

WORKFLOW_C_FILES := kernel/mpoller.c kernel/poller.c kernel/rbtree.c kernel/msgqueue.c kernel/thrdpool.c \
 util/json_parser.c protocol/dns_parser.c protocol/http_parser.c protocol/mysql_stream.c \
 protocol/mysql_parser.c protocol/mysql_byteorder.c protocol/redis_parser.c
WORKFLOW_CXX_FILES := kernel/IOService_linux.cc kernel/CommRequest.cc kernel/CommScheduler.cc \
 kernel/Communicator.cc kernel/Executor.cc kernel/SubTask.cc util/EncodeStream.cc util/StringUtil.cc \
 util/URIParser.cc manager/DnsCache.cc manager/RouteManager.cc manager/WFGlobal.cc manager/UpstreamManager.cc \
 protocol/PackageWrapper.cc protocol/SSLWrapper.cc protocol/DnsMessage.cc protocol/DnsUtil.cc \
 protocol/HttpMessage.cc protocol/HttpUtil.cc protocol/TLVMessage.cc protocol/MySQLMessage.cc \
 protocol/MySQLResult.cc protocol/MySQLUtil.cc protocol/RedisMessage.cc factory/WFGraphTask.cc \
 factory/DnsTaskImpl.cc factory/WFTaskFactory.cc factory/Workflow.cc factory/HttpTaskImpl.cc \
 factory/WFResourcePool.cc factory/WFMessageQueue.cc factory/FileTaskImpl.cc factory/MySQLTaskImpl.cc \
 factory/RedisTaskImpl.cc nameservice/WFNameService.cc nameservice/WFDnsResolver.cc \
 nameservice/WFServiceGovernance.cc nameservice/UpstreamPolicies.cc server/WFServer.cc \
 server/WFMySQLServer.cc client/WFDnsClient.cc client/WFHttpChunkedClient.cc client/WFRedisSubscriber.cc \
 client/WFMySQLConnection.cc client/WFConsulClient.cc
WORKFLOW_SOURCES := $(addprefix $(WORKFLOW_SRC)/src/,$(WORKFLOW_C_FILES) $(WORKFLOW_CXX_FILES))
WORKFLOW_OBJECTS := $(addprefix $(BUILD_DIR)/workflow/obj/,$(WORKFLOW_C_FILES:.c=.o) $(WORKFLOW_CXX_FILES:.cc=.o))
WORKFLOW_CPPFLAGS = $(CPPFLAGS) -I$(WORKFLOW_INCLUDE)/workflow $(OPENSSL_CFLAGS)

$(WORKFLOW_READY): $(ROOT)/tools/fetch-source.sh $(ROOT)/mk/workflow.mk
	$(SHELL) $(ROOT)/tools/fetch-source.sh https://github.com/sogou/workflow.git $(WORKFLOW_REVISION) $(WORKFLOW_SRC)
	mkdir -p $(@D)
	touch $@

# Explicit source targets let a clean checkout fetch sources before resolving object prerequisites.
$(WORKFLOW_SOURCES): | $(WORKFLOW_READY)
	@test -f $@

$(WORKFLOW_HEADERS_READY): $(WORKFLOW_READY) $(wildcard $(WORKFLOW_SRC)/src/*/*.h $(WORKFLOW_SRC)/src/*/*.inl)
	mkdir -p $(WORKFLOW_INCLUDE)/workflow
	find $(WORKFLOW_SRC)/src -type f \( -name '*.h' -o -name '*.inl' \) -exec cp -t $(WORKFLOW_INCLUDE)/workflow {} +
	touch $@

$(BUILD_DIR)/workflow/obj/%.o: $(WORKFLOW_SRC)/src/%.c $(ROOT)/mk/workflow.mk $(WORKFLOW_HEADERS_READY)
	mkdir -p $(@D)
	$(CC) $(WORKFLOW_CPPFLAGS) $(CFLAGS) -std=gnu90 -fPIC -pipe -pthread -MMD -MP -c $< -o $@

$(BUILD_DIR)/workflow/obj/%.o: $(WORKFLOW_SRC)/src/%.cc $(ROOT)/mk/workflow.mk $(WORKFLOW_HEADERS_READY)
	mkdir -p $(@D)
	$(CXX) $(WORKFLOW_CPPFLAGS) $(CXXFLAGS) -std=c++11 -fPIC -pipe -pthread -fno-exceptions -MMD -MP -c $< -o $@

$(WORKFLOW_LIBRARY): $(WORKFLOW_OBJECTS)
	$(AR) rcs $@ $^
