CXX ?= g++
CXXFLAGS ?= -std=c++20 -Wall -Wextra -Werror -O2 -ffile-prefix-map=$(CURDIR)=.
INCLUDES = -Iinclude

SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin
TEST_DIR = tests

SRCS = $(SRC_DIR)/vma_scanner.cpp \
       $(SRC_DIR)/proc_auditor.cpp \
       $(SRC_DIR)/rootkit_hunter.cpp \
       $(SRC_DIR)/sarif_exporter.cpp \
       $(SRC_DIR)/engine.cpp

OBJS = $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(SRCS))
MAIN_OBJ = $(BUILD_DIR)/main.o

TARGET = $(BIN_DIR)/aegis
TEST_TARGET = $(BIN_DIR)/test_runner

.PHONY: all aegis clean test audit

all: $(TARGET)

aegis: $(TARGET)

$(TARGET): $(OBJS) $(MAIN_OBJ) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $^ -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

$(BUILD_DIR)/main.o: $(SRC_DIR)/main.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

$(TEST_TARGET): $(OBJS) $(TEST_DIR)/test_aegis.cpp | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $^ -o $@

test: $(TEST_TARGET)
	@echo "[test] Executing Aegis automated test suite..."
	@./$(TEST_TARGET)

audit:
	@bash scripts/security-audit.sh

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
