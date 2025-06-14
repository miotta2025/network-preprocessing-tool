# Directories
SOURCE_DIRECTORY = src
HEADER_DIRECTORY = include
OBJ_DIR = obj
BIN = nprint

# Compiler and flags
CXX = g++
CXXFLAGS = -Wall -Wextra -I$(HEADER_DIRECTORY) -I$(HEADER_DIRECTORY)/io -I$(HEADER_DIRECTORY)/packet -lpcap

SOURCE_FILES = $(wildcard $(SOURCE_DIRECTORY)/*.cpp) $(wildcard $(SOURCE_DIRECTORY)/*/*.cpp)
HEADER_FILES = $(wildcard $(HEADER_DIRECTORY)/*.hpp) $(wildcard $(SOURCE_DIRECTORY)/*/*.hpp)

OBJECT_FILES = $(patsubst %.cpp, $(OBJ_DIR)/%.o, \
                $(subst $(SOURCE_DIRECTORY)/, ,$(SOURCE_FILES)))

#default rule 
all: $(BIN)

$(BIN): $(OBJECT_FILES)
	$(CXX) $(OBJECT_FILES) -lpcap -o $@

$(OBJ_DIR)/%.o: $(SOURCE_DIRECTORY)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

