CFLAGS += -g -Wall -c -fPIC -O2 -Wno-pointer-sign -Wno-char-subscripts -Wno-unused-variable -Wno-unused-function -Wno-strict-aliasing -Wno-discarded-qualifiers -Wno-unused-const-variable $(CPU_FLAGS) $(HAVE_FEATURE)
CXXFLAGS += -g -Wall -fPIC -fpermissive -O2 -funroll-loops -fomit-frame-pointer -Wno-char-subscripts -Wno-unused-variable -Wno-unused-function -Wno-strict-aliasing -Wno-sign-compare -std=c++11 $(CPU_FLAGS) $(HAVE_FEATURE)
LDFLAGS += -shared
TARGET = libbeamhash.so

OBJECTS = beam/core/difficulty.o beam/core/uintBig.o beam/utility/common.o crypto/blake/sse/blake2b.o crypto/beamHashIII.o crypto/equihashR.o support/cleanse.o arith_uint256.o beamhashverify.o exports.o random.o uint256.o util.o utilstrencodings.o

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

.PHONY: clean

clean:
	$(RM) $(TARGET) $(OBJECTS)
