#!/bin/bash

OutDir=$1

export UNAME_S=$(uname -s)
export UNAME_P=$(uname -m || uname -p)

AES=$(../Native/check_cpu.sh aes && echo -maes || echo)
SSE2=$(../Native/check_cpu.sh sse2 && echo -msse2 || echo)
SSE3=$(../Native/check_cpu.sh sse3 && echo -msse3 || echo)
SSSE3=$(../Native/check_cpu.sh ssse3 && echo -mssse3 || echo)
PCLMUL=$(../Native/check_cpu.sh pclmul && echo -mpclmul || echo)
AVX=$(../Native/check_cpu.sh avx && echo -mavx || echo)
AVX2=$(../Native/check_cpu.sh avx2 && echo -mavx2 || echo)
AVX512F=$(../Native/check_cpu.sh avx512f && echo -mavx512f || echo)

export CPU_FLAGS="$AES $SSE2 $SSE3 $SSSE3 $PCLMUL $AVX $AVX2 $AVX512F"

HAVE_AES=$(../Native/check_cpu.sh aes && echo -D__AES__ || echo)
HAVE_SSE2=$(../Native/check_cpu.sh sse2 && echo -DHAVE_SSE2 || echo)
HAVE_SSE3=$(../Native/check_cpu.sh sse3 && echo -DHAVE_SSE3 || echo)
HAVE_SSSE3=$(../Native/check_cpu.sh ssse3 && echo -DHAVE_SSSE3 || echo)
HAVE_PCLMUL=$(../Native/check_cpu.sh pclmul && echo -DHAVE_PCLMUL || echo)
HAVE_AVX=$(../Native/check_cpu.sh avx && echo -DHAVE_AVX || echo)
HAVE_AVX2=$(../Native/check_cpu.sh avx2 && echo -DHAVE_AVX2 || echo)
HAVE_AVX512F=$(../Native/check_cpu.sh avx512f && echo -DHAVE_AVX512F || echo)

export HAVE_FEATURE="$HAVE_AES $HAVE_SSE2 $HAVE_SSE3 $HAVE_SSSE3 $HAVE_PCLMUL $HAVE_AVX $HAVE_AVX2 $HAVE_AVX512F"

(cd ../Native/libmultihash && make clean && make) && mv ../Native/libmultihash/libmultihash.so "$OutDir"
(cd ../Native/libbeamhash && make clean && make) && mv ../Native/libbeamhash/libbeamhash.so "$OutDir"
(cd ../Native/libetchash && make clean && make) && mv ../Native/libetchash/libetchash.so "$OutDir"
(cd ../Native/libethhash && make clean && make) && mv ../Native/libethhash/libethhash.so "$OutDir"
(cd ../Native/libethhashb3 && make -j clean && make -j) && mv ../Native/libethhashb3/libethhashb3.so "$OutDir"
(cd ../Native/libubqhash && make clean && make) && mv ../Native/libubqhash/libubqhash.so "$OutDir"
(cd ../Native/libcryptonote && make clean && make) && mv ../Native/libcryptonote/libcryptonote.so "$OutDir"
(cd ../Native/libcryptonight && make clean && make) && mv ../Native/libcryptonight/libcryptonight.so "$OutDir"
(cd ../Native/libverushash && make clean && make) && mv ../Native/libverushash/libverushash.so "$OutDir"
(cd ../Native/libfiropow && make clean && make) && mv ../Native/libfiropow/libfiropow.so "$OutDir"
(cd ../Native/libkawpow && make clean && make) && mv ../Native/libkawpow/libkawpow.so "$OutDir"
(cd ../Native/libmeowpow && make clean && make) && mv ../Native/libmeowpow/libmeowpow.so "$OutDir"
(cd ../Native/libdero && make clean && make) && mv ../Native/libdero/libdero.so "$OutDir"

((cd /tmp && rm -rf secp256k1 && git clone https://github.com/bitcoin-ABC/secp256k1 && cd secp256k1 && git checkout 04fabb44590c10a19e35f044d11eb5058aac65b2 && mkdir build && cd build && cmake -GNinja .. -DCMAKE_C_FLAGS=-fPIC -DSECP256K1_ENABLE_MODULE_RECOVERY=OFF -DSECP256K1_ENABLE_COVERAGE=OFF -DSECP256K1_ENABLE_MODULE_SCHNORR=ON && ninja) && (cd ../Native/libnexapow && cp /tmp/secp256k1/build/libsecp256k1.a . && make clean && make) && mv ../Native/libnexapow/libnexapow.so "$OutDir")
((cd /tmp && rm -rf RandomX && git clone https://github.com/tevador/RandomX && cd RandomX && git checkout tags/v1.2.1 && mkdir build && cd build && cmake -DARCH=native .. && make) && (cd ../Native/librandomx && cp /tmp/RandomX/build/librandomx.a . && make clean && make) && mv ../Native/librandomx/librandomx.so "$OutDir")
((cd /tmp && rm -rf RandomARQ && git clone https://github.com/arqma/RandomARQ && cd RandomARQ && git checkout 3bcb6bafe63d70f8e6f78a0d431e71be2b638083 && mkdir build && cd build && cmake -DARCH=native .. && make) && (cd ../Native/librandomarq && cp /tmp/RandomARQ/build/librandomx.a . && make clean && make) && mv ../Native/librandomarq/librandomarq.so "$OutDir")
