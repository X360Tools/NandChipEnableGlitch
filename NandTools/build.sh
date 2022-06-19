mkdir -p obj out
xenon-gcc -m64 -c -o obj/ldr.o ldr.S
xenon-gcc -n -T ldr.lds -nostdlib -n -m64 -Wl,--gc-sections -o obj/ldr.elf obj/ldr.o
xenon-objcopy -O binary obj/ldr.elf out/ldr.bin
g++ --std=c++17 ecc_unpack.cpp -lcrypto -o ecc_unpack
g++ --std=c++17 ecc_repack.cpp -lcrypto -o ecc_repack
mkdir CORONA_16MB
./ecc_unpack CORONA_16MB.ecc CORONA_16MB
cp external_reset_smc.bin CORONA_16MB/smc.bin
./ecc_repack CORONA_16MB

