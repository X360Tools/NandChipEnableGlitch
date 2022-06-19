# NandChipEnableGlitch

This repository contians proof of concept glitch triggered on nand chip enable.
This results in glitching without using post codes.
The glitch used works on any CB_A, even on retail once.
Making of DGX was an epic fail, showing TX had no idea how the RGH accually works.
NandTools folder contains the code needed to make an ecc image that can boot with a single glitch with retail CB_A.bin
PicoRGH folder contains code for the RP2040 to use it as a glitcher.
This POC only works on the Corona boards.
