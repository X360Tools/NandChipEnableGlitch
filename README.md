# NandChipEnableGlitch

This repository contians proof of concept glitch triggered on nand chip enable.

This results in glitching without using post codes.

The glitch used works on any CB_A, even on retail once.

Making of DGX was an epic fail, showing TX had no idea how the RGH actually works.

NandTools folder contains the code needed to make an ecc image that can boot with a single glitch with retail CB_A.bin

PicoRGH folder contains code for the RP2040 to use it as a glitcher.

**This POC only works on the Corona boards.**

How RGH works is very simple: If we send a 4 to 60 ns long pulse (aka. glitch) to the `CPU_RST_N` line the GCPU will not reset, instead it will continue the execution in a corrupted state. If we glitch in an `mr` (move register) instruction at the right time the `destination` will contain `0` instead of the content of the `source` register.

To mitigate RGH attacks Microsoft did some changes how CB works.
- They added a loader, CB_A and renamed CB to CB_B.
- The CB_A loads, decrypts and verifies CB_B.
- The decryption key contains 0x10 bytes of the console unique fuse, if its a retail, not mfg (manufacturing) CB_A, meaning every console uses a different key to decrypt the CB_B.

With more technical detail, CB usually runs at 0x8000020000010000.
Since now that they put CB_A in place of CB once CB_A starts to execute it relocates itself to 0x800002000001C000, to give space for CB_B at 0x8000020000010000.
This means CB_B MUST NOT BE BIGGER then C000 bytes.

Also there is no cache, write or data execution protections.

This is reverse engineered source code of the interesting part happens, this is the same on retail and mfg CB_A:
```
void load_sb_b(_BLDR_2BL *sb_a_bldr@<r2>, _BLDR_2BL *sb_b_nand_offset@<r3>, _BLDR_2BL *sb_b_load_addr@<r4>)
{
	[...]

	uint64_t sb_b_nand_offset = bldr->qwSbFlashAddr + sb_b_nand_offset;

	[...]

	WRITE_POST(sb_a_bldr->qwPostOutAddr, 0xD3);
	memcpy16(sb_b_load_addr, sb_b_sb_b_nand_offset, 1);

	WRITE_POST(sb_a_bldr->qwPostOutAddr, 0xD4);
	uint32_t size = sb_b_load_addr->Size;
	uint32_t entry = sb_b_load_addr->Entry;
	if ((size - 0x3C0) > 0xBC40 ||
		sb_b_load_addr->Magic != sb_a_bldr->Magic ||
		entry & 0x300000000i64 ||
		entry < 0x3C0 ||
		entry >= (size & 0xFFFFFFFC) ||
		!check_address(sb_b_nand_offset, size) )
	{
		WRITE_POST(sb_a_bldr->qwPostOutAddr, 0xF1);
		PANIC();
	}	
	uint64_t padded_size = (size + 0xF) & 0xFFFFFFF0;

	WRITE_POST(sb_a_bldr->qwPostOutAddr, 0xD5);
	uint64_t load_size = padded_size - 0x10;
	memcpy16(sb_b_load_addr + 0x10, sb_b_sb_b_nand_offset + 0x10, load_size >> 4);

	WRITE_POST(sb_a_bldr->qwPostOutAddr, 0xD6);
	
	[...]
}
```
The important parts is this line: `uint64_t load_size = padded_size - 0x10;`
- In assembly it looks like that: `mr r11, r27`; `clrrwi r27, r11, 4`
- Here if we glitch the cpu will execute this instead: `uint64_t load_size = 0 - 0x10;`
- Since load_size is unsigned, this will result in load_size = 0xFFFFFFFFFFFFFFF0.
- When memcpy16 tries to load this much it will overwrite itself.

How do I now that we are at `load_size`?
- You can look for 0xD5 post code and trigger on that.
- You can count chip enable pulses and trigger on that. (This is what this code does.)

Here is how the attack works:
- On the nand we put CB_A, after that a decrypted, patched CB_B, then the compiled `ldr.S`.
- The bootrom loads CB_A to 0x8000020000010000, verifies it and jumps to it.
- CB_A relocates to 0x800002000001C000.
- We glitch load_size.
- memcpy16 starts to load `ldr.S`, that it thinks is encrypted CB_B.
- It reads too much and overwrites itself.
- ldr.S starts to execute and jumps back to the CB_B.
- The console boots up a modded OS.
