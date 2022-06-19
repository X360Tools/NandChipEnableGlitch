#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "big.h"

#include <openssl/hmac.h>
#include <openssl/rc4.h>

static uint8_t SB_KEY_SEED[] = { 0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7, 0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA };
uint8_t smc_key[] = { 0x42, 0x75, 0x4e, 0x79 };
uint8_t nonce[] = { 0x2d, 0x87, 0x58, 0x61, 0x4f, 0x10, 0x63, 0xa1, 0x82, 0x7c, 0x24, 0x22, 0xad, 0x0d, 0x84, 0x42 };

#pragma pack(push, 1)
struct BLDR
{
	big_uint16_t Magic;
	big_uint16_t Build;
	big_uint16_t Qfe;
	big_uint16_t Flags;
	big_uint32_t Entry;
	big_uint32_t Size;
};

struct _BLDR_FLASH : BLDR
{
	char achCopyright[64];
	uint8_t abReserved[16];
	big_uint32_t dwKeyVaultSize; // 0x4000
	big_uint32_t dwSysUpdateAddr;
	big_uint16_t wSysUpdateCount;
	big_uint16_t wKeyVaultVersion;
	big_uint32_t dwKeyVaultAddr; // 0x4000
	big_uint32_t dwFileSystemAddr;
	big_uint32_t dwSmcConfigAddr;
	big_uint32_t dwSmcBootSize; // 0x3000
	big_uint32_t dwSmcBootAddr; // 0x1000
};

struct _BLDR_2BL : BLDR
{
	uint8_t abNonce[16];
};
#pragma pack(pop)

int XeCryptHmacSha(const void *key, int key_len, const uint8_t *data0, size_t data0len, const uint8_t *data1, size_t data1len, const uint8_t *data2, size_t data2len, uint8_t *hmac)
{
	HMAC_CTX *ctx = HMAC_CTX_new();

	int ret = HMAC_Init_ex(ctx, key, key_len, EVP_sha1(), NULL);
	if (ret < 0)
		return ret;

	if (data0len)
	{
		ret = HMAC_Update(ctx, data0, data0len);
		if (ret < 0)
			return ret;
	}

	if (data1len)
	{
		ret = HMAC_Update(ctx, data1, data1len);
		if (ret < 0)
			return ret;
	}

	if (data2len)
	{
		ret = HMAC_Update(ctx, data2, data2len);
		if (ret < 0)
			return ret;
	}

	unsigned int hmaclen = 20;
	ret = HMAC_Final(ctx, hmac, &hmaclen);
	if (ret < 0)
		return ret;

	HMAC_CTX_free(ctx);
	
	return hmaclen;
}

std::string readfile(std::string file)
{
	std::string data;
	FILE *f = fopen(file.c_str(), "rb");
	fseek(f, 0, SEEK_END);
	data.resize(ftell(f));
	fseek(f, 0, SEEK_SET);
	fread(data.data(), 1, data.size(), f);
	fclose(f);
	return data;
}

int main(int argc, char ** argv)
{
	std::string smc = readfile(std::string(argv[1]) + "/smc.bin");
	std::string kv = readfile(std::string(argv[1]) + "/kv.bin");
	std::string sb = readfile(std::string(argv[1]) + "/cb_a.bin");
	std::string sb_b = readfile(std::string(argv[1]) + "/cb_b.bin");
	std::string ldr = readfile("out/ldr.bin");
	std::string sd = readfile(std::string(argv[1]) + "/cd.bin");
	std::string xell = readfile(std::string(argv[1]) + "/xell.bin");
	
	for (int i = 0; i < smc.size(); i++)
	{
		smc[i] ^= smc_key[i & 3];

		uint16_t mod = (uint8_t) smc[i] * 0xFB;
		smc_key[(i + 1) & 3] += mod;
		smc_key[(i + 2) & 3] += mod >> 8;
	}
	
	_BLDR_2BL *sb_header = (_BLDR_2BL *) sb.data();
	uint8_t *cb_content = (uint8_t *) &sb.data()[sizeof(_BLDR_2BL)];
	
	sb_b.resize(0xC000);
	
	{
		uint8_t SB_KEY[20];
		int ret = XeCryptHmacSha(SB_KEY_SEED, sizeof(SB_KEY_SEED), nonce, sizeof(nonce), 0, 0, 0, 0, SB_KEY);
		if (ret < 0)
			printf("XeCryptHmacSha failed! %d\n", ret);
		memcpy(sb_header->abNonce, nonce, sizeof(nonce));

		RC4_KEY key;
		RC4_set_key(&key, 16, SB_KEY);
		RC4(&key, sb_header->Size - sizeof(_BLDR_2BL), cb_content, cb_content);
	}

	struct _BLDR_FLASH nandheader;
	memset(&nandheader, 0, sizeof(nandheader));

	nandheader.Magic = 0xFF4F;
	nandheader.Build = 1888;
	strcpy(nandheader.achCopyright, "Balika011's special");
	
	nandheader.dwSmcBootAddr = 0x800;
	nandheader.dwSmcBootSize = smc.size();

	nandheader.dwKeyVaultAddr = nandheader.dwSmcBootAddr + nandheader.dwSmcBootSize;
	nandheader.dwKeyVaultAddr = kv.size();

	nandheader.Entry = nandheader.dwKeyVaultAddr + nandheader.dwKeyVaultAddr;
	
	// HACK: align the start of sb_b to 0x200
	if (sb.size() % 0x200)
		nandheader.Entry += 0x200 - sb.size() % 0x200;
	
	nandheader.Size = 0x70000;
	
	nandheader.dwSysUpdateAddr = nandheader.Size;
	nandheader.wSysUpdateCount = 0x2;
	nandheader.wKeyVaultVersion = 0x712;
	
	std::string data;
	data += std::string((char *) &nandheader, sizeof(nandheader));

	{
		std::string ff;
		ff.resize(nandheader.dwSmcBootAddr - 0x200);
		memset(ff.data(), 0xff, ff.size());
		data.resize(0x200);
		data += ff;
	}
	data += smc;

	data.resize(nandheader.dwKeyVaultAddr);
	data += kv;

	data.resize(nandheader.Entry);
	data += sb;
	data += sb_b;
	data += ldr;
	data += sd;

	{
		std::string ff;
		ff.resize(0xc0000 - data.size());
		memset(ff.data(), 0xff, ff.size());
		data += ff;
	}

	data += xell;
	
	FILE *f = fopen((std::string(argv[1]) + "/new.ecc").c_str(), "wb");
	for (int i = 0; i < data.size(); i += 0x200)
	{
		std::string o = data.substr(i, 0x200);
		o.resize(0x210);
		
		*(uint16_t *) &o[0x200] = i / 0x4000;		
		o[0x205] = 0xff;
	
		uint32_t ecc = 0;

		uint32_t *ptr = (uint32_t *) o.data();
		unsigned int v = 0;
		for (int i = 0; i < (512 * 8) + 102; i++)
		{
			if (!(i & 31))
			{
				v = ~*ptr++;
			}
		       ecc ^= v & 1;
		       v>>=1;
		       if (ecc & 1)
			   ecc ^= 0x6954559;
			ecc >>= 1;
		}
		ecc = ~ecc;

		ecc = (((ecc >> 18) & 0xFF) << 24) | (((ecc >> 10) & 0xFF) << 16) | (((ecc >> 2) & 0xFF) << 8) | ((ecc << 6) & 0xC0);

		*(uint32_t *) &o.data()[0x20C] = ecc;

		fwrite(o.data(), 1, o.size(), f);	
	}
	fclose(f);

	return 0;	
}
