#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "big.h"

#include <openssl/hmac.h>
#include <openssl/rc4.h>

static uint8_t SB_KEY_SEED[] = { 0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7, 0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA };
uint8_t smc_key[] = { 0x42, 0x75, 0x4e, 0x79 };

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

int main(int argc, char ** argv)
{
	std::string data;

	FILE *f = fopen(argv[1], "rb");
	
	uint8_t buffer[0x210];
	while (fread(buffer, 1, 0x210, f))
		data += std::string((char *) buffer, 0x200);
	
	fclose(f);
	
	_BLDR_FLASH *nandheader = (_BLDR_FLASH *) data.data();

	printf("nand Build: %d\n", (uint16_t) nandheader->Build);
	printf("nand copyright: %s\n", nandheader->achCopyright);
	
	// ---
	
	uint8_t *smc_start = (uint8_t *) &data.data()[nandheader->dwKeyVaultSize];
	
	for (int i = 0; i < nandheader->dwSmcBootSize; i++)
	{
		uint16_t mod = smc_start[i] * 0xFB;
		smc_start[i] ^= smc_key[i & 3];

		smc_key[(i + 1) & 3] += mod;
		smc_key[(i + 2) & 3] += mod >> 8;
	}
	
	FILE *smc = fopen((std::string(argv[2]) + "/smc.bin").c_str(), "wb");
	fwrite(smc_start, 1, nandheader->dwSmcBootSize, smc);
	fclose(smc);
	
	// ---
	
	uint8_t *kv_start = (uint8_t *) &data.data()[nandheader->dwKeyVaultAddr];
	
	FILE *kv = fopen((std::string(argv[2]) + "/kv.bin").c_str(), "wb");
	fwrite(kv_start, 1, nandheader->dwKeyVaultSize, kv);
	fclose(kv);
	
	// ---

	uint32_t offset = nandheader->Entry;
	printf("sb offset: %x\n", offset);
	
	_BLDR_2BL *sb_header = (_BLDR_2BL *) &data.data()[offset];
	printf("sb Build: %d\n", (uint16_t) sb_header->Build);
	uint8_t *cb_content = (uint8_t *) &data.data()[offset + sizeof(_BLDR_2BL)];

	printf("sb nonce: ");
	for (int i = 0; i < sizeof(sb_header->abNonce); i++)
		printf("0x%02x, ", sb_header->abNonce[i]);
	printf("\n");

	uint8_t SB_KEY[20];
	int ret = XeCryptHmacSha(SB_KEY_SEED, sizeof(SB_KEY_SEED), sb_header->abNonce, sizeof(sb_header->abNonce), 0, 0, 0, 0, SB_KEY);
	if (ret < 0)
		printf("XeCryptHmacSha failed! %d\n", ret);
	memcpy(sb_header->abNonce, SB_KEY, sizeof(sb_header->abNonce));

	RC4_KEY key;
	RC4_set_key(&key, sizeof(sb_header->abNonce), sb_header->abNonce);
	RC4(&key, sb_header->Size - sizeof(_BLDR_2BL), cb_content, cb_content);
	
	FILE *sb = fopen((std::string(argv[2]) + "/cb_a.bin").c_str(), "wb");
	fwrite(sb_header, 1, sb_header->Size, sb);
	fclose(sb);
	
	offset += sb_header->Size;
	
	// ---
	
	printf("sb_b offset: %x\n", offset);
	
	_BLDR_2BL *sb_b_header = (_BLDR_2BL *) &data.data()[offset];
	printf("sb_b Build: %d\n", (uint16_t) sb_b_header->Build);
	uint8_t *cb_b_content = (uint8_t *) &data.data()[offset + sizeof(_BLDR_2BL)];

	printf("sb_b nonce: ");
	for (int i = 0; i < sizeof(sb_b_header->abNonce); i++)
		printf("0x%02x, ", sb_b_header->abNonce[i]);
	printf("\n");

	uint8_t cpukey[16];
	memset(cpukey, 0, sizeof(cpukey)); // MFG CB uses zero key
	ret = XeCryptHmacSha(sb_header->abNonce, sizeof(sb_header->abNonce), sb_b_header->abNonce, sizeof(sb_b_header->abNonce), cpukey, sizeof(cpukey), 0, 0, SB_KEY);
	if (ret < 0)
		printf("XeCryptHmacSha failed! %d\n", ret);
	memcpy(sb_b_header->abNonce, SB_KEY, sizeof(sb_b_header->abNonce));

	RC4_set_key(&key, sizeof(sb_b_header->abNonce), sb_b_header->abNonce);	
	RC4(&key, sb_b_header->Size - sizeof(_BLDR_2BL), cb_b_content, cb_b_content);
	
	FILE *sb_b = fopen((std::string(argv[2]) + "/cb_b.bin").c_str(), "wb");
	fwrite(sb_b_header, 1, sb_b_header->Size, sb_b);
	fclose(sb_b);
	
	offset += sb_b_header->Size;
	
	// ---
	
	printf("sd offset: %x\n", offset);
	
	_BLDR_2BL *sd_header = (_BLDR_2BL *) &data.data()[offset];
	printf("sd magic: %x\n", (uint16_t) sd_header->Magic);
	printf("sd Build: %d\n", (uint16_t) sd_header->Build);
	
	FILE *sd = fopen((std::string(argv[2]) + "/cd.bin").c_str(), "wb");
	fwrite(sd_header, 1, sd_header->Size, sd);
	fclose(sd);
	
	offset += sd_header->Size;
	
	// ---
	
	std::string xell_buf = data.substr(0xc0000);
	
	FILE *xell = fopen((std::string(argv[2]) + "/xell.bin").c_str(), "wb");
	fwrite(xell_buf.data(), 1, xell_buf.size(), xell);
	fclose(xell);
	
	return 0;	
}
