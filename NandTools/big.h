#ifndef __BIG_H__
#define __BIG_H__

#include <stdint.h>
#include <stdlib.h>
#include <byteswap.h>

#pragma pack(push, 1)
class big_uint16_t
{
	uint16_t value;

public:
	big_uint16_t() {}

	big_uint16_t(uint16_t value)
	{
		this->value = bswap_16(value);
	}

	uint16_t operator=(uint16_t value)
	{
		this->value = bswap_16(value);
		return value;
	}

	uint16_t operator+=(uint16_t value)
	{
		this->value = bswap_16(bswap_16(this->value) + value);
		return value;
	}

	operator uint16_t()
	{
		return bswap_16(this->value);
	}
};

class big_uint32_t
{
	uint32_t value;

public:
	big_uint32_t() {}

	big_uint32_t(uint32_t value)
	{
		this->value = bswap_32(value);
	}

	uint32_t operator=(uint32_t value)
	{
		this->value = bswap_32(value);
		return value;
	}

	uint32_t operator+=(uint32_t value)
	{
		this->value = bswap_32(bswap_32(this->value) + value);
		return value;
	}

	operator uint32_t()
	{
		return bswap_32(this->value);
	}
};
#pragma pack(pop)

#endif
