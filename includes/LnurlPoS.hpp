#pragma once

#include "Bitcoin.h"
#include "Bitcoin.h"
#include "Conversion.h" // to get access to functions like toHex() or fromBase64()
#include "Hash.h"
#include <Hash.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <cstdlib>

////////////////////////////////////////////
///////////////LNURL STUFF//////////////////
////USING STEPAN SNIGREVS GREAT CRYTPO//////
////////////THANK YOU STEPAN////////////////
////////////////////////////////////////////

class LnurlPoS
{
public:
	LnurlPoS();
	~LnurlPoS();
	LnurlPoS(const LnurlPoS &other);
	LnurlPoS &operator=(const LnurlPoS &other);

	void init(const std::string &lnurl_device_string, const bool debug_mode);
	std::string makeLNURL(int amount_in_cents);
	std::string getCurrency() const;
	std::string getAmountString(int amount_in_cents);

private:
	bool _initialized;
	uint8_t *_secretATM;
	std::string _baseURL;
	bool _debugMode;
	size_t _secretLength;
	std::string _currencyATM;

	std::string _getValue(const std::string &data, char separator, int index);
	int _xor_encrypt(uint8_t *output, size_t outlen, uint8_t *key, size_t keylen, uint8_t *nonce, size_t nonce_len, uint64_t pin, uint64_t amount_in_cents);
	void _to_upper(char *arr);
};
