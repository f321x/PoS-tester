#include "LnurlPoS.hpp"

LnurlPoS::LnurlPoS() : _initialized(false) {}

LnurlPoS::~LnurlPoS() {}

LnurlPoS::LnurlPoS(const LnurlPoS &other)
{
	_secretATM = other._secretATM;
	_baseURL = other._baseURL;
	_currencyATM = other._currencyATM;
	_debugMode = other._debugMode;
	_secretLength = other._secretLength;
	_initialized = other._initialized;
}

LnurlPoS &LnurlPoS::operator=(const LnurlPoS &other)
{
	if (this == &other)
		return *this;
	_secretATM = other._secretATM;
	_baseURL = other._baseURL;
	_currencyATM = other._currencyATM;
	_debugMode = other._debugMode;
	_secretLength = other._secretLength;
	_initialized = other._initialized;
	return *this;
}

void LnurlPoS::init(const std::string &lnurl_device_string, const bool debug_mode)
{
	_debugMode = debug_mode;
	if (_debugMode)
		std::cout << "LnurlPoS created" << std::endl;
	if (lnurl_device_string == "https://legend.lnbits.com/lnurldevice/api/v1/lnurl/idexample,keyexample,EUR" && _debugMode)
	{
		std::cout << "LnurlPoS: WARNING: using default lnurl_device_string" << std::endl;
	}
	if (lnurl_device_string.length() == 0)
	{
		throw std::invalid_argument("LnurlPoS: lnurl_device_string must be non-empty");
	}
	_baseURL = _getValue(lnurl_device_string, ',', 0);
	std::string secretATMbuf = _getValue(lnurl_device_string, ',', 1);
	_currencyATM = _getValue(lnurl_device_string, ',', 2);

	_secretLength = secretATMbuf.length();
	_secretATM = (uint8_t *)secretATMbuf.c_str();
	if (_secretATM == NULL || _secretLength == 0 || _baseURL.length() == 0)
	{
		throw std::invalid_argument("LnurlPoS: secretATM and baseURL must be non-empty");
	}
	_initialized = true;
}

// Function to seperate the LNURLDevice string in key, url and currency
std::string LnurlPoS::_getValue(const std::string &data, char separator, int index)
{
	int found = 0;
	std::pair<int, int> strIndex = {0, -1};
	const int maxIndex = data.length() - 1;

	for (int i = 0; i <= maxIndex && found <= index; i++)
	{
		if (data.at(i) == separator || i == maxIndex)
		{
			found++;
			strIndex.first = strIndex.second + 1;
			strIndex.second = (i == maxIndex) ? i + 1 : i;
		}
	}
	return found > index ? data.substr(strIndex.first, strIndex.second - strIndex.first) : "";
}

std::string LnurlPoS::getAmountString(int amount_in_cents)
{
	std::string euro;
	std::string cents;
	std::string return_value;
	int euro_value;
	int cent_remainder;

	euro_value = amount_in_cents / 100;
	cent_remainder = amount_in_cents % 100;
	euro = std::to_string(euro_value);
	if (cent_remainder > 9)
		cents = std::to_string(cent_remainder);
	else if (cent_remainder < 10)
		cents = "0" + std::to_string(cent_remainder);
	return_value = std::string(euro) + "." + std::string(cents) + " " + _currencyATM;
	if (_debugMode)
		std::cout << "Calculated amount string: " << return_value << std::endl;
	return (return_value);
}

std::string LnurlPoS::getCurrency() const
{
	if (!_initialized)
	{
		throw std::invalid_argument("LnurlPoS: not initialized");
	}
	return _currencyATM;
}

int LnurlPoS::_xor_encrypt(uint8_t *output, size_t outlen, uint8_t *key, size_t keylen, uint8_t *nonce, size_t nonce_len, uint64_t pin, uint64_t amount_in_cents)
{
	// check we have space for all the data:
	// <variant_byte><len|nonce><len|payload:{pin}{amount}><hmac>
	if (outlen < 2 + nonce_len + 1 + lenVarInt(pin) + 1 + lenVarInt(amount_in_cents) + 8)
	{
		return 0;
	}

	int cur = 0;
	output[cur] = 1; // variant: XOR encryption
	cur++;

	// nonce_len | nonce
	output[cur] = nonce_len;
	cur++;
	memcpy(output + cur, nonce, nonce_len);
	cur += nonce_len;

	// payload, unxored first - <pin><currency byte><amount>
	int payload_len = lenVarInt(pin) + 1 + lenVarInt(amount_in_cents);
	output[cur] = (uint8_t)payload_len;
	cur++;
	uint8_t *payload = output + cur;								 // pointer to the start of the payload
	cur += writeVarInt(pin, output + cur, outlen - cur);			 // pin code
	cur += writeVarInt(amount_in_cents, output + cur, outlen - cur); // amount
	cur++;

	// xor it with round key
	uint8_t hmacresult[32];
	SHA256 h;
	h.beginHMAC(key, keylen);
	h.write((uint8_t *)"Round secret:", 13);
	h.write(nonce, nonce_len);
	h.endHMAC(hmacresult);
	for (int i = 0; i < payload_len; i++)
	{
		payload[i] = payload[i] ^ hmacresult[i];
	}

	// add hmac to authenticate
	h.beginHMAC(key, keylen);
	h.write((uint8_t *)"Data:", 5);
	h.write(output, cur);
	h.endHMAC(hmacresult);
	memcpy(output + cur, hmacresult, 8);
	cur += 8;

	// return number of bytes written to the output
	return cur;
}

void LnurlPoS::_to_upper(char *arr)
{
	for (size_t i = 0; i < strlen(arr); i++)
	{
		if (arr[i] >= 'a' && arr[i] <= 'z')
		{
			arr[i] = arr[i] - 'a' + 'A';
		}
	}
}

std::string LnurlPoS::makeLNURL(int total)
{
	if (!_initialized)
	{
		throw std::invalid_argument("LnurlPoS: not initialized");
	}
	int randomPin = rand() % 9000 + 1000;
	unsigned char nonce[8];
	for (int i = 0; i < 8; i++)
	{
		nonce[i] = rand() % 256;
	}
	unsigned char payload[51]; // 51 bytes is max one can get with xor-encryption
	size_t payload_len = _xor_encrypt(payload, sizeof(payload), _secretATM, _secretLength, nonce, sizeof(nonce), randomPin, total);
	std::string preparedURL = _baseURL + "?atm=1&p=";
	preparedURL += toBase64(payload, payload_len, BASE64_URLSAFE | BASE64_NOPADDING);
	if (_debugMode)
		std::cout << preparedURL << std::endl;
	char Buf[200];
	preparedURL.copy(Buf, preparedURL.size() + 1);
	Buf[preparedURL.size()] = '\0';
	char *url = Buf;
	unsigned char *data = (unsigned char *)calloc(strlen(url) * 2, sizeof(unsigned char));
	if (!data)
		return (std::string(""));
	size_t len = 0;
	int res = convert_bits(data, &len, 5, (unsigned char *)url, strlen(url), 8, 1);
	char *charLnurl = (char *)calloc(strlen(url) * 2, sizeof(unsigned char));
	if (!charLnurl)
	{
		free(data);
		return (std::string(""));
	}
	bech32_encode(charLnurl, "lnurl", data, len);
	_to_upper(charLnurl);
	free(data);
	std::string lnurl(charLnurl);
	free(charLnurl);
	return (lnurl);
}
