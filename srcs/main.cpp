#include "LnurlPoS.hpp"

int main(void)
{
	std::string input;
	LnurlPoS pos;

	std::cout << "Enter Lnurl Device String pasted from LNBits: ";
	std::getline(std::cin, input);
	std::cout << "You entered: " << input << std::endl;

	pos.init(input, true);

	std::cout << "How many cents: ";
	std::getline(std::cin, input);
	std::cout << pos.makeLNURL(std::stoi(input)) << std::endl;

	return 0;
}
