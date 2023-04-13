#include <iostream>
#include <string>
#include <iomanip>
#include <cassert>
#include "ChaCha20.h"

std::vector<uint8_t> string_to_vector_u8(const std::string& s)
{
	std::vector<uint8_t> result;
	result.reserve(s.size());
	for(const auto each : s)
	{
		result.push_back(static_cast<uint8_t>(each));
	}
	return result;
}

int main()
{
	std::vector<uint8_t> data = string_to_vector_u8("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it. Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it. Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it. Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it. Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");

	std::cout << "original data:\n";
	for (const auto each : data)
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(each) << ' ';
	std::cout << "\n\n";

	std::array<uint32_t, 8> key{ 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c };
	std::array<uint32_t, 3> nonce{ 0x90000000, 0x4a000000, 0x00000000 };
	four::ChaCha20 chacha(key, nonce, 1);

	auto encrypted = chacha.encrypt_copy(data);

	std::cout << "encrypted data:\n";
	for (const auto each : encrypted)
	{
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(each) << ' ';
	}
	std::cout << "\n\n";

	chacha.reset();
	auto decrypted = chacha.decrypt_copy(encrypted);
	std::cout << "decrypted data:\n";
	for (const auto each : decrypted)
	{
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(each) << ' ';
	}

	std::cout << "\n\n\n\n";

	std::cout << "original input:\n";
	for (const auto each : data)
	{
		std::cout << each;
	}
	std::cout << "\n\n";

	std::cout << "decrypted input:\n";
	for (const auto each : decrypted)
	{
		std::cout << each;
	}

	std::cout << "\n\n\n\n";

	assert(data == decrypted);

	return 0;
}