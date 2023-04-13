#ifndef CHACHA20_H
#define CHACHA20_H

#include <array>
#include <vector>

namespace four {

	class ChaCha20Block
	{

	public:
		explicit constexpr ChaCha20Block(const std::array<uint32_t, 8>& key, const std::array<uint32_t, 3>& nonce, std::size_t round = 10) noexcept
			: m_key(key), m_nonce(nonce)
			, round_count(round)
		{
			std::array<uint32_t, 4> magic_const {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
			m_state[0] = magic_const[0];
			m_state[1] = magic_const[1];
			m_state[2] = magic_const[2];
			m_state[3] = magic_const[3];
			
			m_state[4] = key[0];
			m_state[5] = key[1];
			m_state[6] = key[2];
			m_state[7] = key[3];
			m_state[8] = key[4];
			m_state[9] = key[5];
			m_state[10] = key[6];
			m_state[11] = key[7];

			m_state[12] = 0x00000001;
			m_state[13] = nonce[0];
			m_state[14] = nonce[1];
			m_state[15] = nonce[2];
		}

		constexpr void set_counter(uint32_t counter) noexcept
		{
			m_state[12] = counter;
		}

		constexpr void set_nonce(const std::array<uint32_t, 3>& new_nonce) noexcept
		{
			m_nonce = new_nonce;
			m_state[13] = new_nonce[0];
			m_state[14] = new_nonce[1];
			m_state[15] = new_nonce[2];
		}

		constexpr void set_key(const std::array<uint32_t, 8> new_key) noexcept
		{
			m_key = new_key;
			m_state[4] = m_key[0];
			m_state[5] = m_key[1];
			m_state[6] = m_key[2];
			m_state[7] = m_key[3];
			m_state[8] = m_key[4];
			m_state[9] = m_key[5];
			m_state[10] = m_key[6];
			m_state[11] = m_key[7];
		}

		constexpr void reset() noexcept
		{
			m_state[4] = m_key[0];
			m_state[5] = m_key[1];
			m_state[6] = m_key[2];
			m_state[7] = m_key[3];
			m_state[8] = m_key[4];
			m_state[9] = m_key[5];
			m_state[10] = m_key[6];
			m_state[11] = m_key[7];

			m_state[12] = 0x00000001;
			m_state[13] = m_nonce[0];
			m_state[14] = m_nonce[1];
			m_state[15] = m_nonce[2];
		}

		constexpr void set_round(std::size_t new_round) noexcept
		{
			round_count = new_round;
		}

		constexpr void next(std::array<uint32_t, 16>& result)
		{
			for(size_t i = 0; i < 16; ++i)
				result[i] = m_state[i];

			for(size_t i = 0; i < round_count; ++i)
			{
				chacha20_quarterround(result, 0, 4, 8, 12);
				chacha20_quarterround(result, 1, 5, 9, 13);
				chacha20_quarterround(result, 2, 6, 10, 14);
				chacha20_quarterround(result, 3, 7, 11, 15);
				chacha20_quarterround(result, 0, 5, 10, 15);
				chacha20_quarterround(result, 1, 6, 11, 12);
				chacha20_quarterround(result, 2, 7, 8, 13);
				chacha20_quarterround(result, 3, 4, 9, 14);
			}

			for(size_t i = 0; i < 16; ++i)
				result[i] += m_state[i];

			// increment counter
			++m_state[12];
		}

	private:
		std::size_t round_count = 10;
		std::array<uint32_t, 16> m_state;
		std::array<uint32_t, 8> m_key;
		std::array<uint32_t, 3> m_nonce;


		static constexpr uint32_t rotate_op(uint32_t val, int32_t n) noexcept
		{
			return (val << n) | (val >> (32-n));
		}

		static constexpr void chacha20_quarterround(std::array<uint32_t, 16>& src, size_t a, size_t b, size_t c, size_t d) noexcept
		{
			src[a] += src[b]; src[d] ^= src[a]; src[d] = rotate_op(src[d], 16);
			src[c] += src[d]; src[b] ^= src[c]; src[b] = rotate_op(src[b], 12);
			src[a] += src[b]; src[d] ^= src[a]; src[d] = rotate_op(src[d], 8);
			src[c] += src[b]; src[b] ^= src[c]; src[b] = rotate_op(src[b], 7);
		}
	};

	class ChaCha20
	{
	public:
		constexpr explicit ChaCha20(const std::array<uint32_t, 8>& key, const std::array<uint32_t, 3>& nonce, uint32_t counter = 1) noexcept
			: block(key, nonce), m_position(0)
		{
			block.set_counter(counter);
		}

		constexpr void set_nonce(const std::array<uint32_t, 3>& nonce) noexcept
		{
			block.set_nonce(nonce);
		}

		constexpr void reset()
		{
			block.reset();
			block.set_counter(1);
			m_position = 0;
			for(auto& each : stream_key)
				each = 0;
		}
	
		/* it doesn't change the original input and return a new vector */
		constexpr std::vector<uint8_t> encrypt_copy(const std::vector<uint8_t>& data)
		{
			std::vector<uint8_t> result;
			result.reserve(data.size());
			for(const unsigned char & i : data)
			{
				if(m_position >= stream_key.size())
				{
					block.next(stream_key);
					m_position = 0;
				}
				result.push_back(i ^  stream_key[m_position]);
				++m_position;
			}
			return result;
		}

		/* rewrite the original data */
		constexpr void encrypt(std::vector<uint8_t>& data)
		{
			for (unsigned char& i : data)
			{
				if (m_position >= stream_key.size())
				{
					block.next(stream_key);
					m_position = 0;
				}
				i ^= stream_key[m_position];
				++m_position;
			}
		}

		/* it doesn't change the original input and return a new vector */
		constexpr std::vector<uint8_t> decrypt_copy(const std::vector<uint8_t>& data)
		{
			return encrypt_copy(data);
		}

		/* rewrite the original data */
		constexpr void decrypt(std::vector<uint8_t>& data)
		{
			encrypt(data);
		}
	private:
		ChaCha20Block block;
		std::array<uint32_t, 16> stream_key{};
		std::size_t m_position = 0;
	};
}

#endif //CHACHA20_H