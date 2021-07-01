#include <algorithm>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/utils.h>
#include <system_error>
#include <variant>

#include <gtest/gtest.h>
#include <sodium.h>

#include "../AsyncCipherStream.h"

using namespace crypto;
using byte = AsyncCipherStream::byte;
using Bytes = AsyncCipherStream::Bytes;

std::string to_hex(auto c) {
  const unsigned char* buf =
      reinterpret_cast<const unsigned char*>(std::data(c));
  const auto size = std::size(c);
  const auto value_size = sizeof(typename decltype(c)::value_type);

  auto output = std::string(size * value_size * 2, ' ');

  for (size_t i = 0; i < size; ++i) {
    snprintf(output.data() + (i * value_size * 2), 3, "%02x", buf[i]);
  }

  return output;
}

std::string sodium_to_hex(auto c) {
  const unsigned char* buf =
      reinterpret_cast<const unsigned char*>(std::data(c));
  const auto size = std::size(c);
  const auto value_size = sizeof(typename decltype(c)::value_type);

  auto output = std::string(size * value_size * 2 + 1, ' ');

  sodium_bin2hex(output.data(), output.size(), buf, size);
  output.resize(output.size()-1);

  return output;
}

inline std::array<byte, AsyncCipherStream::KEY_BYTES> random_key() {
  std::array<byte, AsyncCipherStream::KEY_BYTES> key;
  randombytes_buf(key.data(), key.size());
  return key;
}

inline std::array<byte, AsyncCipherStream::NONCE_BYTES> random_nonce() {
  std::array<byte, AsyncCipherStream::NONCE_BYTES> nonce;
  randombytes_buf(nonce.data(), nonce.size());
  return nonce;
}


bool all_unique(auto c) {
  for (auto it = c.begin(); it != c.end()-1; ++it) {
    if (std::find(it+1, c.end(), *it) != c.end()) {
      return false;
    }
  }
  return true;
}

constexpr char KEY_HEX[] =
    "e2c47e1108f827fd4a0f7e21c905b48d45c9914f232093c82737f36c4f875771";
const std::array<byte, AsyncCipherStream::KEY_BYTES> KEY =
    []{
      std::array<byte, AsyncCipherStream::KEY_BYTES> key;
      sodium_hex2bin(key.data(), key.size(),
                     KEY_HEX, sizeof(KEY_HEX)-1,
                     nullptr, nullptr, nullptr);
      return key;
    }();

constexpr char NONCE_HEX[] =
    "78ca6917b85b7afa48fbec2487039dd351eb8ff1d768f998";
const std::array<byte, AsyncCipherStream::NONCE_BYTES> NONCE =
    []{
      std::array<byte, AsyncCipherStream::NONCE_BYTES> nonce;
      sodium_hex2bin(nonce.data(), nonce.size(),
                     NONCE_HEX, sizeof(NONCE_HEX)-1,
                     nullptr, nullptr, nullptr);
      return nonce;
    }();

constexpr unsigned char message[] = "message";

// It's imperative that OP_ID is size_t so that the additional data's length
// used for signing is the same as in the AsyncCipherStream.
constexpr size_t OP_ID = 0;
const Bytes ENCRYPTED_MSG = []{
  Bytes ciphertext(sizeof(message)-1 + AsyncCipherStream::ABYTES);
  unsigned long long real_size{0};

  auto ret = crypto_aead_xchacha20poly1305_ietf_encrypt(
      ciphertext.data(), &real_size,
      message, sizeof(message)-1,
      reinterpret_cast<const unsigned char*>(&OP_ID), sizeof(OP_ID),
      nullptr,
      NONCE.data(), KEY.data());
  assert(ret == 0);
  assert(real_size == ciphertext.size());

  return ciphertext;
}();

TEST(AsyncCipherStream, encrypt_decrypt_with_known_key) {
  AsyncCipherStream ctx(KEY, NONCE);

  constexpr auto ITERATIONS = 100;
  std::array<Bytes, ITERATIONS> results;
  for (auto i = 0; i < ITERATIONS; ++i) {
    auto encryption_ret = ctx.Encrypt({message, sizeof(message)-1}, i);
    ASSERT_FALSE(std::holds_alternative<std::error_code>(encryption_ret))
        << "Iteration: " << i;
    results[i] = std::move(std::get<Bytes>(encryption_ret));
    ASSERT_FALSE(sodium_is_zero(results[i].data(), results[i].size()));
  }

  ASSERT_TRUE(all_unique(results))
      << "Ciphertext for different op_ids is repeating";

  for (int i = 0; i < ITERATIONS; ++i) {
    auto decryption_ret = ctx.Decrypt(results[i], i);
    ASSERT_FALSE(std::holds_alternative<std::error_code>(decryption_ret))
        << "Iteration: " << i;
    const Bytes& result = std::get<Bytes>(decryption_ret);
    ASSERT_TRUE(std::equal(message, message+sizeof(message)-1,
                           result.begin(), result.end()))
        << "Iteration: " << i;
  }

  ASSERT_TRUE(std::equal(results[0].begin(), results[0].end(),
                         ENCRYPTED_MSG.begin(), ENCRYPTED_MSG.end()))
      << "Check if OP_ID is the same length as in AsyncCipherStream";
}

TEST(AsyncCipherStream, encrypt_decrypt_with_random_keys_and_op_ids) {
  size_t op_id{0};

  constexpr auto ITERATIONS = 100;

  for (auto i = 0; i < ITERATIONS; ++i) {
    AsyncCipherStream ctx(random_key(), NONCE);
    randombytes_buf(&op_id, sizeof(op_id));

    auto enc_ret = ctx.Encrypt({message, sizeof(message)-1}, op_id);
    ASSERT_FALSE(std::holds_alternative<std::error_code>(enc_ret))
        << "Iteration " << i;

    const auto& ciphertext = std::get<Bytes>(enc_ret);
    ASSERT_FALSE(sodium_is_zero(ciphertext.data(), ciphertext.size()))
        << "Iteration " << i;

    auto dec_ret = ctx.Decrypt(ciphertext, op_id);
    ASSERT_FALSE(std::holds_alternative<std::error_code>(dec_ret))
        << "Iteration " << i;

    const auto& cleartext = std::get<Bytes>(dec_ret);
    ASSERT_TRUE(std::equal(message, message+sizeof(message)-1,
                           cleartext.begin(), cleartext.end()))
        << "Iteration: " << i;
  }
}

TEST(AsyncCipherStream, decrypt_with_wrong_op_id) {
  AsyncCipherStream ctx(KEY, NONCE);

  auto enc_ret = ctx.Encrypt({message, sizeof(message)-1}, 1234);
  ASSERT_FALSE(std::holds_alternative<std::error_code>(enc_ret));

  auto dec_ret = ctx.Decrypt(std::get<Bytes>(enc_ret), 4321);
  ASSERT_TRUE(std::holds_alternative<std::error_code>(dec_ret));

  auto ec = std::get<std::error_code>(dec_ret);
  ASSERT_EQ(ec.value(), static_cast<int>(std::errc::bad_message));
}

TEST(AsyncCipherStream, different_contexts) {
  AsyncCipherStream enc_ctx(KEY, NONCE);
  AsyncCipherStream dec_ctx(KEY, NONCE);

  auto enc_ret = enc_ctx.Encrypt({message, sizeof(message)-1}, 1234);
  ASSERT_FALSE(std::holds_alternative<std::error_code>(enc_ret));

  auto dec_ret = dec_ctx.Decrypt(std::get<Bytes>(enc_ret), 1234);
  ASSERT_FALSE(std::holds_alternative<std::error_code>(dec_ret));

  const auto& cleartext = std::get<Bytes>(dec_ret);
  ASSERT_TRUE(std::equal(message, message+sizeof(message)-1,
                         cleartext.begin(), cleartext.end()));
}

TEST(AsyncCipherStream, wrong_base_nonce) {
  AsyncCipherStream enc_ctx(KEY, NONCE);
  AsyncCipherStream dec_ctx(KEY, random_nonce());

  auto enc_ret = enc_ctx.Encrypt({message, sizeof(message)-1}, 1234);
  ASSERT_FALSE(std::holds_alternative<std::error_code>(enc_ret));

  auto dec_ret = dec_ctx.Decrypt(std::get<Bytes>(enc_ret), 1234);
  ASSERT_TRUE(std::holds_alternative<std::error_code>(dec_ret));

  auto ec = std::get<std::error_code>(dec_ret);
  ASSERT_EQ(ec.value(), static_cast<int>(std::errc::bad_message));
}

TEST(AsyncCipherStream, wrong_key) {
  AsyncCipherStream enc_ctx(KEY, NONCE);
  AsyncCipherStream dec_ctx(random_key(), NONCE);

  auto enc_ret = enc_ctx.Encrypt({message, sizeof(message)-1}, 1234);
  ASSERT_FALSE(std::holds_alternative<std::error_code>(enc_ret));

  auto dec_ret = dec_ctx.Decrypt(std::get<Bytes>(enc_ret), 1234);
  ASSERT_TRUE(std::holds_alternative<std::error_code>(dec_ret));

  auto ec = std::get<std::error_code>(dec_ret);
  ASSERT_EQ(ec.value(), static_cast<int>(std::errc::bad_message));
}

TEST(AsyncCipherStream, encrypt_wrong_input) {
  AsyncCipherStream ctx(KEY, NONCE);

  const std::array test_cases = {
    std::span{(const byte*)nullptr, 0},
    std::span{(const byte*)nullptr, 10},
    std::span{message, 0}
  };

  for (auto& test_case : test_cases) {
    auto enc_ret = ctx.Encrypt(test_case, OP_ID);

    bool contains_error = std::holds_alternative<std::error_code>(enc_ret);
    EXPECT_TRUE(contains_error)
        << "Input " << (test_case.data() ? "not null" : "null")
        << ", size: " << test_case.size();

    if (contains_error) {
      EXPECT_EQ(std::get<std::error_code>(enc_ret).value(),
                static_cast<int>(std::errc::invalid_argument))
          << "Input " << (test_case.data() ? "not null" : "null")
          << ", size: " << test_case.size();
    }
  }
}

TEST(AsyncCipherStream, encrypt_wrong_output) {
  AsyncCipherStream ctx(KEY, NONCE);

  std::array<byte, sizeof(message)-1 + AsyncCipherStream::ABYTES> output;

  const std::array test_cases = {
    std::span{(byte*)nullptr, 0},
    std::span{(byte*)nullptr, AsyncCipherStream::ABYTES-1},
    std::span{(byte*)nullptr, AsyncCipherStream::ABYTES},
    std::span{(byte*)nullptr, AsyncCipherStream::ABYTES+1},
    std::span{output.data(), 0},
    std::span{output.data(), AsyncCipherStream::ABYTES-1},
    std::span{output.data(), AsyncCipherStream::ABYTES},
    std::span{output.data(), AsyncCipherStream::ABYTES+1},
    std::span{
      output.data(),
      // minimal output size - 1
      (sizeof(message)-1) + AsyncCipherStream::ABYTES - 1}
  };

  for (auto& test_case : test_cases) {
    auto enc_ret = ctx.Encrypt({message, sizeof(message)-1},
                               test_case,
                               OP_ID);

    bool contains_error = std::holds_alternative<std::error_code>(enc_ret);
    EXPECT_TRUE(contains_error)
        << "Input " << (test_case.data() ? "not null" : "null")
        << ", size: " << test_case.size();

    if (contains_error) {
      EXPECT_EQ(std::get<std::error_code>(enc_ret).value(),
                static_cast<int>(std::errc::invalid_argument))
          << "Input " << (test_case.data() ? "not null" : "null")
          << ", size: " << test_case.size();
    }
  }
}

TEST(AsyncCipherStream, decrypt_wrong_input) {
  AsyncCipherStream ctx(KEY, NONCE);

  const std::array test_cases = {
    std::span{(const byte*)nullptr, 0},
    std::span{(const byte*)nullptr, AsyncCipherStream::ABYTES-1},
    std::span{(const byte*)nullptr, AsyncCipherStream::ABYTES},
    std::span{(const byte*)nullptr, AsyncCipherStream::ABYTES+1},
    std::span{ENCRYPTED_MSG.data(), 0},
    std::span{ENCRYPTED_MSG.data(), AsyncCipherStream::ABYTES-1},
    std::span{ENCRYPTED_MSG.data(), AsyncCipherStream::ABYTES},
  };

  for (auto& test_case : test_cases) {
    auto enc_ret = ctx.Decrypt(test_case, OP_ID);
    bool contains_error = std::holds_alternative<std::error_code>(enc_ret);
    EXPECT_TRUE(contains_error)
        << "Input " << (test_case.data() ? "not null" : "null")
        << ", size: " << test_case.size();

    if (contains_error) {
      EXPECT_EQ(std::get<std::error_code>(enc_ret).value(),
                static_cast<int>(std::errc::invalid_argument))
          << "Input " << (test_case.data() ? "not null" : "null")
          << ", size: " << test_case.size();
    }
  }
}

TEST(AsyncCipherStream, decrypt_good_input_span_bad_message) {
  AsyncCipherStream ctx(KEY, NONCE);

  const std::array test_cases = {
    std::span{ENCRYPTED_MSG.data(), AsyncCipherStream::ABYTES+1},
    std::span{ENCRYPTED_MSG.data(), ENCRYPTED_MSG.size()-1}
  };

  for (auto& test_case : test_cases) {
    auto enc_ret = ctx.Decrypt(test_case, OP_ID);
    bool contains_error = std::holds_alternative<std::error_code>(enc_ret);
    EXPECT_TRUE(contains_error)
        << "Input " << (test_case.data() ? "not null" : "null")
        << ", size: " << test_case.size();

    if (contains_error) {
      EXPECT_EQ(std::get<std::error_code>(enc_ret).value(),
                static_cast<int>(std::errc::bad_message))
          << "Input " << (test_case.data() ? "not null" : "null")
          << ", size: " << test_case.size();
    }
  }
}

TEST(AsyncCipherStream, decrypt_wrong_output) {
  AsyncCipherStream ctx(KEY, NONCE);
  constexpr auto cleartext_size = sizeof(message) - 1;
  Bytes output(cleartext_size);

  const std::array test_cases = {
    std::span{(byte*)nullptr, 0},
    std::span{(byte*)nullptr, cleartext_size-1},
    std::span{(byte*)nullptr, cleartext_size},
    std::span{(byte*)nullptr, cleartext_size+1},
    std::span{output.data(), 0},
    std::span{output.data(), cleartext_size-1},
  };

  for (auto& test_case : test_cases) {
    auto enc_ret = ctx.Decrypt(ENCRYPTED_MSG, test_case, OP_ID);

    bool contains_error = std::holds_alternative<std::error_code>(enc_ret);
    EXPECT_TRUE(contains_error)
        << "Input " << (test_case.data() ? "not null" : "null")
        << ", size: " << test_case.size();

    if (contains_error) {
      EXPECT_EQ(std::get<std::error_code>(enc_ret).value(),
                static_cast<int>(std::errc::invalid_argument))
          << "Input " << (test_case.data() ? "not null" : "null")
          << ", size: " << test_case.size();
    }
  }
}

TEST(AsyncCipherStream, encrypt_overlapping_input_output) {
  AsyncCipherStream ctx(KEY, NONCE);
  Bytes input(sizeof(message)-1 + AsyncCipherStream::ABYTES);
  constexpr auto message_size = sizeof(message)-1;
  std::copy_n(message, message_size, input.data());

  auto enc_ret = ctx.Encrypt({input.data(), message_size}, input, OP_ID);

  ASSERT_FALSE(std::holds_alternative<std::error_code>(enc_ret));
  ASSERT_EQ(input, ENCRYPTED_MSG);
}

TEST(AsyncCipherStream, decrypt_overlapping_input_output) {
  AsyncCipherStream ctx(KEY, NONCE);
  Bytes input(ENCRYPTED_MSG);

  auto dec_ret = ctx.Decrypt(input, input, OP_ID);

  ASSERT_FALSE(std::holds_alternative<std::error_code>(dec_ret));

  input.resize(std::get<size_t>(dec_ret));

  ASSERT_TRUE(std::equal(input.begin(), input.end(), message));
}
