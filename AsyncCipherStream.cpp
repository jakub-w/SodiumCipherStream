#include "AsyncCipherStream.h"

#include <cassert>
#include <cstring>
#include <sodium/crypto_aead_xchacha20poly1305.h>

namespace crypto {
AsyncCipherStream::AsyncCipherStream(
    std::array<byte, KEY_BYTES> key,
    std::array<byte, NONCE_BYTES> nonce) noexcept
    : key_(std::move(key)),
      nonce_base_(std::move(nonce)) {}

std::variant<std::error_code, size_t>
AsyncCipherStream::Encrypt(std::span<const byte> input,
                           std::span<byte> output,
                           size_t op_id) noexcept {
  static_assert(sizeof(op_id) % sizeof(unsigned char) == 0);
  static_assert(alignof(decltype(op_id)) % alignof(unsigned char) == 0);

  if ((input.data() == nullptr) or
      (input.size_bytes() == 0) or
      (output.data() == nullptr) or
      (output.size_bytes() < input.size_bytes() + ABYTES)) {
    return std::make_error_code(std::errc::invalid_argument);
  }

  std::array<byte, NONCE_BYTES> cur_nonce = compute_nonce(op_id);

  unsigned long long real_size = output.size_bytes();

  crypto_aead_xchacha20poly1305_ietf_encrypt(
      output.data(), &real_size,
      input.data(), input.size_bytes(),
      reinterpret_cast<const unsigned char*>(&op_id), sizeof(op_id),
      nullptr, cur_nonce.data(), key_.data());

  return real_size;
}

std::variant<std::error_code, size_t>
AsyncCipherStream::Decrypt(std::span<const byte> input,
                           std::span<byte> output,
                           size_t op_id) noexcept {
  if ((input.data() == nullptr) or
      (input.size_bytes() < ABYTES) or
      (output.data() == nullptr) or
      (output.size_bytes() < input.size_bytes() - ABYTES)) {
    return std::make_error_code(std::errc::invalid_argument);
  }

  std::array<byte, NONCE_BYTES> cur_nonce = compute_nonce(op_id);

  unsigned long long real_size = output.size_bytes();

  auto ret = crypto_aead_xchacha20poly1305_ietf_decrypt(
      output.data(), &real_size, nullptr,
      input.data(), input.size_bytes(),
      reinterpret_cast<const unsigned char*>(&op_id), sizeof(op_id),
      cur_nonce.data(), key_.data());

  if (0 != ret) {
    return std::make_error_code(std::errc::bad_message);
  }

  return real_size;
}

std::array<AsyncCipherStream::byte, AsyncCipherStream::NONCE_BYTES>
AsyncCipherStream::compute_nonce(size_t op_id) noexcept {
  std::array<byte, NONCE_BYTES> new_nonce{0};
  static_assert(sizeof(op_id) <= new_nonce.size());

  std::memcpy(new_nonce.data(), &op_id, sizeof(op_id));
  sodium_add(new_nonce.data(), nonce_base_.data(), nonce_base_.size());
  return new_nonce;
}
}
