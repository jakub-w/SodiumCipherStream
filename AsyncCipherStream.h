#ifndef ASYNCCIPHERSTREAM_H
#define ASYNCCIPHERSTREAM_H

#include <span>
#include <system_error>
#include <variant>
#include <vector>

#include <sodium.h>

namespace crypto {
/// Wraps libsodium's XChaCha20-Poly1305 functions.
/// Can be used to asynchronously encrypt and decrypt messages.
/// I.e. The decryption of messages don't need to follow the same order as
/// their encryption. To achieve that a unique ID must be passed for every
/// encryption-decryption operation.
///
/// Note that every method of this class is \e noexcept.
class AsyncCipherStream {
 public:
  using byte = unsigned char;
  using Bytes = std::vector<byte>;

  static constexpr auto
  NONCE_BYTES = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  static constexpr auto
  KEY_BYTES = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
  static constexpr auto
  ABYTES = crypto_aead_xchacha20poly1305_ietf_ABYTES;

  AsyncCipherStream(std::array<byte, KEY_BYTES> key,
                    std::array<byte, NONCE_BYTES> nonce) noexcept;

  AsyncCipherStream(const AsyncCipherStream&) = delete;
  AsyncCipherStream& operator=(const AsyncCipherStream&) = delete;

  inline AsyncCipherStream(AsyncCipherStream&& other) noexcept
      : key_{std::move(other.key_)},
        nonce_base_{std::move(other.nonce_base_)} {
    sodium_memzero(other.key_.data(), other.key_.size());
    sodium_memzero(other.nonce_base_.data(), other.nonce_base_.size());
  }

  inline AsyncCipherStream& operator=(AsyncCipherStream&& other) noexcept {
    key_ = std::move(other.key_);
    nonce_base_ = std::move(other.nonce_base_);
    sodium_memzero(other.key_.data(), other.key_.size());
    sodium_memzero(other.nonce_base_.data(), other.nonce_base_.size());
    return *this;
  }

  inline ~AsyncCipherStream() noexcept {
    sodium_memzero(key_.data(), key_.size());
    sodium_memzero(nonce_base_.data(), nonce_base_.size());
  }

  /// \anchor AsyncEncrypt_doc
  ///
  /// Encrypt \e input and put it in \e output.
  ///
  /// \param[in] input Array of plain bytes to be encrypted. It's size must be
  /// bigger than 0.
  ///
  /// \param[out] output Place to store the result. Its size must be at least
  /// \verbatim input.size() + ABYTES \endverbatim. The final size of the
  /// output is returned so that the size of the container storing it may be
  /// adjusted. Can overlap with \e input.
  ///
  /// \param[in] op_id Operation ID. Must be unique for every Encrypt-Decrypt
  /// operation. The same \e op_id has to be used when decrypting.
  ///
  /// \return Final size of the output. It may be shorter than
  /// \e output.size().
  /// \return \e std::errc::invalid_argument if \e output or \e input is too
  /// short.
  [[nodiscard]]
  std::variant<std::error_code, size_t>
  Encrypt(std::span<const byte> input, std::span<byte> output,
          size_t op_id) noexcept;

  // [[nodiscard]]
  // inline std::error_code
  // Encrypt(std::span<const byte> input, Bytes& output, size_t op_id) {
  //   output.reserve(input.size() + ABYTES);
  //   auto result = Encrypt(input, std::span(output), op_id);
  //   if (std::holds_alternative<std::error_code>(result)) {
  //     return std::move(std::get<std::error_code>(result));
  //   }
  //   output.resize(std::get<size_t>(result));
  //   return {};
  // }

  /// Encrypt \e input and return the result.
  ///
  /// \return Either an error code or the resulting ciphertext.
  /// In addition to error codes \ref AsyncEncrypt_doc Encrypt() can return,
  /// it may return a code stored in an exception thrown by
  /// \e std::vector::vector(size_type) or \e std::vector::resize(size_type).
  [[nodiscard]]
  inline std::variant<std::error_code, Bytes>
  Encrypt(std::span<const byte> input, size_t op_id) noexcept {
    try {
      Bytes output(input.size() + ABYTES);
      auto result = Encrypt(input, output, op_id);
      if (std::holds_alternative<std::error_code>(result)) {
        return std::move(std::get<std::error_code>(result));
      }
      output.resize(std::get<size_t>(result));
      return output;
    } catch (std::system_error& e) {
      return e.code();
    }
  }

  /// \anchor AsyncDecrypt_doc
  ///
  /// Decrypt \e input and put it in \e output.
  ///
  /// \param[in] input Array of bytes to be decrypted. Must be larger than
  /// \ref ABYTES. Empty messages are disallowed.
  ///
  /// \param[out] output Place to store the result. Its size must be at least
  /// \verbatim input.size() - ABYTES \endverbatim. The final size of the
  /// output is returned so that the size of the container storing it may be
  /// adjusted. Can overlap with \e input.
  ///
  /// \param[in] op_id Operation ID. Must be unique for every Encrypt-Decrypt
  /// operation. It has to be the same \e op_id that was used for encryption.
  ///
  /// \return Final size of the output. It may be shorter than
  /// \e output.size().
  /// \return \e std::errc::invalid_argument if \e output is too short.
  /// \return \e std::errc::bad_message if a message stored at \e input is
  /// invalid, incomplete or corrupt or if the \e op_id is incorrect.
  [[nodiscard]]
  std::variant<std::error_code, size_t>
  Decrypt(std::span<const byte> input, std::span<byte> output,
          size_t op_id) noexcept;

  // [[nodiscard]]
  // inline std::error_code
  // Decrypt(std::span<const byte> input, Bytes& output, size_t op_id) {
  //   output.reserve(input.size() + ABYTES);
  //   auto result = Decrypt(input, std::span(output), op_id);
  //   if (std::holds_alternative<std::error_code>(result)) {
  //     return std::move(std::get<std::error_code>(result));
  //   }
  //   output.resize(std::get<size_t>(result));
  //   return {};
  // }

  /// Decrypt \e input and return the result.
  ///
  /// \return Either an error code or the resulting cleartext.
  /// In addition to error codes \ref AsyncDecrypt_doc Decrypt() can return,
  /// it may return a code stored in an exception thrown by
  /// \e std::vector::vector(size_type) or \e std::vector::resize(size_type).
  [[nodiscard]]
  inline std::variant<std::error_code, Bytes>
  Decrypt(std::span<const byte> input, size_t op_id) noexcept {
    if (input.size_bytes() < ABYTES) {
      return std::make_error_code(std::errc::invalid_argument);
    }
    try {
      Bytes output(input.size() - ABYTES);
      auto result = Decrypt(input, output, op_id);
      if (std::holds_alternative<std::error_code>(result)) {
        return std::move(std::get<std::error_code>(result));
      }
      output.resize(std::get<size_t>(result));
      return output;
    } catch (std::system_error& e) {
      return e.code();
    }
  }

 private:
  std::array<byte, NONCE_BYTES> compute_nonce(size_t op_id) noexcept;

  std::array<byte, KEY_BYTES> key_;
  std::array<byte, NONCE_BYTES> nonce_base_;
};
}

#endif /* ASYNCCIPHERSTREAM_H */
