#include "crypto_guard_ctx.h"
#include <array>
#include <openssl/evp.h>  // для подключения OpenSSL функций

namespace CryptoGuard {

// Внутренний класс, реализующий функционал класса CryptoGuardCtx
class CryptoGuardCtx::Impl {
public:
    Impl() {
        // Инициализация библиотеки OpenSSL
        OpenSSL_add_all_algorithms();
    }

    ~Impl() {
        // Освобождение ресурсов, выделенных для библиотеки OpenSSL
        EVP_cleanup();
    }

    // Параметры AES-256 шифрования (Advanced Encryption Standard - симметричный алгоритм блочного шифрования)
    struct AesCipherParams {
        static const size_t KEY_SIZE = 32;  // размер ключа шифрования AES-256, в байтах
        static const size_t IV_SIZE = 16;   // размер блока AES, в байтах

        // Указатель на функцию OpenSSL для AES-256-CBC, где CBC (Cipher Block Chaining) -
        // режим, в котором каждый блок зависит от предыдущего
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();

        int encrypt;  // флаг типа действия (0 - дешифрование, 1 - шифрование)

        // Ключ шифрования (32 байта = 256 бит)
        std::array<unsigned char, KEY_SIZE> key;
        // Вектор инициализации (16 байт = 128 бит), предотвращает повторение шифрования одинаковых данных
        std::array<unsigned char, IV_SIZE> iv;
    };

    // Метод, преобразующий пароль пользователя в криптографический ключ для AES-256 шифрования.
    AesCipherParams CreateCipherParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        // "Соль" - последовательность бит, которая добавляется к данным перед шифрованием, увеличивая длину и
        // сложность пароля (повышает стойкость к атакам с помощью радужных таблиц, перебора паролей). В данном проекте
        // используется статическая соль.
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result =
            EVP_BytesToKey(params.cipher,  // функция шифрования AES-256-CBC
                           EVP_sha256(),   // хеш-функция (SHA-256)
                           salt.data(),    // "cоль" для повышения сложности пароля
                           reinterpret_cast<const unsigned char *>(password.data()),  // входной пароль пользователя
                           password.size(),    // длина входного пароля пользователя
                           1,                  // число итераций
                           params.key.data(),  // выходной ключ шифрования AES-256
                           params.iv.data());  // выходной вектор инициализации

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }

    // Заготовки методов, реализующих API класса CryptoGuardCtx
    void EncryptFileImpl(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}
    void DecryptFileImpl(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}
    std::string CalculateChecksumImpl(std::iostream &inStream) { return "NOT_IMPLEMENTED"; }
};

// Определение конструктора по-умолчанию класса CryptoGuardCtx
CryptoGuardCtx::CryptoGuardCtx()
    : pImpl_(std::make_unique<Impl>())  // создаем экземпляр внутреннего класса Impl
{}

// Явное определение деструктора по-умолчанию класса CryptoGuardCtx
CryptoGuardCtx::~CryptoGuardCtx() = default;

// Методы-обертки, делегирующие вызовы API класса CryptoGuardCtx внутреннему классу Impl
void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFileImpl(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFileImpl(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) {
    return pImpl_->CalculateChecksumImpl(inStream);
}

}  // namespace CryptoGuard
