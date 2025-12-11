#include "crypto_guard_ctx.h"
#include <array>
#include <iostream>
#include <memory>         // для подключения std::unique_ptr
#include <openssl/evp.h>  // для подключения OpenSSL функций
#include <stdexcept>

namespace CryptoGuard {

// Создадим пользовательский "удалитель" контекста OpenSSL с помощью лямбда-функции
// Согласно документации OpenSSL для EVP_CIPHER_CTX_free значение nullptr является валидным (проверка не нужна)
auto EVP_CIPHER_CTX_Deleter = [](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); };
// Обернем "удалитель" в псевдоним (т.к. имя лямбды генерирует компилятор, то указываем ее тип с помощью decltype)
using EVP_CIPHER_CTX_Ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(EVP_CIPHER_CTX_Deleter)>;

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

        int encrypt;  // флаг шифрования (0 - дешифрование, 1 - шифрование)

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

    // Методы, реализующие API класса CryptoGuardCtx
    void EncryptFileImpl(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void DecryptFileImpl(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}
    std::string CalculateChecksumImpl(std::iostream &inStream) { return "NOT_IMPLEMENTED"; }
};

// Метод, реализующий шифрование файла в API класса CryptoGuardCtx.
void CryptoGuardCtx::Impl::EncryptFileImpl(std::iostream &inStream, std::iostream &outStream,
                                           std::string_view password) {
    // Проверка состояний входного и выходного потоков перед шифрованием
    if (!inStream.good()) {
        throw std::runtime_error{"Input stream is not ready for I/O operations"};
    }
    if (!outStream.good()) {
        throw std::runtime_error{"Output stream is not ready for I/O operations"};
    }

    // Создание контекста OpenSSL с умным указателем
    EVP_CIPHER_CTX_Ptr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw std::runtime_error{"Failed to create OpenSSL context"};
    }

    // Создание ключа шифрования AES-256 из пароля пользователя
    AesCipherParams params = CreateCipherParamsFromPassword(password);
    params.encrypt = 1;  // указываем OpenSSL, что будет шифрование данных

    // Получение длин ключа шифрования и вектора инициализации для AES-256-CBC (должны быть 32 и 16 байт)
    // (https://docs.openssl.org/master/man3/EVP_EncryptInit/#examples)
    // Используется функция EVP_CipherInit_ex2 вместо deprecated функции EVP_CipherInit_ex
    if (!EVP_CipherInit_ex2(ctx.get(), params.cipher, nullptr, nullptr, params.encrypt, nullptr)) {
        throw std::runtime_error{"Failed to get key and IV lengths"};
    }
    // Проверка корректности полученных длин
    if (EVP_CIPHER_CTX_get_key_length(ctx.get()) != AesCipherParams::KEY_SIZE ||
        EVP_CIPHER_CTX_get_iv_length(ctx.get()) != AesCipherParams::IV_SIZE) {
        throw std::runtime_error{"Invalid key or IV length"};
    }

    // Инициализация контекста OpenSSL значениями ключа шифрования и вектора инициализации
    if (!EVP_CipherInit_ex2(ctx.get(), nullptr, params.key.data(), params.iv.data(), params.encrypt, nullptr)) {
        throw std::runtime_error{"Failed to initialize OpenSSL context for encryption"};
    }

    // Создание буферов для чтения входных данных и записи зашифрованных выходных данных
    const size_t BUF_SIZE = 1024;  // размер буфера данных, в байтах (кратен 16 байтам - размеру блока в AES)
    // Т.к. буферы малого размера, то используем более быструю статическую память
    std::array<unsigned char, BUF_SIZE> inBuf{};
    std::array<unsigned char, BUF_SIZE + EVP_MAX_BLOCK_LENGTH> outBuf{};  // резервируем в буфере место под padding
    int outLen = 0;

    // Цикл чтения/шифрования входных данных
    for (;;) {
        // Чтение данных из входного потока
        inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
        // Проверка состояния входного потока после чтения данных
        if (inStream.bad()) {
            throw std::runtime_error{"Failed to read block from input stream"};
        }

        // Получение числа фактически прочитанных байт (может быть < BUF_SIZE в конце файла)
        auto bytesRead = inStream.gcount();
        if (bytesRead <= 0)  // дошли до конца потока (-1) или все блоки были уже извлечены ранее (0)
            break;

        // Шифрование блока данных
        if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(bytesRead))) {
            throw std::runtime_error{"Failed to encrypt block"};
        }

        // Запись зашифрованного блока данных в выходной поток
        outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
        // Проверка состояния выходного потока после записи зашифрованного блока
        if (!outStream.good()) {
            throw std::runtime_error{"Failed to write encrypted block to output stream"};
        }
    }

    // Шифрование финального padding-блока
    if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
        throw std::runtime_error{"Failed to encrypt final padding-block"};
    }

    // Если финальный padding-блок ненулевого размера, то записываем его в выходной поток
    if (outLen > 0) {
        outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
        // Проверка состояния выходного потока после записи финального padding-блока
        if (!outStream.good()) {
            throw std::runtime_error{"Failed to write final block to output stream"};
        }
    }
}

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
