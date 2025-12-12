#include "crypto_guard_ctx.h"
#include <array>   // для подключения шаблона статического массива
#include <format>  // для подключения шаблона форматируемой строки
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
    // Конструктор по умолчанию.
    Impl() {
        OpenSSL_add_all_algorithms();  // инициализация библиотеки OpenSSL
    }

    // Деструктор
    ~Impl() {
        EVP_cleanup();  // освобождение ресурсов, выделенных для библиотеки OpenSSL
    }

    // Метод, реализующий шифрование файла в API класса CryptoGuardCtx.
    void EncryptFileImpl(std::iostream &inStream, std::iostream &outStream, std::string_view password);

    // Метод, реализующий дешифрование файла в API класса CryptoGuardCtx.
    void DecryptFileImpl(std::iostream &inStream, std::iostream &outStream, std::string_view password);

    // Метод, реализующий подсчёт контрольной суммы файла в API класса CryptoGuardCtx.
    std::string CalculateChecksumImpl(std::iostream &inStream) { return "NOT_IMPLEMENTED"; }

private:
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

    // Метод, реализующий шифрование/дешифрование строкового потока файла
    void DoCrypt(std::iostream &inStream, std::iostream &outStream, std::string_view password, int doEncrypt);
};

// Метод, реализующий шифрование/дешифрование строкового потока файла
void CryptoGuardCtx::Impl::DoCrypt(std::iostream &inStream, std::iostream &outStream, std::string_view password,
                                   int doEncrypt) {
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
    AesCipherParams params = CreateCipherParamsFromPassword(password);  // здесь работает RVO-оптимизация компилятора.
    params.encrypt = doEncrypt;  // указываем OpenSSL тип выполняемой операции (0 - дешифрование, 1 - шифрование)

    // Согласно документации OpenSSL (https://docs.openssl.org/master/man3/EVP_EncryptInit/#examples) инициализация
    // контекста OpenSSL выполняется с помощью EVP_CipherInit_ex2 (вместо deprecated EVP_CipherInit_ex) в два этапа:
    // 1) сначала нужно получить длины ключа шифрования и вектора инициализации и проверить их значения (для AES-256-CBC
    // они должны быть 32 и 16 байт); 2) затем выполняется инициализация контекста OpenSSL значениями ключа шифрования и
    // вектора инициализации

    // Получение длин ключа шифрования и вектора инициализации
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
        throw std::runtime_error{"Failed to initialize OpenSSL context"};
    }

    // Создание буферов для чтения входных (исходных/шифрованных) данных и записи выходных (шифрованных/дешифрованных)
    // данных (т.к. буферы малого размера, то используем более быструю статическую память)
    static const size_t BUF_SIZE = 1024;  // размер входного буфера, в байтах (кратен 16 байтам - размеру блока в AES)
    std::array<unsigned char, BUF_SIZE> inBuf{};
    std::array<unsigned char, BUF_SIZE + EVP_MAX_BLOCK_LENGTH> outBuf{};  // размер выходного буфера с учетом padding
    int outLen = 0;

    std::string cryptoAction = doEncrypt ? ("encrypt") : ("decrypt");
    auto updateErrStr = std::format("Failed to {} data", cryptoAction);
    auto finalErrStr = std::format("Failed to {} final block", cryptoAction);

    // Цикл криптографической обработки входных данных
    for (;;) {
        // Чтение данных из входного потока в буфер
        inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
        // Проверка состояния входного потока после чтения данных
        if (inStream.bad()) {
            throw std::runtime_error{"Failed to read data from input stream"};
        }

        // Получение числа фактически прочитанных байт (может быть < BUF_SIZE в конце файла)
        auto bytesRead = inStream.gcount();
        if (bytesRead <= 0)  // дошли до конца потока (-1) или все блоки были уже извлечены ранее (0)
            break;

        // Шифрование/дешифрование данных
        if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(bytesRead))) {
            throw std::runtime_error{updateErrStr};
        }

        // Запись полученных после криптообработки данных в выходной поток
        outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
        // Проверка состояния выходного потока после записи данных
        if (!outStream.good()) {
            throw std::runtime_error{"Failed to write processed data to output stream"};
        }
    }

    // Шифрование/дешифрование финального блока данных (padding-блока при шифровании)
    if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
        throw std::runtime_error{finalErrStr};
    }

    // Если финальный блок ненулевого размера, то записываем его в выходной поток
    if (outLen > 0) {
        outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
        // Проверка состояния выходного потока после записи финального блока
        if (!outStream.good()) {
            throw std::runtime_error{"Failed to write final block to output stream"};
        }
    }
}

// Метод, реализующий шифрование файла в API класса CryptoGuardCtx.
void CryptoGuardCtx::Impl::EncryptFileImpl(std::iostream &inStream, std::iostream &outStream,
                                           std::string_view password) {
    DoCrypt(inStream, outStream, password, 1);
}

// Метод, реализующий дешифрование файла в API класса CryptoGuardCtx.
void CryptoGuardCtx::Impl::DecryptFileImpl(std::iostream &inStream, std::iostream &outStream,
                                           std::string_view password) {
    DoCrypt(inStream, outStream, password, 0);
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
