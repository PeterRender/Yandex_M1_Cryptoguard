#include "crypto_guard_ctx.h"
#include <array>    // для подключения шаблона статического массива
#include <format>   // для подключения шаблона форматируемой строки
#include <iomanip>  // для форматирования строкового потока
#include <iostream>
#include <memory>         // для подключения std::unique_ptr
#include <openssl/err.h>  // для расшифровки ошибок OpenSSL
#include <openssl/evp.h>  // для подключения OpenSSL функций
#include <sstream>
#include <stdexcept>

namespace CryptoGuard {

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
    std::string CalculateChecksumImpl(std::iostream &inStream);

private:
    // Создадим псевдоним умного указателя на контекст шифрования OpenSSL с пользовательским "удалителем".
    // "Удалитель" реализован с помощью лямбда-функции (т.к. имя лямбды генерирует компилятор, ее тип указан через
    // decltype). Для EVP_CIPHER_CTX_free значение nullptr является валидным, поэтому проверка не нужна
    using EVP_CIPHER_CTX_Ptr =
        std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })>;

    // Создадим псевдоним умного указателя на хеш-контекст OpenSSL аналогично контексту шифрования
    using EVP_MD_CTX_Ptr = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *mdctx) { EVP_MD_CTX_free(mdctx); })>;

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
            throw std::runtime_error{std::format("Failed to create a key from password: {}", GetOpenSSLErrorStr())};
        }

        return params;
    }

    // Подготавливает строковый поток к операции чтения/записи.
    void PrepareStreamForIO(std::iostream &strStream, bool isInput) {
        // Проверка состояния потока на критические ошибки
        if (strStream.bad()) {
            throw std::runtime_error{std::format("{} stream is corrupted", isInput ? "Input" : "Output")};
        }

        // Сброс всех флагов состояния (goodbit, eofbit, failbit, badbit)
        strStream.clear();

        // Установка позиции в начало
        if (isInput)
            strStream.seekg(0, std::ios::beg);  // для чтения
        else
            strStream.seekp(0, std::ios::beg);  // для записи

        // Проверка успешного перехода в начало потока
        if (strStream.fail()) {
            throw std::runtime_error{std::format("Failed to seek {} stream", isInput ? "input" : "output")};
        }
    }

    // Метод получения текстовой расшифровки ошибки OpenSSL
    std::string GetOpenSSLErrorStr() {
        char errBuf[256];
        unsigned long errCode = ERR_get_error();  // получим код первой ошибки OpenSSL из очереди

        if (errCode == 0) {
            return "There is no OpenSSL error";
        }

        // Текстовая расшифровка кода ошибки OpenSSL
        ERR_error_string_n(errCode, errBuf, sizeof(errBuf));
        return std::string(errBuf);
    }

    // Метод, реализующий шифрование/дешифрование строкового потока файла
    void DoCrypt(std::iostream &inStream, std::iostream &outStream, std::string_view password, int doEncrypt);
};

// Метод, реализующий шифрование/дешифрование строкового потока файла
void CryptoGuardCtx::Impl::DoCrypt(std::iostream &inStream, std::iostream &outStream, std::string_view password,
                                   int doEncrypt) {
    // Подготовка входного и выходного потоков
    PrepareStreamForIO(inStream, true);    // к операции чтения
    PrepareStreamForIO(outStream, false);  // к операции записи

    // Создание контекста шифрования OpenSSL с умным указателем
    EVP_CIPHER_CTX_Ptr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw std::runtime_error{std::format("Failed to create OpenSSL cipher context: {}", GetOpenSSLErrorStr())};
    }

    // Создание ключа шифрования AES-256 из пароля пользователя
    AesCipherParams params = CreateCipherParamsFromPassword(password);  // работает RVO-оптимизация, копирования нет
    params.encrypt = doEncrypt;  // указываем OpenSSL тип выполняемой операции (0 - дешифрование, 1 - шифрование)

    // Согласно документации OpenSSL (https://docs.openssl.org/master/man3/EVP_EncryptInit/#examples) инициализация
    // контекста шифрования OpenSSL выполняется с помощью EVP_CipherInit_ex2 (вместо deprecated EVP_CipherInit_ex) в
    // два этапа: 1) сначала нужно получить длины ключа шифрования и вектора инициализации и проверить их значения
    // (для AES-256-CBC они должны быть 32 и 16 байт); 2) затем выполняется инициализация контекста шифрования
    // OpenSSL значениями ключа шифрования и вектора инициализации

    // Получение длин ключа шифрования и вектора инициализации
    if (!EVP_CipherInit_ex2(ctx.get(), params.cipher, nullptr, nullptr, params.encrypt, nullptr)) {
        throw std::runtime_error{std::format("Failed to get key and IV lengths: {}", GetOpenSSLErrorStr())};
    }
    // Проверка корректности полученных длин
    if (EVP_CIPHER_CTX_get_key_length(ctx.get()) != AesCipherParams::KEY_SIZE ||
        EVP_CIPHER_CTX_get_iv_length(ctx.get()) != AesCipherParams::IV_SIZE) {
        throw std::runtime_error{std::format("Invalid key or IV length: {}", GetOpenSSLErrorStr())};
    }
    // Инициализация контекста шифрования OpenSSL значениями ключа шифрования и вектора инициализации
    if (!EVP_CipherInit_ex2(ctx.get(), nullptr, params.key.data(), params.iv.data(), params.encrypt, nullptr)) {
        throw std::runtime_error{std::format("Failed to init OpenSSL context: {}", GetOpenSSLErrorStr())};
    }

    // Создание буферов для чтения входных (исходных/шифрованных) данных и записи выходных
    // (шифрованных/дешифрованных) данных (т.к. буферы малого размера, то используем более быструю статическую
    // память)
    static const size_t BUF_SIZE = 1024;  // размер входного буфера, в байтах (кратен 16 байтам - размеру блока в AES)
    std::array<unsigned char, BUF_SIZE> inBuf{};
    std::array<unsigned char, BUF_SIZE + EVP_MAX_BLOCK_LENGTH> outBuf{};  // размер выходного буфера с учетом padding
    int outLen = 0;

    std::string cryptoAction = doEncrypt ? ("encrypt") : ("decrypt");

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
            throw std::runtime_error{std::format("Failed to {} data: {}", cryptoAction, GetOpenSSLErrorStr())};
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
        throw std::runtime_error{std::format("Failed to {} final block: {}", cryptoAction, GetOpenSSLErrorStr())};
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

// Метод, реализующий подсчёт контрольной суммы файла в API класса CryptoGuardCtx.
std::string CryptoGuardCtx::Impl::CalculateChecksumImpl(std::iostream &inStream) {
    // Подготовка входного потока к операции чтения.
    PrepareStreamForIO(inStream, true);

    // Создание хеш-контекста OpenSSL с умным указателем
    EVP_MD_CTX_Ptr mdctx(EVP_MD_CTX_new());
    if (!mdctx) {
        throw std::runtime_error{std::format("Failed to create hash context: {}", GetOpenSSLErrorStr())};
    }

    // Инициализация хеш-контекста OpenSSL алгоритмом SHA-256
    // (функция EVP_sha256() возвращает указатель на структуру, описывающую алгоритм SHA-256)
    if (!EVP_DigestInit_ex(mdctx.get(), EVP_sha256(), nullptr)) {
        throw std::runtime_error{std::format("Failed to init hash context with SHA-256: {}", GetOpenSSLErrorStr())};
    }

    // Создание буфера для чтения входных данных (чтение реализуется порционно для поддержки больших файлов)
    static const size_t BUF_SIZE = 1024;  // размер буфера, в байтах (кратен 64 байтам - размеру блока в SHA-256)
    std::array<unsigned char, BUF_SIZE> inBuf{};

    // Цикл подсчета хеша входных данных
    while (true) {
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

        // Обновление хеша входных данных
        if (!EVP_DigestUpdate(mdctx.get(), inBuf.data(), bytesRead)) {
            throw std::runtime_error{std::format("Failed to update hash: {}", GetOpenSSLErrorStr())};
        }
    }

    // Создание буфера для финального хеша
    std::array<unsigned char, EVP_MAX_MD_SIZE> hashResult{};  // длина буфера = max размеру хеша в OpenSSL
    unsigned int hashLength = 0;  // сюда запишется реальная длина хеша (для SHA256 - 32 байта)

    // Получение финального хеша
    if (!EVP_DigestFinal_ex(mdctx.get(), hashResult.data(), &hashLength)) {
        throw std::runtime_error{std::format("Failed to finalize hash: {}", GetOpenSSLErrorStr())};
    }

    // Создание строкового потока для преобразования хеша в hex-строку
    std::stringstream hexStream;
    hexStream << std::hex << std::setfill('0');

    // Каждый байт хеша преобразуем в два hex-символа (setw(2) гарантирует вывод вида 0x0F -> "0f")
    for (unsigned int i = 0; i < hashLength; i++) {
        hexStream << std::setw(2) << static_cast<int>(hashResult[i]);
    }

    return hexStream.str();
}

// Определение конструктора по-умолчанию класса CryptoGuardCtx
CryptoGuardCtx::CryptoGuardCtx()
    : pImpl_(std::make_unique<Impl>())  // создаем экземпляр внутреннего класса Impl
{}

// Явное определение деструктора по-умолчанию класса CryptoGuardCtx
CryptoGuardCtx::~CryptoGuardCtx() = default;

// === Методы-обертки, делегирующие вызовы API класса CryptoGuardCtx внутреннему классу Impl ===
// Метод шифрования файла.
void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFileImpl(inStream, outStream, password);
}

// Метод дешифрования файла.
void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFileImpl(inStream, outStream, password);
}

// Метод подсчета контрольной суммы файла.
std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) {
    return pImpl_->CalculateChecksumImpl(inStream);
}

}  // namespace CryptoGuard
