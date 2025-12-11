#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <sstream>

// Тест шифрования входного строкового потока длиной < длины буфера (1024 байт)
TEST(CryptoGuardCtx, EncryptSmallInputStream) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inStream("Hello, Yandex Practicum!");  // входной строковый поток
    std::stringstream outStream;                             // выходной строковый поток с зашифрованными данными

    // Шифрование должно пройти без исключений
    ASSERT_NO_THROW(cryptoCtx.EncryptFile(inStream, outStream, "1234"));
    // Выходной поток должен быть не пустой
    EXPECT_FALSE(outStream.str().empty());
    // Входной и выходной потоки должны отличаться
    EXPECT_NE(inStream.str(), outStream.str());
}

// Тест шифрования входного строкового потока длиной > длины буфера (1024 байт)
TEST(CryptoGuardCtx, EncryptBigInputStream) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inStream(std::string(5000, 'P'));  // входной строковый поток из 5000 символов 'P'
    std::stringstream outStream;                         // выходной строковый поток с зашифрованными данными

    // Шифрование должно пройти без исключений
    ASSERT_NO_THROW(cryptoCtx.EncryptFile(inStream, outStream, "1234"));
    // Выходной поток должен быть не пустой
    EXPECT_FALSE(outStream.str().empty());
    // Входной и выходной потоки должны отличаться
    EXPECT_NE(inStream.str(), outStream.str());
}

// Тест шифрования пустого входного строкового потока
TEST(CryptoGuardCtx, EncryptEmptyInputStream) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inStream;   // пустой входной строковый поток
    std::stringstream outStream;  // выходной строковый поток с зашифрованными данными

    // Шифрование должно пройти без исключений
    ASSERT_NO_THROW(cryptoCtx.EncryptFile(inStream, outStream, "1234"));
    // Выходной поток должен быть не пустой (добавится зашифрованная "соль")
    EXPECT_FALSE(outStream.str().empty());
}

// Тест шифрования некорректного входного строкового потока
TEST(CryptoGuardCtx, EncryptInvalidInputStream) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inStream("Hello, Yandex Practicum!");  // входной строковый поток
    std::stringstream outStream;                             // выходной строковый поток с зашифрованными данными
    inStream.setstate(std::ios::badbit);                     // поднимем флаг ошибки во входном потоке

    // Шифрование должно бросить исключение
    ASSERT_THROW(cryptoCtx.EncryptFile(inStream, outStream, "1234"), std::runtime_error);
}

// Тест шифрования с некорректным выходным строковым потоком
TEST(CryptoGuardCtx, EncryptInvalidOutputStream) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inStream("Hello, Yandex Practicum!");  // входной строковый поток
    std::stringstream outStream;                             // выходной строковый поток с зашифрованными данными
    outStream.setstate(std::ios::badbit);                    // поднимем флаг ошибки в выходном потоке

    // Шифрование должно бросить исключение
    ASSERT_THROW(cryptoCtx.EncryptFile(inStream, outStream, "1234"), std::runtime_error);
}
