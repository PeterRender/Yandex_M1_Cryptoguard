#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <sstream>
#include <string>
#include <vector>

// Массив вариантов входных тестовых строк
static const std::vector<std::string> testStrings = {
    "Hello, Yandex Practicum!",  // строка длиной < длины буфера (1024 байт)
    std::string(5000, 'P'),      // строка длиной > длины буфера (1024 байт)
    "",                          // пустая строка
};

// Пароль, используемый в тестах для шифрования/дешифрования данных
static const std::string MY_PASS = "qwe1234";

// ====== ТЕСТЫ ШИФРОВАНИЯ ======

// Тест шифрования корректного входного строкового потока
TEST(CryptoGuardCtx, EncryptValidInputStream) {
    // Цикл по вариантам тестовых строк
    for (const std::string &rTestStr : testStrings) {
        CryptoGuard::CryptoGuardCtx cryptoCtx;
        std::stringstream inStream(rTestStr);  // входной строковый поток
        std::stringstream outStream;           // выходной строковый поток с зашифрованными данными

        // Шифрование должно пройти без исключений
        ASSERT_NO_THROW(cryptoCtx.EncryptFile(inStream, outStream, MY_PASS));
        // Выходной поток должен быть не пустой
        EXPECT_FALSE(outStream.str().empty());
        // Входной и выходной потоки должны отличаться
        EXPECT_NE(inStream.str(), outStream.str());
    }
}

// Тест повторного шифрования корректного входного строкового потока
TEST(CryptoGuardCtx, DoubleEncryptValidInputStream) {
    // Цикл по вариантам тестовых строк
    for (const std::string &rTestStr : testStrings) {
        CryptoGuard::CryptoGuardCtx cryptoCtx;
        std::stringstream inStream(rTestStr);                 // входной строковый поток
        std::stringstream outStream;                          // выходной строковый поток с зашифрованными данными
        cryptoCtx.EncryptFile(inStream, outStream, MY_PASS);  // шифруем данные с заданным паролем
        std::string firstOutput = outStream.str();            // запомним результат первого прохода

        // Повторное шифрование должно пройти без исключений
        ASSERT_NO_THROW(cryptoCtx.EncryptFile(inStream, outStream, MY_PASS));
        // Выходной поток должен быть не пустой
        EXPECT_FALSE(outStream.str().empty());
        // Результат второго прохода должен совпадать с результатом первого прохода
        EXPECT_EQ(outStream.str(), firstOutput);
    }
}

// Тест шифрования некорректного входного строкового потока
TEST(CryptoGuardCtx, EncryptInvalidInputStream) {
    // Цикл по вариантам тестовых строк
    for (const std::string &rTestStr : testStrings) {
        CryptoGuard::CryptoGuardCtx cryptoCtx;
        std::stringstream inStream(rTestStr);  // входной строковый поток
        std::stringstream outStream;           // выходной строковый поток с зашифрованными данными

        inStream.setstate(std::ios::badbit);  // поднимем флаг ошибки во входном потоке

        // Шифрование должно бросить исключение
        ASSERT_THROW(cryptoCtx.EncryptFile(inStream, outStream, MY_PASS), std::runtime_error);
    }
}

// Тест шифрования с некорректным выходным строковым потоком
TEST(CryptoGuardCtx, EncryptInvalidOutputStream) {
    // Цикл по вариантам тестовых строк
    for (const std::string &rTestStr : testStrings) {
        CryptoGuard::CryptoGuardCtx cryptoCtx;
        std::stringstream inStream(rTestStr);  // входной строковый поток
        std::stringstream outStream;           // выходной строковый поток с зашифрованными данными

        outStream.setstate(std::ios::badbit);  // поднимем флаг ошибки в выходном потоке

        // Шифрование должно бросить исключение
        ASSERT_THROW(cryptoCtx.EncryptFile(inStream, outStream, MY_PASS), std::runtime_error);
    }
}

// ====== ТЕСТЫ ДЕШИФРОВАНИЯ ======

// Тест дешифрования корректного входного строкового потока с правильным паролем
TEST(CryptoGuardCtx, DecryptWithCorrectPass) {
    // Цикл по вариантам тестовых строк
    for (const std::string &rTestStr : testStrings) {
        CryptoGuard::CryptoGuardCtx cryptoCtx;
        std::stringstream inStream(rTestStr);                       // входной строковый поток
        std::stringstream encryptedStream;                          // выходной строковый поток с зашифрованными данными
        std::stringstream decryptedStream;                          // выходной строковый поток с дешифрованными данными
        cryptoCtx.EncryptFile(inStream, encryptedStream, MY_PASS);  // шифруем данные с заданным паролем

        // Дешифрование с правильным паролем должно пройти без исключений
        ASSERT_NO_THROW(cryptoCtx.DecryptFile(encryptedStream, decryptedStream, MY_PASS));
        // Проверяем, что получили исходную тестовую строку
        EXPECT_EQ(rTestStr, decryptedStream.str());
    }
}

// Тест повторного дешифрования корректного входного строкового потока с правильным паролем
TEST(CryptoGuardCtx, DoubleDecryptWithCorrectPass) {
    // Цикл по вариантам тестовых строк
    for (const std::string &rTestStr : testStrings) {
        CryptoGuard::CryptoGuardCtx cryptoCtx;
        std::stringstream inStream(rTestStr);                       // входной строковый поток
        std::stringstream encryptedStream;                          // выходной строковый поток с зашифрованными данными
        std::stringstream decryptedStream;                          // выходной строковый поток с дешифрованными данными
        cryptoCtx.EncryptFile(inStream, encryptedStream, MY_PASS);  // шифруем данные
        cryptoCtx.DecryptFile(encryptedStream, decryptedStream, MY_PASS);  // дешифруем данные

        // Повторное дешифрование должно пройти без исключений
        ASSERT_NO_THROW(cryptoCtx.DecryptFile(encryptedStream, decryptedStream, MY_PASS));
        // Проверяем, что получили исходную тестовую строку (выходной поток перезаписыается, а не дополняется)
        EXPECT_EQ(rTestStr, decryptedStream.str());
    }
}

// Тест дешифрования корректного входного строкового потока с неправильным паролем
TEST(CryptoGuardCtx, DecryptWithWrongPass) {
    // Цикл по вариантам тестовых строк
    for (const std::string &rTestStr : testStrings) {
        CryptoGuard::CryptoGuardCtx cryptoCtx;
        std::stringstream inStream(rTestStr);                       // входной строковый поток
        std::stringstream encryptedStream;                          // выходной строковый поток с зашифрованными данными
        std::stringstream decryptedStream;                          // выходной строковый поток с дешифрованными данными
        cryptoCtx.EncryptFile(inStream, encryptedStream, MY_PASS);  // шифруем данные с заданным паролем

        // Дешифрование с неправильным паролем должно бросить исключение
        ASSERT_THROW(cryptoCtx.DecryptFile(encryptedStream, decryptedStream, MY_PASS + "123"), std::runtime_error);
    }
}

// Тест дешифрования поврежденных данных (не содержащих валидные зашифрованные AES-блоки)
TEST(CryptoGuardCtx, DecryptBadData) {
    // Цикл по вариантам тестовых строк
    for (const std::string &rTestStr : testStrings) {
        CryptoGuard::CryptoGuardCtx cryptoCtx;
        std::stringstream badStream(rTestStr);  // входной строковый поток с "поврежденными" зашифрованными данными
        std::stringstream outStream;            // выходной строковый поток с дешифрованными данными

        // Дешифрование должно бросить исключение
        ASSERT_THROW(cryptoCtx.DecryptFile(badStream, outStream, MY_PASS), std::runtime_error);
    }
}

// ====== ТЕСТЫ ШИФРОВАНИЯ/ДЕШИФРОВАНИЯ ======

// Тест серии корректных шифрований/дешифрований с помощью одного экземпляра класса CryptoGuardCtx
TEST(CryptoGuardCtx, SeriesEncryptDecrypt) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    // Цикл по вариантам тестовых строк
    for (const std::string &rTestStr : testStrings) {
        std::stringstream inStream(rTestStr);  // входной строковый поток
        std::stringstream encryptedStream;     // выходной строковый поток с зашифрованными данными
        std::stringstream decryptedStream;     // выходной строковый поток с дешифрованными данными

        // Шифрование должно пройти без исключений
        ASSERT_NO_THROW(cryptoCtx.EncryptFile(inStream, encryptedStream, MY_PASS));
        // Выходной зашифрованными поток должен быть не пустой
        EXPECT_FALSE(encryptedStream.str().empty());
        // Входной и выходной зашифрованный потоки должны отличаться
        EXPECT_NE(inStream.str(), encryptedStream.str());
        // Дешифрование с правильным паролем должно пройти без исключений
        ASSERT_NO_THROW(cryptoCtx.DecryptFile(encryptedStream, decryptedStream, MY_PASS));
        // Проверяем, что получили исходную тестовую строку
        EXPECT_EQ(rTestStr, decryptedStream.str());
    }
}

// ====== ТЕСТЫ ПОДСЧЕТА КОНТРОЛЬНОЙ СУММЫ ======
