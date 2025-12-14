#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <sstream>
#include <string>
#include <vector>

// Структура тестовых данных
struct TestData {
    std::string inputStr;    // тестовая строка
    std::string outputHash;  // эталонный хеш SHA256, посчитанный для тестовой строки
};

// Массив вариантов тестовых данных
static const std::vector<TestData> testVec = {
    {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {"a", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"},
    {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
    {"hello", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
    {"hello world", "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"},
    {"Hello, Yandex Practicum!", "2c37536bc24e4bbdaf4293aa031752b4c85156e5acdc4fc03a43e7947fa04010"},
    {std::string(1500, 'P'),
     "23bde8a0bfba1c5b9d51b2d2a30eb22528e1d170282ac4acead139ec3c956504"},  // длина строки > длины буфера (1024 байт)
};

// Пароль, используемый в тестах для шифрования/дешифрования данных
static const std::string MY_PASS = "qwe1234";

// ====== ТЕСТЫ ШИФРОВАНИЯ ======

// Тест шифрования корректного входного строкового потока
TEST(CryptoGuardCtx, EncryptValidInputStream) {
    // Цикл по вариантам тестовых данных
    for (const TestData &rTestData : testVec) {
        CryptoGuard::CryptoGuardCtx cryptoCtx;
        std::stringstream inStream(rTestData.inputStr);  // входной строковый поток
        std::stringstream outStream;                     // выходной строковый поток с зашифрованными данными

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
    // Цикл по вариантам тестовых данных
    for (const TestData &rTestData : testVec) {
        CryptoGuard::CryptoGuardCtx cryptoCtx;
        std::stringstream inStream(rTestData.inputStr);       // входной строковый поток
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
    // Цикл по вариантам тестовых данных
    for (const TestData &rTestData : testVec) {
        CryptoGuard::CryptoGuardCtx cryptoCtx;
        std::stringstream inStream(rTestData.inputStr);  // входной строковый поток
        std::stringstream outStream;                     // выходной строковый поток с зашифрованными данными

        inStream.setstate(std::ios::badbit);  // поднимем флаг ошибки во входном потоке

        // Шифрование должно бросить исключение
        ASSERT_THROW(cryptoCtx.EncryptFile(inStream, outStream, MY_PASS), std::runtime_error);
    }
}

// Тест шифрования с некорректным выходным строковым потоком
TEST(CryptoGuardCtx, EncryptInvalidOutputStream) {
    // Цикл по вариантам тестовых данных
    for (const TestData &rTestData : testVec) {
        CryptoGuard::CryptoGuardCtx cryptoCtx;
        std::stringstream inStream(rTestData.inputStr);  // входной строковый поток
        std::stringstream outStream;                     // выходной строковый поток с зашифрованными данными

        outStream.setstate(std::ios::badbit);  // поднимем флаг ошибки в выходном потоке

        // Шифрование должно бросить исключение
        ASSERT_THROW(cryptoCtx.EncryptFile(inStream, outStream, MY_PASS), std::runtime_error);
    }
}

// ====== ТЕСТЫ ДЕШИФРОВАНИЯ ======

// Тест дешифрования корректного входного строкового потока с правильным паролем
TEST(CryptoGuardCtx, DecryptWithCorrectPass) {
    // Цикл по вариантам тестовых данных
    for (const TestData &rTestData : testVec) {
        CryptoGuard::CryptoGuardCtx cryptoCtx;
        std::stringstream inStream(rTestData.inputStr);             // входной строковый поток
        std::stringstream encryptedStream;                          // выходной строковый поток с зашифрованными данными
        std::stringstream decryptedStream;                          // выходной строковый поток с дешифрованными данными
        cryptoCtx.EncryptFile(inStream, encryptedStream, MY_PASS);  // шифруем данные с заданным паролем

        // Дешифрование с правильным паролем должно пройти без исключений
        ASSERT_NO_THROW(cryptoCtx.DecryptFile(encryptedStream, decryptedStream, MY_PASS));
        // Проверяем, что получили исходную тестовую строку
        EXPECT_EQ(rTestData.inputStr, decryptedStream.str());
    }
}

// Тест повторного дешифрования корректного входного строкового потока с правильным паролем
TEST(CryptoGuardCtx, DoubleDecryptWithCorrectPass) {
    // Цикл по вариантам тестовых данных
    for (const TestData &rTestData : testVec) {
        CryptoGuard::CryptoGuardCtx cryptoCtx;
        std::stringstream inStream(rTestData.inputStr);             // входной строковый поток
        std::stringstream encryptedStream;                          // выходной строковый поток с зашифрованными данными
        std::stringstream decryptedStream;                          // выходной строковый поток с дешифрованными данными
        cryptoCtx.EncryptFile(inStream, encryptedStream, MY_PASS);  // шифруем данные
        cryptoCtx.DecryptFile(encryptedStream, decryptedStream, MY_PASS);  // дешифруем данные

        // Повторное дешифрование должно пройти без исключений
        ASSERT_NO_THROW(cryptoCtx.DecryptFile(encryptedStream, decryptedStream, MY_PASS));
        // Проверяем, что получили исходную тестовую строку (выходной поток перезаписыается, а не дополняется)
        EXPECT_EQ(rTestData.inputStr, decryptedStream.str());
    }
}

// Тест дешифрования корректного входного строкового потока с неправильным паролем
TEST(CryptoGuardCtx, DecryptWithWrongPass) {
    // Цикл по вариантам тестовых данных
    for (const TestData &rTestData : testVec) {
        CryptoGuard::CryptoGuardCtx cryptoCtx;
        std::stringstream inStream(rTestData.inputStr);             // входной строковый поток
        std::stringstream encryptedStream;                          // выходной строковый поток с зашифрованными данными
        std::stringstream decryptedStream;                          // выходной строковый поток с дешифрованными данными
        cryptoCtx.EncryptFile(inStream, encryptedStream, MY_PASS);  // шифруем данные с заданным паролем

        // Дешифрование с неправильным паролем должно бросить исключение
        ASSERT_THROW(cryptoCtx.DecryptFile(encryptedStream, decryptedStream, MY_PASS + "123"), std::runtime_error);
    }
}

// Тест дешифрования поврежденных данных (не содержащих валидные зашифрованные AES-блоки)
TEST(CryptoGuardCtx, DecryptBadData) {
    // Цикл по вариантам тестовых данных
    for (const TestData &rTestData : testVec) {
        CryptoGuard::CryptoGuardCtx cryptoCtx;
        std::stringstream badStream(
            rTestData.inputStr);      // входной строковый поток с "поврежденными" зашифрованными данными
        std::stringstream outStream;  // выходной строковый поток с дешифрованными данными

        // Дешифрование должно бросить исключение
        ASSERT_THROW(cryptoCtx.DecryptFile(badStream, outStream, MY_PASS), std::runtime_error);
    }
}

// ====== ТЕСТЫ ШИФРОВАНИЯ/ДЕШИФРОВАНИЯ ======

// Тест серии корректных шифрований/дешифрований с помощью одного экземпляра класса CryptoGuardCtx
TEST(CryptoGuardCtx, SeriesEncryptDecrypt) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    // Цикл по вариантам тестовых данных
    for (const TestData &rTestData : testVec) {
        std::stringstream inStream(rTestData.inputStr);  // входной строковый поток
        std::stringstream encryptedStream;               // выходной строковый поток с зашифрованными данными
        std::stringstream decryptedStream;               // выходной строковый поток с дешифрованными данными

        // Шифрование должно пройти без исключений
        ASSERT_NO_THROW(cryptoCtx.EncryptFile(inStream, encryptedStream, MY_PASS));
        // Выходной зашифрованными поток должен быть не пустой
        EXPECT_FALSE(encryptedStream.str().empty());
        // Входной и выходной зашифрованный потоки должны отличаться
        EXPECT_NE(inStream.str(), encryptedStream.str());
        // Дешифрование с правильным паролем должно пройти без исключений
        ASSERT_NO_THROW(cryptoCtx.DecryptFile(encryptedStream, decryptedStream, MY_PASS));
        // Проверяем, что получили исходную тестовую строку
        EXPECT_EQ(rTestData.inputStr, decryptedStream.str());
    }
}

// ====== ТЕСТЫ ПОДСЧЕТА КОНТРОЛЬНОЙ СУММЫ ======

// Тест контрольной суммы для строки с известным хешем
TEST(CryptoGuardCtx, ChecksumWithReference) {
    // Цикл по вариантам тестовых данных
    for (const TestData &rTestData : testVec) {
        CryptoGuard::CryptoGuardCtx cryptoCtx;
        std::stringstream inStream(rTestData.inputStr);  // входной строковый поток
        std::string checksumStr;                         // строка контрольной суммы SHA-256 в hex-формате

        // Подсчет контрольной суммы должен пройти без исключений
        ASSERT_NO_THROW(checksumStr = cryptoCtx.CalculateChecksum(inStream));
        // Полученная строка контрольной суммы должна совпадать с эталонной
        EXPECT_EQ(checksumStr, rTestData.outputHash);
    }
}

// Тест контрольной суммы некорректного входного строкового потока
TEST(CryptoGuardCtx, ChecksumInvalidInputStream) {
    // Цикл по вариантам тестовых данных
    for (const TestData &rTestData : testVec) {
        CryptoGuard::CryptoGuardCtx cryptoCtx;
        std::stringstream inStream(rTestData.inputStr);  // входной строковый поток
        inStream.setstate(std::ios::badbit);             // поднимем флаг ошибки во входном потоке

        // Подсчет контрольной суммы должен выбросить исключение
        ASSERT_THROW(cryptoCtx.CalculateChecksum(inStream), std::runtime_error);
    }
}

// Тест контрольной суммы до и после шифрования/дешифрования
TEST(CryptoGuardCtx, ChecksumAfterEncryptDecrypt) {
    // Цикл по вариантам тестовых данных
    for (const TestData &rTestData : testVec) {
        CryptoGuard::CryptoGuardCtx cryptoCtx;
        std::stringstream inStream(rTestData.inputStr);  // входной строковый поток
        std::stringstream encryptedStream;               // выходной строковый поток с зашифрованными данными
        std::stringstream decryptedStream;               // выходной строковый поток с дешифрованными данными
        std::string checksumBefore = cryptoCtx.CalculateChecksum(inStream);  // контрольная сумма исходной строки
        cryptoCtx.EncryptFile(inStream, encryptedStream, MY_PASS);           // шифруем данные
        cryptoCtx.DecryptFile(encryptedStream, decryptedStream, MY_PASS);    // дешифруем данные
        std::string checksumAfter =
            cryptoCtx.CalculateChecksum(decryptedStream);  // контрольная сумма результата дешифрования

        // Контрольные суммы до и после шифрования/дешифрования должны совпадать
        EXPECT_EQ(checksumBefore, checksumAfter);
    }
}

// ====== ДОПОЛНИТЕЛЬНЫЕ ТЕСТЫ ======

// Тест расшифровки OpenSSl-ошибки при дешифровании с неправильным паролем
TEST(CryptoGuardCtx, ExtendedOpenSSLError) {
    // Цикл по вариантам тестовых данных
    for (const TestData &rTestData : testVec) {
        CryptoGuard::CryptoGuardCtx cryptoCtx;
        std::stringstream inStream(rTestData.inputStr);             // входной строковый поток
        std::stringstream encryptedStream;                          // выходной строковый поток с зашифрованными данными
        std::stringstream decryptedStream;                          // выходной строковый поток с дешифрованными данными
        cryptoCtx.EncryptFile(inStream, encryptedStream, MY_PASS);  // шифруем данные с заданным паролем

        // Попытка дешифрования с неправильным паролем должна дать текстовую OpenSSl-ошибку
        try {
            cryptoCtx.DecryptFile(encryptedStream, decryptedStream, MY_PASS + "123");
            FAIL() << "Expected std::runtime_error";
        } catch (const std::runtime_error &e) {
            std::string errorMsg = e.what();
            // В сообщении должны быть ключевые слова OpenSSL-ошибки
            EXPECT_TRUE(errorMsg.find("error:") != std::string::npos && errorMsg.find("routines") != std::string::npos);
        }
    }
}