#include "cmd_options.h"
#include <gtest/gtest.h>
#include <stdexcept>

// Тест работы опции --help
TEST(ProgramOptions, HelpCheck) {
    const char *argv[] = {"./CryptoGuard", "--help"};
    CryptoGuard::ProgramOptions options;
    testing::internal::CaptureStdout();  // начало захвата стандартного потока вывода

    // Парсинг не должен бросать исключение
    EXPECT_NO_THROW(options.Parse(2, const_cast<char **>(argv)));

    std::string outputStr = testing::internal::GetCapturedStdout();  // захваченная строка вывода

    // В строке вывода должны быть ключевые слова справки
    EXPECT_TRUE(outputStr.find("Allowed options") != std::string::npos && outputStr.find("help") != std::string::npos &&
                outputStr.find("command") != std::string::npos && outputStr.find("input") != std::string::npos &&
                outputStr.find("output") != std::string::npos && outputStr.find("password") != std::string::npos);
}

// Тест корректного парсинга команды --checksum (без лишних аргументов)
TEST(ProgramOptions, ChecksumValidCheck) {
    const char *argv[] = {"./CryptoGuard", "--command", "checksum", "--input", "origin.txt"};
    CryptoGuard::ProgramOptions options;

    // Парсинг не должен бросать исключение
    EXPECT_NO_THROW(options.Parse(5, const_cast<char **>(argv)));
    // Проверяем поля объекта после парсинга
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(options.GetInputFile(), "origin.txt");
    // Для команды checksum поля outputFile_ и password_ должны быть пусты
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}

// Тест парсинга команды --checksum с лишним аргументом пароля
TEST(ProgramOptions, ChecksumWithPassCheck) {
    const char *argv[] = {"./CryptoGuard", "--command", "checksum", "--input", "origin.txt", "--password", "1234"};
    CryptoGuard::ProgramOptions options;

    try {
        // Пытаемся выполнить парсинг
        options.Parse(7, const_cast<char **>(argv));
        // Если не выбросило исключение - тест провален
        FAIL() << "Expected std::runtime_error";
    } catch (const std::runtime_error &e) {
        // Проверяем, что ошибка содержит ключевые слова
        EXPECT_TRUE(std::string(e.what()).find("checksum") != std::string::npos);
        EXPECT_TRUE(std::string(e.what()).find("--password") != std::string::npos);
    }
}

// Тест корректного парсинга команды --encrypt (со всеми обязательными аргументами)
TEST(ProgramOptions, EncryptValidCheck) {
    const char *argv[] = {"./CryptoGuard", "--command",     "encrypt",    "--input", "origin.txt",
                          "--output",      "encrypted.txt", "--password", "1234"};
    CryptoGuard::ProgramOptions options;

    // Парсинг не должен бросать исключение
    EXPECT_NO_THROW(options.Parse(9, const_cast<char **>(argv)));

    // После парсинга все поля должны быть заполнены
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "origin.txt");
    EXPECT_EQ(options.GetOutputFile(), "encrypted.txt");
    EXPECT_EQ(options.GetPassword(), "1234");
}

// Тест парсинга команды --encrypt без аргумента пароля
TEST(ProgramOptions, EncryptNoPassCheck) {
    const char *argv[] = {"./CryptoGuard", "--command", "encrypt",      "--input",
                          "origin.txt",    "--output",  "encrypted.txt"};
    CryptoGuard::ProgramOptions options;

    try {
        // Пытаемся выполнить парсинг
        options.Parse(7, const_cast<char **>(argv));
        // Если не выбросило исключение - тест провален
        FAIL() << "Expected std::runtime_error";
    } catch (const std::runtime_error &e) {
        // Проверяем, что ошибка содержит ключевые слова
        EXPECT_TRUE(std::string(e.what()).find("encrypt") != std::string::npos);
        EXPECT_TRUE(std::string(e.what()).find("--password") != std::string::npos);
    }
}

// Тест корректного парсинга команды --decrypt (со всеми обязательными аргументами)
TEST(ProgramOptions, DecryptValidCheck) {
    const char *argv[] = {"./CryptoGuard", "--command",     "decrypt",    "--input", "encrypted.txt",
                          "--output",      "decrypted.txt", "--password", "1234"};
    CryptoGuard::ProgramOptions options;

    // Парсинг не должен бросать исключение
    EXPECT_NO_THROW(options.Parse(9, const_cast<char **>(argv)));

    // После парсинга все поля должны быть заполнены
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(options.GetInputFile(), "encrypted.txt");
    EXPECT_EQ(options.GetOutputFile(), "decrypted.txt");
    EXPECT_EQ(options.GetPassword(), "1234");
}

// Тест парсинга команды --decrypt без аргумента пароля
TEST(ProgramOptions, DecryptNoPassCheck) {
    const char *argv[] = {"./CryptoGuard", "--command", "decrypt",      "--input",
                          "encrypted.txt", "--output",  "decrypted.txt"};
    CryptoGuard::ProgramOptions options;

    try {
        // Пытаемся выполнить парсинг
        options.Parse(7, const_cast<char **>(argv));
        // Если не выбросило исключение - тест провален
        FAIL() << "Expected std::runtime_error";
    } catch (const std::runtime_error &e) {
        // Проверяем, что ошибка содержит ключевые слова
        EXPECT_TRUE(std::string(e.what()).find("decrypt") != std::string::npos);
        EXPECT_TRUE(std::string(e.what()).find("--password") != std::string::npos);
    }
}

// Тест парсинга неизвестной команды
TEST(ProgramOptions, UnknownCommandCheck) {
    const char *argv[] = {"./CryptoGuard", "--command", "invalid", "--input", "origin.txt"};
    CryptoGuard::ProgramOptions options;

    try {
        // Пытаемся выполнить парсинг
        options.Parse(5, const_cast<char **>(argv));
        // Если не выбросило исключение - тест провален
        FAIL() << "Expected std::runtime_error";
    } catch (const std::runtime_error &e) {
        // Проверяем, что ошибка содержит ключевые слова
        EXPECT_TRUE(std::string(e.what()).find("unknown") != std::string::npos);
    }
}
