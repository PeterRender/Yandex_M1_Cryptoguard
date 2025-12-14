#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <format>   // для подключения шаблона форматируемой строки
#include <fstream>  // для работы с файловыми потоками
#include <iostream>
#include <print>
#include <stdexcept>
#include <string>

int main(int argc, char *argv[]) {
    try {
        // Вспомогательная лямбда-функция для открытия файлов с обработкой ошибок
        auto OpenFile = [](const std::string &filename, std::ios::openmode mode) {
            std::fstream file(filename, mode);
            if (!file.is_open()) {
                const char *fileType = (mode & std::ios::in) ? "input" : "output";  // тип файла по режиму открытия
                throw std::runtime_error{std::format("Failed to open {} file '{}'", fileType, filename)};
            }
            return file;
        };

        // Создание объекта-хелпера для извлечения параметров приложения CryptoGuard из командной строки
        CryptoGuard::ProgramOptions options;

        try {
            // Парсим аргументы командной строки
            options.Parse(argc, argv);
        } catch (const std::exception &e) {
            std::print(std::cerr, "Command line error: {}\n", e.what());
            return 1;
        }

        // Создание объекта-хелпера, реализующего API приложения CryptoGuard
        CryptoGuard::CryptoGuardCtx cryptoCtx;

        // Задание краткого псевдонима для типа крипто-команды приложения CryptoGuard
        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;

        // Обработка крипто-команды, полученной от пользователя
        switch (options.GetCommand()) {
        // Команда шифрования файла
        case COMMAND_TYPE::ENCRYPT: {
            // Открытие входного файла в бинарном режиме для чтения
            auto inFile = OpenFile(options.GetInputFile(), std::ios::in | std::ios::binary);
            // Открытие выходного файла в бинарном режиме для записи
            auto outFile = OpenFile(options.GetOutputFile(), std::ios::out | std::ios::binary);

            // Шифрование входного файла с помощью объекта-хелпера
            cryptoCtx.EncryptFile(inFile, outFile, options.GetPassword());
            std::print("File '{}' is encrypted successfully\n", options.GetInputFile());
            break;
        }
        // Команда дешифрования файла
        case COMMAND_TYPE::DECRYPT: {
            // Открытие входного файла в бинарном режиме для чтения
            auto inFile = OpenFile(options.GetInputFile(), std::ios::in | std::ios::binary);
            // Открытие выходного файла в бинарном режиме для записи
            auto outFile = OpenFile(options.GetOutputFile(), std::ios::out | std::ios::binary);

            // Дешифрование входного файла с помощью объекта-хелпера
            cryptoCtx.DecryptFile(inFile, outFile, options.GetPassword());
            std::print("File '{}' is decrypted successfully\n", options.GetInputFile());
            break;
        }
        // Команда подсчета контрольной суммы файла
        case COMMAND_TYPE::CHECKSUM: {
            // Открытие входного файла в бинарном режиме для чтения
            auto inFile = OpenFile(options.GetInputFile(), std::ios::in | std::ios::binary);

            // Подсчет контрольной суммы файла с помощью объекта-хелпера
            std::string checksum = cryptoCtx.CalculateChecksum(inFile);
            std::print("Checksum (SHA-256) of '{}' is {}\n", options.GetInputFile(), checksum);
            break;
        }
        // Нераспознанный тип команды
        default: {
            throw std::runtime_error{"Unsupported command type"};
        }
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}