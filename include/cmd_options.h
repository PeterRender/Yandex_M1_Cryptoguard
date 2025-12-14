#pragma once

#include <boost/program_options.hpp>
#include <string>
#include <unordered_map>

namespace CryptoGuard {

// Класс-хелпер, реализующий извлечение параметров приложения CryptoGuard из командной строки
class ProgramOptions {
public:
    // Конструктор по умолчанию
    ProgramOptions();

    // Деструктор
    ~ProgramOptions();

    // Перечисляемый тип крипто-команды приложения CryptoGuard
    enum class COMMAND_TYPE {
        ENCRYPT,   // шифрование файла
        DECRYPT,   // дешифрование файла
        CHECKSUM,  // подсчет контрольной суммы файла
    };

    // Метод, реализующий парсинг (разбор) аргументов командной строки
    void Parse(int argc, char *argv[]);

    // Методы доступа к параметрам приложения CryptoGuard
    COMMAND_TYPE GetCommand() const { return command_; }       // возвращает идентификатор запущенной крипто-команды
    std::string GetInputFile() const { return inputFile_; }    // возвращает имя входного файла
    std::string GetOutputFile() const { return outputFile_; }  // возвращает имя файла-результата критообработки
    std::string GetPassword() const { return password_; }      // возвращает пароль для шифрования/дешифрования

private:
    COMMAND_TYPE command_;  // идентификатор запущенной крипто-команды

    // Карта текстовых расшифровок идентификаторов крипто-команд приложения CryptoGuard
    const std::unordered_map<std::string_view, COMMAND_TYPE> commandMapping_ = {
        {"encrypt", ProgramOptions::COMMAND_TYPE::ENCRYPT},
        {"decrypt", ProgramOptions::COMMAND_TYPE::DECRYPT},
        {"checksum", ProgramOptions::COMMAND_TYPE::CHECKSUM},
    };

    std::string inputFile_;   // имя входного файла
    std::string outputFile_;  // имя файла-результата критообработки
    std::string password_;    // пароль для шифрования/дешифрования

    // Хранилище поддерживаемых опций командной строки приложения CryptoGuard
    boost::program_options::options_description desc_;
};

}  // namespace CryptoGuard
