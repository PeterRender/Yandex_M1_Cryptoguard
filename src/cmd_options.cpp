#include "cmd_options.h"
#include <iostream>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    namespace po = boost::program_options;

    desc_.add_options()
        // Опция help
        ("help,h", "produce help message")
        // Обязательная опция command
        ("command,c", po::value<std::string>()->required(), "command: encrypt, decrypt or checksum")
        // Обязательная опция input
        ("input,i", po::value<std::string>()->required(), "input file")
        // Необязательная опция output и password
        ("output,o", po::value<std::string>(), "output file (required for encrypt/decrypt command)")
        // Необязательная опция password
        ("password,p", po::value<std::string>(), "password (required for encrypt/decrypt command)");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    namespace po = boost::program_options;

    try {
        // Создаем парсер со строгим стилем, который не дополняет имена опций при разборе (в отличие от дефолтного
        // parse_command_line)
        po::command_line_parser parser(argc, argv);
        // В качестве стиля указываем Unix-стиль (требует -- для long опций и - для short), а также отключаем
        // автодополнение имен опций
        parser.options(desc_).style(po::command_line_style::unix_style & ~po::command_line_style::allow_guessing);

        // Парсинг аргументов (если у какой-то опции нет аргумента, то бросается исключение)
        po::variables_map vm;
        po::store(parser.run(), vm);

        // Обработка опции help
        if (vm.count("help")) {
            // Выводим справку и корректно завершаем программу
            std::cout << desc_ << std::endl;
            exit(0);
        }

        // Проверка наличия в мапе обязательных опций (если их нет, то бросается исключение)
        po::notify(vm);

        // Преобразуем аргумент опции command в enum
        std::string commandStr = vm["command"].as<std::string>();
        auto it = commandMapping_.find(commandStr);
        if (it == commandMapping_.end()) {
            throw po::error("unknown command \"" + commandStr + "\"");
        }
        command_ = it->second;

        // Получаем строку имени входного файла
        inputFile_ = vm["input"].as<std::string>();

        // Флаги наличия в мапе опций output и password
        bool gotOutFile = vm.count("output");
        bool gotPass = vm.count("password");

        // Для команд encrypt и decrypt нужны опции output и password
        if (command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT) {
            // Если в мапе нет опции output или опции password, то бросаем исключение
            if (!gotOutFile || !gotPass) {
                throw po::error("both options --output and --password are required for encrypt/decrypt commands");
            }
            // Получаем строку имени выходного файла и строку пароля
            outputFile_ = vm["output"].as<std::string>();
            password_ = vm["password"].as<std::string>();
        }

        // Для команды checksum не нужны опции output и password
        if ((command_ == COMMAND_TYPE::CHECKSUM) && (gotOutFile || gotPass)) {
            throw po::error("neither --output nor --password option are required for checksum command");
        }

    } catch (const po::error &e) {
        // Пробрасываем это исключение дальше как std::runtime_error (для унифицированной обработки)
        throw std::runtime_error(e.what());
    }
}

}  // namespace CryptoGuard
