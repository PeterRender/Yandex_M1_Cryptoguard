#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <algorithm>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <string>

int main(int argc, char *argv[]) {
    try {
        /*         //
                // OpenSSL пример использования:
                //
                std::string input = "01234567890123456789";
                std::string output;

                OpenSSL_add_all_algorithms();

                auto params = CreateChiperParamsFromPassword("12341234");
                params.encrypt = 1;
                auto *ctx = EVP_CIPHER_CTX_new();

                // Инициализируем cipher
                EVP_CipherInit_ex(ctx, params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);

                std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
                std::vector<unsigned char> inBuf(16);
                int outLen;

                // Обрабатываем первые N символов
                std::copy(input.begin(), std::next(input.begin(), 16), inBuf.begin());
                EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(16));
                for (int i = 0; i < outLen; ++i) {
                    output.push_back(outBuf[i]);
                }

                // Обрабатываем оставшиеся символы
                std::copy(std::next(input.begin(), 16), input.end(), inBuf.begin());
                EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(input.size() - 16));
                for (int i = 0; i < outLen; ++i) {
                    output.push_back(outBuf[i]);
                }

                // Заканчиваем работу с cipher
                EVP_CipherFinal_ex(ctx, outBuf.data(), &outLen);
                for (int i = 0; i < outLen; ++i) {
                    output.push_back(outBuf[i]);
                }
                EVP_CIPHER_CTX_free(ctx);
                std::print("String encoded successfully. Result: '{}'\n\n", output);
                EVP_cleanup();
                //
                // Конец примера
                // */

        CryptoGuard::ProgramOptions options;

        try {
            // Парсим аргументы командной строки
            options.Parse(argc, argv);
        } catch (const std::exception &e) {
            std::print(std::cerr, "Command line error: {}\n", e.what());
            return 1;
        }

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT:
            std::print("File encoded successfully\n");
            break;

        case COMMAND_TYPE::DECRYPT:
            std::print("File decoded successfully\n");
            break;

        case COMMAND_TYPE::CHECKSUM:
            std::print("Checksum: {}\n", "CHECKSUM_NOT_IMPLEMENTED");
            break;

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}