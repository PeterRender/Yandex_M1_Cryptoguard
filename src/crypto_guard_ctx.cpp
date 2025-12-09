#include "crypto_guard_ctx.h"
#include <openssl/evp.h>  // для подключения OpenSSL функций

namespace CryptoGuard {

// Внутренний класс, реализующий функционал класса CryptoGuardCtx
class CryptoGuardCtx::Impl {
public:
    Impl() {
        // Инициализация библиотеки OpenSSL
        OpenSSL_add_all_algorithms();
    }

    ~Impl() {
        // Освобождение ресурсов, выделенных для библиотеки OpenSSL
        EVP_cleanup();
    }

    // Заготовки методов, реализующих API класса CryptoGuardCtx
    void EncryptFileImpl(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}
    void DecryptFileImpl(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}
    std::string CalculateChecksumImpl(std::iostream &inStream) { return "NOT_IMPLEMENTED"; }
};

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
