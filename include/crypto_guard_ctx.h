#pragma once

#include <experimental/propagate_const>
#include <memory>  // для подключения std::unique_ptr
#include <string>

namespace CryptoGuard {

// Класс, реализующий криптографическую обработку файлов
class CryptoGuardCtx {
public:
    // Конструктор по умолчанию.
    CryptoGuardCtx();
    // Деструктор
    ~CryptoGuardCtx();

    // Удаляем копирующие конструктор и оператор присваивания
    CryptoGuardCtx(const CryptoGuardCtx &) = delete;
    CryptoGuardCtx &operator=(const CryptoGuardCtx &) = delete;

    // Разрешаем перемещающие конструктор и оператор присваивания по-умолчанию
    CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;
    CryptoGuardCtx &operator=(CryptoGuardCtx &&) noexcept = default;

    // Метод, реализующий шифрование файла
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);

    // Метод, реализующий дешифрование файла
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);

    // Метод, реализующий подсчёт контрольной суммы файла
    std::string CalculateChecksum(std::iostream &inStream);

private:
    class Impl;  // предварительное объявление класса, реализующего функционал класса CryptoGuardCtx
    std::experimental::propagate_const<std::unique_ptr<Impl>>
        pImpl_;  // умный указатель, владеющий объектом класса Impl, с оберткой, обеспечивающей const-correctness.
};

}  // namespace CryptoGuard
