#include <iostream>
#include <filesystem>
#include <array>
#include <fstream>
#include <sstream>
#include <string>
#include <algorithm>

#include "rivit_common.h"
#include "obfuscated_string.h"

std::filesystem::path fs_path;

u32 get_option() {
    u32 ret = 0;
    std::cin >> ret;
    while (std::cin.get() != '\n') {
    }
    return ret;
}

[[nodiscard]]
std::filesystem::path get_filename(const std::string& prompt) {
    std::cout << prompt;
    std::string fname;
    std::getline(std::cin, fname);

    if (std::ranges::any_of(fname, [](char c) {
        return !std::isalnum(c) && c != '-' && c != '.';
    })) {
        throw std::invalid_argument(XOR_STRING("invalid fname"));
    }

    return fname;
}

class Command {
public:
    virtual void execute() const = 0;
    virtual ~Command() = default;
};

class MenuCommand final : public Command {
public:
    void execute() const override {
        std::cout << XOR_STRING("JCTF COMMANDER v0.1\n");
        std::cout << XOR_STRING("1. create file\n");
        std::cout << XOR_STRING("2. rename file\n");
        std::cout << XOR_STRING("3. print file\n");
        std::cout << XOR_STRING("4. delete file\n");
        std::cout << XOR_STRING("5. edit file\n");
        // std::cout << XOR_STRING("6. list files\n"); // not implemented
        // std::cout << XOR_STRING("7. compress files\n"); // hidden option
        // std::cout << XOR_STRING("8. download file\n"); // not implemented
        std::cout << XOR_STRING("0. exit\n");
        std::cout << XOR_STRING("> ");
    }
};

class CreateCommand final : public Command {
    void execute() const override {
        const auto fname = get_filename(XOR_STRING("Input filename: "));
        if (std::filesystem::exists(fname)) {
            throw std::invalid_argument(XOR_STRING("file already exists"));
        }

        std::ofstream file(fname);
        file.close();
    }
};

class RenameCommand final : public Command {
    void execute() const override {
        const auto fname = get_filename(XOR_STRING("Input filename: "));
        if (!std::filesystem::exists(fname)) {
            throw std::invalid_argument(XOR_STRING("file does not exists"));
        }

        std::string new_fname;
        std::cout << XOR_STRING("Input new filename: ");
        std::getline(std::cin, new_fname);
        std::filesystem::rename(fname, new_fname);
    }
};

class PrintCommand final : public Command {
    void execute() const override {
        const auto fname = get_filename(XOR_STRING("Input filename: "));
        if (!std::filesystem::exists(fname)) {
            throw std::invalid_argument(XOR_STRING("file does not exists"));
        }

        std::ifstream in(fname);
        std::string data{std::istreambuf_iterator{in}, {}};
        std::cout << data;
        std::cout << std::endl;
    }
};

class DeleteCommand final : public Command {
    void execute() const override {
        const auto fname = get_filename(XOR_STRING("Input filename: "));
        if (!std::filesystem::exists(fname)) {
            throw std::invalid_argument(XOR_STRING("file does not exists"));
        }

        std::filesystem::remove(fname);
    }
};

class EditCommand final : public Command {
    void execute() const override {
        const auto fname = get_filename(XOR_STRING("Input filename: "));
        if (!std::filesystem::exists(fname)) {
            throw std::invalid_argument(XOR_STRING("file does not exists"));
        }

        std::string data;
        std::cout << XOR_STRING("Input data: ");
        std::getline(std::cin, data);
        std::ofstream file(fname);
        file << data;
    }
};

class NotImplementedCommand final : public Command {
    void execute() const override {
        throw std::invalid_argument(XOR_STRING("not implemented yet"));
    }
};

class CompressCommand final : public Command {
    void execute() const override {
        const auto fname = get_filename(XOR_STRING("Input archive name: "));
        if (std::filesystem::exists(fname)) {
            throw std::invalid_argument(XOR_STRING("file already exists"));
        }

        std::stringstream fmt;
        fmt << XOR_STRING("/bin/tar cf ") << fname << XOR_STRING(" *");
        std::system(fmt.str().c_str());
    }
};

class ExitCommand final : public Command {
public:
    void execute() const override {
        std::cout << XOR_STRING("Bye!\n");
        std::exit(0);
    }
};

void setup() {
    std::cout.setf(std::ios::unitbuf);
    std::cin.setf(std::ios::unitbuf);
    std::cerr.setf(std::ios::unitbuf);

    const auto fs = getenv(XOR_STRING("FS_PATH").data());
    fs_path = fs == nullptr ? XOR_STRING("fs/") : fs;

    if (!std::filesystem::exists(std::string(fs_path))) {
        create_directory(fs_path);
    }

    std::filesystem::current_path(fs_path);
}

int main() {
    setup();

    std::array<std::unique_ptr<Command>, 9> fns = {
        std::make_unique<ExitCommand>(),
        std::make_unique<CreateCommand>(),
        std::make_unique<RenameCommand>(),
        std::make_unique<PrintCommand>(),
        std::make_unique<DeleteCommand>(),
        std::make_unique<EditCommand>(),
        std::make_unique<NotImplementedCommand>(),
        std::make_unique<CompressCommand>(),
        std::make_unique<NotImplementedCommand>()
    };

    while (true) {
        MenuCommand menu;
        menu.execute();
        fns[get_option()]->execute();
    }
}
