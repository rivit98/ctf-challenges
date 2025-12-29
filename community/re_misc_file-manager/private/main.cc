#include <iostream>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <algorithm>
#include <optional>

#include "rivit_common.h"

std::filesystem::path fs_path;

u32 get_option() {
    u32 ret = 0;
    std::cin >> ret;
    while (std::cin.get() != '\n') {
    }
    return ret;
}

[[nodiscard]]
std::optional<std::filesystem::path> get_filename(const std::string& prompt) {
    std::cout << prompt;
    std::string fname;
    std::getline(std::cin, fname);

    if (std::any_of(fname.begin(), fname.end(), [](char c) {
        return !std::isalnum(c) && c != '-';
    })) {
        return {};
    }

    return fname;
}

[[nodiscard]]
std::optional<std::filesystem::path> get_filename_checked(bool should_exists) {
    const auto fname = get_filename("Input filename: ");
    if (!fname.has_value()) {
        std::cerr << "invalid filename\n";
        return {};
    }

    if (should_exists && !std::filesystem::exists(fname.value())) {
        std::cerr << "file does not exists\n";
        return {};
    }

    if (!should_exists && std::filesystem::exists(fname.value())) {
        std::cerr << "file already exists\n";
        return {};
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
        std::cout << "1. create file\n";
        std::cout << "2. rename file\n";
        std::cout << "3. print file\n";
        std::cout << "4. delete file\n"; // not implemented
        std::cout << "5. edit file\n";
        // std::cout << "6. list files\n"; // not implemented
        // std::cout << "7. compress files\n"; // hidden option
        // std::cout << "8. download file\n"; // not implemented
        std::cout << "0. exit\n";
        std::cout << "> ";
    }
};

class CreateCommand final : public Command {
    void execute() const override {
        if(const auto fname = get_filename_checked(false); fname.has_value()) {
            std::ofstream file(*fname);
        }
    }
};

class RenameCommand final : public Command {
    void execute() const override {
        if(const auto fname = get_filename_checked(true); fname.has_value()) {
            std::string new_fname;
            std::cout << "Input new filename: ";
            std::getline(std::cin, new_fname);
            std::filesystem::rename(*fname, new_fname);
        }
    }
};

class PrintCommand final : public Command {
    void execute() const override {
        if(const auto fname = get_filename_checked(true); fname.has_value()) {
            std::ifstream in(*fname);
            std::string data{std::istreambuf_iterator{in}, {}};
            std::cout << data;
            std::cout << std::endl;
        }
    }
};

class EditCommand final : public Command {
    void execute() const override {
        if(const auto fname = get_filename_checked(true); fname.has_value()) {
            std::string data;
            std::cout << "Input data: ";
            std::getline(std::cin, data);
            std::ofstream file(*fname);
            file << data;
        }
    }
};

class NotImplementedCommand final : public Command {
    void execute() const override {
        std::cerr << "not implemented yet\n";
    }
};

class CompressCommand final : public Command {
    void execute() const override {
        if(const auto fname = get_filename_checked(false); fname.has_value()) {
            std::stringstream fmt;
            fmt << "/bin/zip " << *fname << " *";
            std::system(fmt.str().c_str());
        }
    }
};

class ExitCommand final : public Command {
public:
    void execute() const override {
        std::cout << "Bye!\n";
        std::exit(0);
    }
};

void setup() {
    std::cout.setf(std::ios::unitbuf);
    std::cin.setf(std::ios::unitbuf);
    std::cerr.setf(std::ios::unitbuf);

    const auto fs = getenv("FS_PATH");
    fs_path = fs == nullptr ? "fs/" : fs;

    if (!std::filesystem::exists(std::string(fs_path))) {
        create_directory(fs_path);
    }

    std::filesystem::current_path(fs_path);
}

int main() {
    setup();

    Command* fns[] = {
        new ExitCommand,
        new CreateCommand,
        new RenameCommand,
        new PrintCommand,
        new NotImplementedCommand, //delete
        new EditCommand,
        new NotImplementedCommand,
        new CompressCommand,
        new NotImplementedCommand,
    };

    MenuCommand menu;
    while (true) {
        menu.execute();
        fns[get_option()]->execute();
    }

    for(auto& fn : fns) {
        delete fn;
    }
}
