import lief
import sys

def add_section_to_elf(input_file, section_name, content):
    binary = lief.parse(input_file)
    new_section = lief.ELF.Section(section_name)
    new_section.content = list(content)  # Byte content of the section
    binary.add(new_section)
    binary.write(input_file)


if __name__ == "__main__":
    add_section_to_elf(sys.argv[1], '.go.runtimeinfo', open(sys.argv[2], "rb").read())
