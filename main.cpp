#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <iomanip>
#include <map>

//TODO: лучше куда-нибудь отдельно вынести как файлик с константами

std::map <unsigned int, std::string> symbol_types = {
        {0,"NOTYPE"},
        {1,"OBJECT"},
        {2,"FUNC"},
        {3,"SECTION"},
        {4,"FILE"},
        {5,"COMMON"},
        {6,"TLS"},
        {10,"LOOS"},
        {12,"HIOS"},
        {13,"LOPROC"},
        {15,"HIPROS"}
};

std::map <unsigned int, std::string> symbol_binds = {
        {0,"LOCAL"},
        {1,"GLOBAL"},
        {2,"WEAK"},
        {10,"LOOS"},
        {12,"HIOS"},
        {13,"LOPROC"},
        {15,"HIPROS"}
};

std::map <int, std::string> symbol_visibilities = {
        {0,"DEFAULT"},
        {1,"INTERNAL"},
        {2,"HIDDEN"},
        {3,"PROTECTED"},
        {4,"EXPORTED"},
        {5,"SINGLETON"},
        {6,"ELIMINATE"}
};

std::map <int, std::string> symbol_indexes = {
        {0,"UNDEF"},
        {0xff00,"LORESERVE"}, //TODO: почему у разных типов одно и то же значение?
        {0xff00,"LOPROC"},
        {0xff00,"BEFORE"},
        {0xff01,"AFTER"},
        {0xff02,"AMD64_LCOMMON"},
        {0xff1f,"HIPROC"},
        {0xff20,"LOOS"},
        {0xff3f,"LOSUNW"},
        {0xff3f,"SUNW_IGNORE"},
        {0xff3f,"HISUNW"},
        {0xff3f,"HIOS"},
        {0xfff1,"ABS"},
        {0xfff2,"COMMON"},
        {0xffff,"XINDEX"},
        {0xffff,"HIRESERVE"}
};

struct elf_file_header {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct section_header {
    uint32_t sh_name;
    uint32_t sh_type;
    uint32_t sh_flags;
    uint32_t sh_addr;
    uint32_t sh_offset;
    uint32_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint32_t sh_addralign;
    uint32_t sh_entsize;
};

struct elf_symbol {
    uint32_t        st_name;
    uint32_t        st_value;
    uint32_t        st_size;
    unsigned char   st_info;
    unsigned char   st_other;
    uint16_t        st_shndx;
};

int parse_symtab(std::ifstream& elf_file, section_header symtab_section_header, std::vector<elf_symbol>& symtab) {
    elf_file.seekg(symtab_section_header.sh_offset, std::ios::beg);

    for (int i = 0; i < symtab_section_header.sh_size / symtab_section_header.sh_entsize; i++) {
        elf_symbol elem;

        if (!elf_file.read((char*)&elem, symtab_section_header.sh_entsize).good()) {
            std::cerr <<"Error: Could not read symbol in symtab" << std::endl;
            return 1;
        }

        symtab.push_back(elem);
    }

    return 0;
}

std::string get_symbol_type(int index_of_symbol) {
    int index = index_of_symbol & 0xf;

    if (symbol_types.find(index) == symbol_types.end()) {
        index = 0;
    }

    return symbol_types[index];
}

std::string get_symbol_bind(int index_of_symbol) {
    int index = index_of_symbol >> 4;

    if (symbol_binds.find(index) == symbol_binds.end()) {
        index = 0;
    }

    return symbol_binds[index];
}

std::string get_symbol_visability(int index_of_symbol) {
    int index = index_of_symbol & 0x3;

    if (symbol_visibilities.find(index) == symbol_visibilities.end()) {
        index = 0;
    }

    return symbol_visibilities[index];
}

std::string get_symbol_index (int index) {
    if (symbol_indexes.find(index) != symbol_indexes.end()) {
        return symbol_indexes[index];
    }
    
    return std::to_string(index);
}

std::string format(const char *fmt, ...) { //полезная функция позволяюшая форматировать на строках (нашла реализацию в интернете) //TODO: не забыть упомянуть об этом в отчете
    va_list args;
    va_start(args, fmt);
    std::vector<char> v(1024);

    while (true) {
        va_list args2;
        va_copy(args2, args);
        int res = vsnprintf(v.data(), v.size(), fmt, args2);

        if ((res >= 0) && (res < static_cast<int>(v.size()))) {
            va_end(args);
            va_end(args2);
            return std::string(v.data());
        }

        size_t size;

        if (res < 0) {
            size = v.size() * 2;
        } else {
            size = static_cast<size_t>(res) + 1;
        }

        v.clear();
        v.resize(size);
        va_end(args2);
    }
}

int get_names_of_symbols(std::vector<elf_symbol> &symtab, std::ifstream& elf_file, int help_address, std::vector<std::string>& names_of_symbols, std::map<int, std::string>& addresses_of_function_names) {
    for (int i = 0; i < symtab.size(); i++) {
        elf_symbol symbol = symtab[i];
        std::string name;

        elf_file.seekg(help_address + symbol.st_name, std::ios::beg);

        char char_buffer = ' ';
        while (char_buffer != '\0') {
            if (!elf_file.read((char *) &char_buffer, 1).good()) {
                std::cerr <<"Error: Could not read name of symbol" << i << std::endl;
                return 1;
            }
            if (char_buffer != '\0') {
                name += char_buffer;
            }
        }

        names_of_symbols.push_back(name);

        if (get_symbol_type(symbol.st_info) == "FUNC" and !name.empty()) {
            addresses_of_function_names[symbol.st_value] = name;
        }
    }
    return 0;
}

int write_symtab(std::vector<elf_symbol> &symtab, std::ifstream& elf_file, std::ofstream& fout, std::vector<std::string>& names_of_symbols) {

    fout << '\n' <<".symtab" << '\n';

    fout <<"Symbol Value              Size Type     Bind     Vis       Index Name" << '\n';

    for (int i = 0; i < symtab.size(); i++) {
        elf_symbol symbol = symtab[i];

        std::string temp_str = format("[%4i] 0x%-15X %5i %-8s %-8s %-8s %6s %s", i, symbol.st_value, symbol.st_size,
                get_symbol_type(symbol.st_info).c_str(), get_symbol_bind(symbol.st_info).c_str(),
                get_symbol_visability(symbol.st_other).c_str(), get_symbol_index(symbol.st_shndx).c_str(),
                names_of_symbols[i].c_str()
                );

        fout << temp_str << '\n';
    }

    return 0;
}

const uint32_t OPCODE_SIZE = 7;
const uint32_t RD_SIZE = 5;
const uint32_t FUNCT3_SIZE = 3;
const uint32_t RS_SIZE = 5;
const uint32_t FUNCT7_SIZE = 7;

std::map <int, std::string> reg = {
        {0,"zero"},
        {1,"ra"},
        {2,"sp"},
        {3,"gp"},
        {4,"tp"},
        {5,"t0"},
        {6,"t1"},
        {7,"t2"},
        {8,"s0"},
        {9,"s1"},
        {10,"a0"},
        {11,"a1"},
        {12,"a2"},
        {13,"a3"},
        {14,"a4"},
        {15,"a5"},
        {16,"a6"},
        {17,"a7"},
        {18,"s2"},
        {19,"s3"},
        {20,"s4"},
        {21,"s5"},
        {22,"s6"},
        {23,"s7"},
        {24,"s8"},
        {25,"s9"},
        {26,"s10"},
        {27,"s11"},
        {28,"t3"},
        {29,"t4"},
        {30,"t5"},
        {31,"t6"}
};


struct R_type {
    uint32_t    opcode;
    uint32_t    rd;
    uint32_t    funct3;
    uint32_t    rs1;
    uint32_t    rs2;
    uint32_t    funct7;

    std::map <std::vector <uint32_t>, std::string> command = {
            {{0, 0},"add"},
            {{(1 << 5), 0},"sub"},
            {{0, 1},"sll"},
            {{0, 2},"slt"},
            {{0, 3},"sltu"},
            {{0, 4},"xor"},
            {{0, 5},"srl"},
            {{(1 << 5), 5},"sra"},
            {{0, 6},"or"},
            {{0, 7},"and"},
            {{1, 0},"mul"},
            {{1, 1},"mulh"},
            {{1, 2},"mulhsu"},
            {{1, 3},"mulhu"},
            {{1, 4},"div"},
            {{1, 5},"divu"},
            {{1, 6},"rem"},
            {{1, 7},"remu"},
    };

    void parse (uint32_t command) {
        opcode = command % (1 << OPCODE_SIZE);
        command = command >> OPCODE_SIZE;

        rd = command % (1 << RD_SIZE);
        command = command >> RD_SIZE;

        funct3 = command % (1 << FUNCT3_SIZE);
        command = command >> FUNCT3_SIZE;

        rs1 = command % (1 << RS_SIZE);
        command = command >> RS_SIZE;

        rs2 = command % (1 << RS_SIZE);
        command = command >> RS_SIZE;

        funct7 = command;
    }
};

struct I_type {
    uint32_t    opcode;
    uint32_t    rd;
    uint32_t    funct3;
    uint32_t    rs1;
    int32_t     cnst;

    std::map <std::vector <uint32_t>, std::string> command = {
            {{3, 0},"lb"},
            {{3, 1},"lh"},
            {{3, 2},"lw"},
            {{3, 4},"lbu"},
            {{3, 5},"lhu"},
            {{19, 0},"addi"},
            {{19, 2},"slti"},
            {{19, 3},"sltiu"},
            {{19, 4},"xori"},
            {{19, 6},"ori"},
            {{19, 7},"andi"},
            {{103, 0},"jalr"},
            {{0, 0, 0},"ecall"},
            {{0, 0, 1},"ebreak"}
    };

    void parse (uint32_t command) {
        opcode = command % (1 <<OPCODE_SIZE);
        command = command >> OPCODE_SIZE;

        rd = command % (1 << RD_SIZE);
        command = command >> RD_SIZE;

        funct3 = command % (1 << FUNCT3_SIZE);
        command = command >> FUNCT3_SIZE;

        rs1 = command % (1 << RS_SIZE);
        command = command >> RS_SIZE;

        cnst = command;
        cnst -= (command >> 11) * (2 << 11);
    }
};

struct S_type {
    uint32_t    opcode;
    uint32_t    cnst4_0;
    uint32_t    funct3;
    uint32_t    rs1;
    uint32_t    rs2;
    uint32_t    cnst11_5;
    int32_t     cnst;

    std::map <std::vector <uint32_t>, std::string> command = {
            {{35, 0},"sb"},
            {{35, 1},"sh"},
            {{35, 2},"sw"},
    };

    void parse (uint32_t command) {
        opcode = command % (1 << OPCODE_SIZE);       
        command = command >> OPCODE_SIZE;
        
        cnst4_0 = command % (1 << RD_SIZE);            
        command = command >> RD_SIZE;
        
        funct3 = command % (1 << FUNCT3_SIZE);       
        command = command >> FUNCT3_SIZE;
        
        rs1 = command % (1 << RS_SIZE);              
        command = command >> RS_SIZE;
        
        rs2 = command % (1 << RS_SIZE);              
        command = command >> RS_SIZE;
        
        cnst11_5 = command;

        cnst = (cnst11_5 << 5) + cnst4_0; 
        cnst -= (cnst >> 11) * (2 << 11);
    }
};

struct B_type {
    uint32_t    opcode;
    uint32_t    funct3;
    uint32_t    rs1;
    uint32_t    rs2;
    uint32_t    cnst4_1;
    uint32_t    cnst10_5;
    uint32_t    cnst11;
    uint32_t    cnst12;
    int32_t     cnst;

    std::map <std::vector <uint32_t>, std::string> command = {
            {{99, 0},"beq"},
            {{99, 1},"bne"},
            {{99, 4},"blt"},
            {{99, 5},"bge"},
            {{99, 6},"bltu"},
            {{99, 7},"bgeu"},
    };

    void parse (uint32_t command) {
        opcode = command % (1 << OPCODE_SIZE);   
        command = command >> OPCODE_SIZE;
        
        cnst11 = command % (1 << 1);         
        command = command >> 1;
        
        cnst4_1 = command % (1 << 4);         
        command = command >> 4;
        
        funct3 = command % (1 << FUNCT3_SIZE);   
        command = command >> FUNCT3_SIZE;
        
        rs1 = command % (1 << RS_SIZE);          
        command = command >> RS_SIZE;
        
        rs2 = command % (1 << RS_SIZE);          
        command = command >> RS_SIZE;
        
        cnst10_5 = command % (1 << 6);         
        command = command >> 6;
        
        cnst12 = command;

        cnst = ((((((cnst12 << 1) + cnst11) << 6) + cnst10_5) << 4) + cnst4_1) << 1;
        cnst -= (cnst >> 12) * (2 << 12);

    }
};

struct U_type {
    uint32_t    opcode;
    uint32_t    rd;
    int64_t     cnst;

    std::map <std::vector <uint32_t>, std::string> command = {
            {{55}, "lui"},
            {{23}, "auipc"}
    };

    void parse (uint32_t command) {
        opcode = command % (1 << OPCODE_SIZE);
        command = command >> OPCODE_SIZE;

        rd = command % (1 << RD_SIZE);
        command = command >> RD_SIZE;

        cnst = command;
    }
};

struct J_type {
    uint32_t    opcode;
    uint32_t    rd;
    uint32_t    cnst_19_12;
    uint32_t    cnst_11;
    uint32_t    cnst_10_1;
    uint32_t    cnst_20;
    int64_t     cnst;

    std::map <std::vector <uint32_t>, std::string> command = {
            {{111},"jal"}
    };

    void parse (uint32_t command) {
        opcode = command % (1 << OPCODE_SIZE);
        command = command >> OPCODE_SIZE;

        rd = command % (1 << RD_SIZE);
        command = command >> RD_SIZE;

        cnst_19_12 = command % (1 << 8);
        command = command >> 8;

        cnst_11 = command % (1 << 1);
        command = command >> 1;

        cnst_10_1 = command % (1 << 10);
        command = command >> 10;

        cnst_20 = command;

        cnst = ((((((cnst_20 << 8) + cnst_19_12) << 1) + cnst_11) << 10) + cnst_10_1) << 1;
        cnst -= (cnst >> 20) * (2 << 20);
    }
};

int parse_and_write_text_or_disassembler(std::vector<elf_symbol> &symtab, std::ifstream& elf_file, std::ofstream& fout, section_header text, std::map<int, std::string>& addresses_of_function_names) {
    uint32_t addr = text.sh_addr;

    fout << ".text" << '\n';

    int counter = 0;

    for (int i = 0; i < text.sh_size / 4; i++) {
        if (addresses_of_function_names.count(addr)) {
            std::string temp_str = format("%08x   <%s>:\n", addr, addresses_of_function_names[addr].c_str());
            fout << temp_str;
        }

        uint32_t command;
        elf_file.seekg(text.sh_offset + i * 4, std::ios::beg);
        
        if (!elf_file.read((char *) &command, sizeof(command)).good()) {
            std::cerr <<"Error: Could not read command" << std::endl;
            return 1;
        }

        uint32_t opcode = command % (1 << OPCODE_SIZE);

        if (opcode == 51) {
            R_type type;
            type.parse(command);

            std::string temp_str = format("   %05x:\t%08x\t%7s\t%s, %s, %s\n", addr, command,
                      type.command[{type.funct7, type.funct3}].c_str(),
                      reg[type.rd].c_str(), reg[type.rs1].c_str(), reg[type.rs2].c_str()
                );

            fout << temp_str;
        } else if (opcode == 3 || opcode == 19 || opcode == 103) {
            I_type type;
            type.parse(command);

            std::string temp_str;

            if (opcode == 19) {
                temp_str = format("   %05x:\t%08x\t%7s\t%s, %s, %s\n", addr, command,
                                              type.command[{opcode, type.funct3}].c_str(),
                                              reg[type.rd].c_str(), reg[type.rs1].c_str(),
                                              std::to_string(type.cnst).c_str()
                );
            } else {
                temp_str = format("   %05x:\t%08x\t%7s\t%s, %s(%s)\n", addr, command,
                                              type.command[{opcode, type.funct3}].c_str(),
                                              reg[type.rd].c_str(),
                                              std::to_string(type.cnst).c_str(), reg[type.rs1].c_str()
                );
            }

            fout << temp_str;
        } else if (opcode == 35) {
            S_type type;
            type.parse(command);

            std::string temp_str = format("   %05x:\t%08x\t%7s\t%s, %s(%s)\n", addr, command,
                       type.command[{opcode, type.funct3}].c_str(), reg[type.rs2].c_str(),
                       std::to_string(type.cnst).c_str(), reg[type.rs1].c_str()
            );

            fout << temp_str;
        } else if (opcode == 99) {
            B_type type;
            type.parse(command);

            std::string temp_str;

            if (addresses_of_function_names.count(addr+type.cnst)) {
                temp_str = format("   %05x:\t%08x\t%7s\t%s, %s, 0x%05x <%s>\n", addr, command,
                                  type.command[{opcode, type.funct3}].c_str(),
                                  reg[type.rs1].c_str(), reg[type.rs2].c_str(), addr + type.cnst,
                                  addresses_of_function_names[addr+type.cnst].c_str()
                );
            } else {
                temp_str = format("   %05x:\t%08x\t%7s\t%s, %s, 0x%05x <%s%s>\n", addr, command,
                                  type.command[{opcode, type.funct3}].c_str(),
                                  reg[type.rs1].c_str(), reg[type.rs2].c_str(), addr + type.cnst,
                                  "L", std::to_string(counter).c_str()
                );
                addresses_of_function_names[addr + type.cnst] = ("L" + std::to_string(counter));
                counter++;
            }
            fout << temp_str;
        } else if (opcode == 23 || opcode == 55) {
            U_type type;
            type.parse(command);

            std::string temp_str = format("   %05x:\t%08x\t%7s\t%s, %s\n", addr, command,
                        type.command[{opcode}].c_str(),
                        reg[type.rd].c_str(), std::to_string(type.cnst).c_str()
            );

            fout << temp_str;
        } else if (opcode == 111) {
            J_type type;
            type.parse(command);

            std::string temp_str;

            if (addresses_of_function_names.count(addr + type.cnst)) {
                temp_str = format("   %05x:\t%08x\t%7s\t%s, 0x%05x <%s>\n", addr, command,
                                  type.command[{opcode}].c_str(),
                                  reg[type.rd].c_str(), addr + type.cnst, addresses_of_function_names[addr + type.cnst].c_str()
                );
            } else {
                temp_str = format("   %05x:\t%08x\t%7s\t%s, 0x%05x <%s%s>\n", addr, command,
                                  type.command[{opcode}].c_str(),
                                  reg[type.rd].c_str(), addr + type.cnst, addresses_of_function_names[addr + type.cnst].c_str(), "L", std::to_string(counter).c_str()
                );

                addresses_of_function_names[addr + type.cnst] = "L" + std::to_string(counter);
                counter++;
            }

            fout << temp_str;
        } else if (opcode == 115) {
            uint32_t parse_command = command;
            parse_command = parse_command >> (OPCODE_SIZE + RD_SIZE + FUNCT3_SIZE + RS_SIZE);
            uint32_t rd = (command >> OPCODE_SIZE) % (1 << RD_SIZE);
            uint32_t funct3 = (command >> (OPCODE_SIZE + RD_SIZE)) % (1 << FUNCT3_SIZE);
            uint32_t rs = (command >> (OPCODE_SIZE + RD_SIZE + FUNCT3_SIZE)) % (1 << RS_SIZE);
            uint32_t cnst = int32_t (parse_command - (parse_command >> 11) * (2 << 11));

            if (rd == 0 && funct3 == 0 && rs == 0) {
                if (cnst == 0) {
                    std::string temp_str = format("   %05x:\t%08x\t%s\n", addr, command, "   ecall");
                    fout << temp_str;
                } else {
                    std::string temp_str = format("   %05x:\t%08x\t%s\n", addr, command, "   ebreak");
                    fout << temp_str;
                }
            } else {
                std::string temp_str = format("   %05x:\t%08x\t%s\n", addr, command,"   unknown_instruction");
                fout << temp_str;
            }
        } else {
            std::string temp_str = format("   %05x:\t%08x\t%s\n", addr, command,"   unknown_instruction");
            fout << temp_str;
        }

        addr += 4;
    }

    return 0;
}

int parse_elf_file(std::ifstream& elf_file, std::string fout_name) {
    elf_file_header elf_header;

    if (!elf_file.read((char*)&elf_header, sizeof(elf_header)).good()) {
        std::cerr <<"Error: Could not read e_ident" << std::endl;
        return 1;
    }

    if (!(elf_header.e_ident[1] == 'E' && elf_header.e_ident[2] == 'L' && elf_header.e_ident[3] == 'F')) {
        std::cerr <<"Error: Wrong file format\n";
        return 1;
    }
    
    //TODO: добавить еще несколько проверок (на 32-битность, на RISC_V)

    std::vector<section_header> section_headers;

    elf_file.seekg(elf_header.e_shoff, std::ios::beg);

    for (int i = 0; i < elf_header.e_shnum; i++) {
        section_header temp;

        if (!elf_file.read((char*)&temp, sizeof(section_header)).good()) {
            std::cerr <<"Error: Could not read section header with number:" << i << std::endl;
            return 1;
        }

        section_headers.push_back(temp);
    }

    int index_of_symtab = -1;
    int index_of_text = -1;
    int index_of_strtab = -1;

    std::vector<elf_symbol> symtab;

    int help_address = section_headers[elf_header.e_shstrndx].sh_offset;

    for (int i = 0; i < elf_header.e_shnum; i++) {
        std::string name;

        elf_file.seekg(help_address + section_headers[i].sh_name, std::ios::beg);

        char char_buffer = ' ';
        while (char_buffer != '\0') {
            if (!elf_file.read((char *) &char_buffer, 1).good()) {
                std::cerr <<"Error: Could not read name of section header with number:" << i << std::endl;
                return 1;
            }
            if (char_buffer != '\0') {
                name += char_buffer;
            }
        }

        if (name == ".symtab") {
            index_of_symtab = i;
        } else if (name == ".text") {
            index_of_text = i;
        } else if (name == ".strtab") {
            index_of_strtab = i;
        }
    }

    if (index_of_symtab == -1) {
        std::cerr <<"Error: Could not find symtab block" << std::endl;
        return 1;
    }

    if (index_of_text == -1) {
        std::cerr <<"Error: Could not find text block" << std::endl;
        return 1;
    }

    if (index_of_strtab == -1) {
        std::cerr <<"Error: Could not find strtab block" << std::endl;
        return 1;
    }

    std::ofstream fout;
    fout.open(fout_name, std::ios::binary);

    if (!fout.is_open()) {
        std::cerr <<"Error: Could not open output file" << std::endl;
        return 1;
    }

    if (parse_symtab(elf_file, section_headers[index_of_symtab], symtab)) {
        std::cerr <<"Error: Could not parse symtab" << std::endl;
        return 1;
    }

    std::vector<std::string> names_of_symbols;
    std::map<int, std::string> addresses_of_function_names;

    if (get_names_of_symbols(symtab, elf_file, section_headers[index_of_strtab].sh_offset, names_of_symbols, addresses_of_function_names)) {
        std::cerr <<"Error: Could not get names of symbol" << std::endl;
        return 1;
    }

    if (parse_and_write_text_or_disassembler(symtab, elf_file, fout, section_headers[index_of_text], addresses_of_function_names)) {
        std::cerr <<"Error: Could not work with text" << std::endl;
        return 1;
    }

    if (write_symtab(symtab, elf_file, fout, names_of_symbols)) {
        std::cerr <<"Error: Could not write symtab" << std::endl;
        return 1;
    }

    fout.close();

    return 0;
}

//TODO: привести main в нормальное состояние из дебажного

int main(int argc, char const* argv[]) {
//int main() {
    const char* fin_name = argv[1];
    const char* fout_name = argv[2];

    //const std::string fin_name ="/Users/maria.barkovskaya/Documents/университет/computure_architecture/lab3/test_elf";
    //const std::string fout_name ="/Users/maria.barkovskaya/Documents/университет/computure_architecture/lab3/output.txt";

    std::ifstream fin;
    fin.open(fin_name, std::ios::binary);

    if (!fin.is_open()) {
        std::cerr <<"Error: Could not open elf file" << std::endl;
        return 0;
    }

    if (parse_elf_file(fin, fout_name) == 1) {
        std::cerr <<"Error: Could not parse elf file" << std::endl;
        return 0;
    }

    fin.close();

    return 0;
};