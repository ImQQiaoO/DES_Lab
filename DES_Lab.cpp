﻿#include <bitset>
#include <iostream>
#include <vector>
#include <filesystem>
#include <fstream>
#include <thread>

#include "DES_constants.h"

using namespace std;

/**
 * 将传入的字符串转化为二进制bitset
 * @param sub_str 传入的字符串
 * @return 二进制bitset
 */
bitset<64> str_to_bitset(const string &sub_str) {
    bitset<64> bits;
    for (size_t i = 0; i < sub_str.size(); ++i) { //sub_str.size() = 8
        bitset<8> temp_char(sub_str[i]);
        for (size_t j = 0; j < 8; ++j) {
            bits[(7 - i) * 8 + j] = temp_char[j];
        }
    }
    return bits;
}

/**
 * 将明文转化为二进制块
 * @return blocks 64位二进制块的vector
 */
vector<bitset<64>> generate_text_block(string &str) {
    vector<bitset<64>> blocks;
    unsigned short empty_bytes;
    if (str.size() % 8) {
        empty_bytes = 8 - str.size() % 8;
    } else {
        empty_bytes = 0;
    }
    // 将不足8位的用全0填充至8位
    for (size_t i = 0; i < empty_bytes; ++i) {
        str.push_back('\0');
    }
    for (size_t i = 0; i < str.size() / 8; ++i) {
        string temp_sub_str = str.substr(i * 8, 8);
        auto bits = str_to_bitset(temp_sub_str);
        blocks.push_back(bits);
    }
    return blocks;
}


/**
 * 检查key是否合法
 * @param key
 * @return
 */
bool check_key_legality(const string &key) {
    return key.size() == 8;
}

/**
 * 生成子密钥
 * @param key
 */
vector<bitset<48>> generate_key(const string &key) {
    bitset<64> bits = str_to_bitset(key);
    bitset<56> key_56;
    for (size_t i = 0; i < 56; ++i) {
        key_56[55 - i] = bits[64 - PC_1[i]];
    }
    bitset<28> left, right;
    vector<bitset<48>> sub_keys(16);
    bitset<48> sub_key;
    for (size_t i = 0; i < 16; ++i) {
        for (size_t j = 0; j < 28; ++j) {
            right[j] = key_56[j];
            left[27 - j] = key_56[j + 28];
        }
        left = (left << shiftBits[i]) | (left >> (28 - shiftBits[i]));
        right = (right << shiftBits[i]) | (right >> (28 - shiftBits[i]));
        bitset<56> temp_key;
        for (size_t j = 0; j < 28; ++j) {
            temp_key[j] = left[j];
            temp_key[j + 28] = right[j];
        }
        for (size_t j = 0; j < 48; ++j) {
            sub_key[47 - j] = temp_key[56 - PC_2[j]];
        }
        sub_keys[i] = sub_key;
    }
    return sub_keys;
}

/**
 * 密码函数f，将32位扩展至48位，与子密钥异或，通过S盒压缩至32位，最后进行P置换
 * @param right
 * @param sub_key
 * @return
 */
bitset<32> f(const bitset<32> &right, const bitset<48> &sub_key) {
    bitset<48> expanded_right;
    for (size_t i = 0; i < 48; ++i) {
        expanded_right[47 - i] = right[32 - E[i]];
    }
    expanded_right ^= sub_key;
    bitset<32> result;
    for (size_t i = 0; i < 8; ++i) {
        int row = expanded_right[47 - i * 6] * 2 + expanded_right[47 - (i + 1) * 6 + 1];
        int col = expanded_right[47 - i * 6 - 1] * 8 + expanded_right[47 - i * 6 - 2] * 4 + expanded_right[47 - i * 6 - 3] * 2 + expanded_right[47 - i * 6 - 4];
        int num = S_BOX[i][row][col];
        for (size_t j = 0; j < 4; ++j) {
            result[31 - i * 4 - j] = (num >> j) & 1;
        }
    }
    bitset<32> final_result;
    for (size_t i = 0; i < 32; ++i) {
        final_result[31 - i] = result[32 - P[i]];
    }
    return final_result;
}



/**
 * 加密明文块
 * @param original 明文
 * @param sub_keys 子密钥
 * @return
 */
bitset<64> encrypt_text(const bitset<64> &original, const vector<bitset<48>> &sub_keys) {
    bitset<64> curr_text;
    // 初始置换
    for (size_t i = 0; i < 64; ++i) {
        curr_text[63 - i] = original[64 - IP[i]];
    }
    // 将完成初始置换后的64位明文分为左右两部分
    bitset<32> left, right;
    for (size_t i = 0; i < 32; ++i) {
        left[i] = curr_text[i];
        right[i] = curr_text[i + 32];
    }
    // 16轮迭代
    for (size_t i = 0; i < 16; ++i) {
        bitset<32> temp = right;
        right = left ^ f(right, sub_keys[i]);	// f函数
        left = temp;
    }
    // 按R，L合并左右两部分
    for (size_t i = 0; i < 32; ++i) {
        curr_text[i] = right[i];
        curr_text[i + 32] = left[i];
    }
    // 结尾置换IP_1
    bitset<64> encrypted_text;
    for (size_t i = 0; i < 64; ++i) {
        encrypted_text[63 - i] = curr_text[64 - IP_1[i]];
    }
    return encrypted_text;
}

void multithreading_encrypt_text(const vector<bitset<64>> &input_file, vector<bitset<64>> &encrypted_blocks, const int start, const int end, const vector<bitset<48>> &sub_keys) {
    for (int i = start; i < end; ++i) {
        encrypted_blocks[i] = encrypt_text(input_file[i], sub_keys);
    }
}

bitset<64> decrypt_text(const bitset<64> &original, const vector<bitset<48>> &sub_keys) {
    bitset<64> curr_text;
    // 初始置换
    for (size_t i = 0; i < 64; ++i) {
        curr_text[63 - i] = original[64 - IP[i]];
    }
    // 将完成初始置换后的64位明文分为左右两部分
    bitset<32> left, right;
    for (size_t i = 0; i < 32; ++i) {
        left[i] = curr_text[i];
        right[i] = curr_text[i + 32];
    }
    // 16轮迭代
    for (size_t i = 0; i < 16; ++i) {
        bitset<32> temp = right;
        right = left ^ f(right, sub_keys[15 - i]);	// f函数
        left = temp;
    }
    // 按R，L合并左右两部分
    for (size_t i = 0; i < 32; ++i) {
        curr_text[i] = right[i];
        curr_text[i + 32] = left[i];
    }
    // 结尾置换IP_1
    bitset<64> text;
    for (size_t i = 0; i < 64; ++i) {
        text[63 - i] = curr_text[64 - IP_1[i]];
    }
    return text;
}


/**
 * 输出函数
 * @param blocks
 */
void show_blocks(const vector<bitset<64>> &blocks) {
    for (auto block : blocks) {
        cout << block << endl;
    }
}

pair<vector<bitset<64>>, vector<bitset<48>>> encrypt_string(string &text, const string &key) {
    if (!check_key_legality(key)) {
        cout << "Key is illegal!" << endl;
        return {};
    }
    // 生成子密钥
    auto sub_keys = generate_key(key);
    // 生成明文块
    vector<bitset<64>> blocks = generate_text_block(text);
    cout << "明文为：\n" << text << "\n二进制明文块为： " << endl;
    show_blocks(blocks);	// 输出明文块
    // 加密明文块
    vector<bitset<64>> encrypted_blocks;
    encrypted_blocks.reserve(blocks.size());
    for (auto &block : blocks) {
        encrypted_blocks.push_back(encrypt_text(block, sub_keys));
    }
    // 加密完成，回收内存
    blocks.clear();

    cout << "经过DES加密后结果为： " << endl;
    show_blocks(encrypted_blocks);	// 输出密文块
    return {encrypted_blocks, sub_keys};
}

void decrypt_string(const vector<bitset<64>> &encrypted_blocks, const vector<bitset<48>> &sub_key) {
    cout << "\n解密后的结果为：";
    // 解密密文块
    for (auto &block : encrypted_blocks) {
        auto decrypt_code = decrypt_text(block, sub_key);
        // 将解密后的明文块转化为字符串
        string decrypted_str;
        for (size_t i = 0; i < 8; ++i) {
            bitset<8> temp;
            for (size_t j = 0; j < 8; ++j) {
                temp[j] = decrypt_code[(7 - i) * 8 + j];
            }
            decrypted_str.push_back(static_cast<char>(temp.to_ulong()));
        }
        cout << decrypted_str;
    }
    cout << endl;
}

vector<bitset<64>> read_file(const string &target_file_name) {
    // 查找当前文件夹中是否存在此文件
    bool find_file = false;
    for (const auto &entry : filesystem::directory_iterator("./")) {
        auto file_name = entry.path().filename();
        if (file_name == target_file_name) {
            find_file = true;
            break;
        }
    }
    if (!find_file) {
        cout << "File not found!" << endl;
        return{};
    }

    // 以二进制模式读取文件
    vector<bitset<64>> bits_blocks;
    ifstream file("./" + target_file_name, ios::binary | ios::ate);
    if (file.is_open()) {
        streamsize size = file.tellg();
        file.seekg(0, ios::beg);
        vector<char> buffer(size);
        if (file.read(buffer.data(), size)) {
            bitset<64> bits_block;
            if (buffer.size() % 8 != 0) {
                for (size_t i = 0; i < buffer.size() % 8; ++i) {
                    buffer.push_back('\0');
                }
            }
            for (size_t i = 0; i < buffer.size(); ++i) {
                bitset<8> bits(buffer[i]);
                for (size_t j = 0; j < 8; ++j) {
                    bits_block[(i % 8) * 8 + j] = bits[j];
                }
                // 满64位就向数组中push
                if (i % 8 == 7) {
                    bits_blocks.push_back(bits_block);
                }
            }
        }
    } else {
        cout << "Error: Could not open file." << endl;
    }

    return bits_blocks;
}

// 解密文件
void decrypt_file(const string &file_name, const string &key) {
    // 读取文件
    ifstream read_file(file_name, ios::binary | ios::in);
    vector<bitset<64>> blocks;
    if (!read_file) {
        cout << "无法打开文件" << endl;
        return;
    }

    while (!read_file.eof()) {
        bitset<64> block;
        read_file.read(reinterpret_cast<char *>(&block), sizeof(block));
        if (read_file.gcount() != sizeof(block)) {
            break;  // 文件结束或者读取错误
        }
        blocks.push_back(block);
    }
    read_file.close();

    vector<bitset<64>> decrypted_blocks;
    decrypted_blocks.reserve(blocks.size());
    // 解密文件
    auto sub_keys = generate_key(key);
    for (auto &block : blocks) {
        decrypted_blocks.push_back(decrypt_text(block, sub_keys));
    }

    // 将解密后的内容以写入文件中
    ofstream output_file("decrypted_" + file_name, ios::binary);
    for (auto &block : decrypted_blocks) {
        output_file.write(reinterpret_cast<char *>(&block), sizeof(block));
        output_file.seekp(0, ios::end);
    }
    output_file.close();
}


uintmax_t get_file_size(const string &file_name) {
    // 获取文件的大小
    uintmax_t file_size = 0;
    filesystem::path file_path = "./" + file_name;
    try {
        file_size = filesystem::file_size(file_path);
    } catch (std::filesystem::filesystem_error &e) {
        cout << e.what() << '\n';
    }
    return file_size;
}

int main() {
    size_t choice;
    //cin >> choice;
    choice = 2;
    if (choice == 1) {
        string str_text = "abcdefgh";
        string key = "01234567";
        auto encrypted_str = encrypt_string(str_text, key);
        decrypt_string(encrypted_str.first, encrypted_str.second);
    } else if (choice == 2) {
        string file_name = "IMG_0732.jpeg";
        auto file_size = get_file_size(file_name);
        cout << "所选文件大小为 " << file_size << " Byte.\n";
        string key = "01234567";
        auto start_encrypt = chrono::system_clock::now();	// 获取当前时间（文件加密开始）
        auto sub_keys = generate_key(key);
        auto input_file = read_file(file_name);

        /*
        vector<bitset<64>> encrypted_blocks;
        encrypted_blocks.reserve(input_file.size());
        for (auto &block : input_file) {
            encrypted_blocks.push_back(encrypt_text(block, sub_keys));
        }*/

        vector<bitset<64>> encrypted_blocks(input_file.size());
        auto num_threads = thread::hardware_concurrency();
        unsigned elements_per_thread = static_cast<unsigned>(input_file.size() / num_threads);
        vector<thread> threads;
        for (unsigned i = 0; i < num_threads; ++i) {
            unsigned start = i * elements_per_thread;
            unsigned end = (i == num_threads - 1) ? static_cast<unsigned>(input_file.size()) : start + elements_per_thread;
            threads.emplace_back(multithreading_encrypt_text, cref(input_file), ref(encrypted_blocks), start, end, cref(sub_keys));
        }
        // 等待所有线程完成
        for (auto &th : threads) {
            th.join();
        }

        /**
        vector<bitset<64>> encrypted_blocks(input_file.size());
        auto num_threads = thread::hardware_concurrency();
        int elements_per_thread = input_file.size() / num_threads;
        vector<thread> threads;
        for (int i = 0; i < num_threads; ++i) {
            int start = i * elements_per_thread;
            int end = (i == num_threads - 1) ? input_file.size() : start + elements_per_thread;
            threads.emplace_back(encrypt_text, ref(input_file), ref(encrypted_blocks), start, end);
        }
        // 等待所有线程完成
        for (auto &th : threads) {
            th.join();
        }
         */
         // 将加密后的内容写入文件中
        ofstream output_file("encrypted_" + file_name, ios::binary | ios::out | ios::app);
        for (auto &block : encrypted_blocks) {
            output_file.write(reinterpret_cast<char *>(&block), sizeof(block));
            // 将文件指针移动到文件末尾
            output_file.seekp(0, ios::end);
        }
        output_file.close();
        auto end_encrypt = chrono::system_clock::now();	// 获取当前时间（文件加密结束）
        cout << "文件加密完成，本次加密用时" << chrono::duration_cast<chrono::seconds>(end_encrypt - start_encrypt).count() << "s." << endl;
        auto start_decrypt = chrono::system_clock::now();	// 获取当前时间（文件加密开始）
        decrypt_file("encrypted_" + file_name, key);
        auto end_decrypt = chrono::system_clock::now();	// 获取当前时间（文件加密结束）
        cout << "文件解密完成, 本次解密用时" << chrono::duration_cast<chrono::seconds>(end_decrypt - start_decrypt).count() << "s." << endl;
    }
    return 0;
}

