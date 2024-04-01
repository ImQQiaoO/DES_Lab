#include <bitset>
#include <iostream>
#include <vector>
#include <filesystem>
#include <fstream>

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

vector<bitset<64>> read_file(string target_file_name, const string key) {
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
	//// 加密文件名，将其转化为16进制，并保存到一个string中作为新文件名
	//stringstream ss_filename;
	//auto temp = encrypt_string(target_file_name, key).first;
	//for (auto i : temp) {
	//	ss_filename << hex << i;
	//}
	//string new_filename = ss_filename.str();
	//cout << "\n new_filename is" << new_filename << endl;

	// 以二进制模式读取文件
	vector<bitset<64>> bits_blocks;
	std::ifstream file("./" + target_file_name, std::ios::binary | std::ios::ate);
	if (file.is_open()) {
		std::streamsize size = file.tellg();
		file.seekg(0, std::ios::beg);
		std::vector<char> buffer(size);
		bitset<64> bits_block;
		if (file.read(buffer.data(), size)) {
			if (buffer.size() % 8 != 0) {
				for (size_t i = 0; i < buffer.size() % 8; ++i) {
					buffer.push_back('\0');
				}
			}
			for (size_t i = 0; i < buffer.size(); ++i) {
				bitset<8> bits(buffer[i]);
				for (size_t i = 0; i < 8; ++i) {
					bits_block[(7 - i) * 8 + i] = bits[i];
				}
				// 满64位就向数组中push
				if (i % 8 == 7) {
					bits_blocks.push_back(bits_block);
					/*bits_block = bits_block.reset;*/
				}
			}
		}
	} else {
		std::cout << "Error: Could not open file." << std::endl;
	}
	return bits_blocks;
}

// 解密文件
void decrypt_file(const string &file_name, const string &key) {
	auto sub_keys = generate_key(key);
	auto input_file = read_file(file_name, key);
	vector<bitset<64>> decrypted_blocks;
	decrypted_blocks.reserve(input_file.size());
	for (auto &block : input_file) {
		decrypted_blocks.push_back(decrypt_text(block, sub_keys));
	}
	// 将解密后的内容以UTF-8写入文件中
	std::ofstream output_file("decrypted_" + file_name, std::ios::binary);
	for (auto &block : decrypted_blocks) {
		for (size_t i = 0; i < 8; ++i) {
			bitset<8> temp;
			for (size_t j = 0; j < 8; ++j) {
				temp[j] = block[(7 - i) * 8 + j];
			}
			output_file << static_cast<char>(temp.to_ulong());
		}
	}
	output_file.close();
	cout << "文件解密完成" << endl;
}


int main() {
	size_t choice;
	//cin >> choice;
	choice = 2;
	if (choice == 1) {
		string str_text = "full_course_reader.pdf";
		string key = "01234567";
		auto encrypted_str = encrypt_string(str_text, key);
		decrypt_string(encrypted_str.first, encrypted_str.second);
	} else if (choice == 2) {
		string file_name = "file.txt";
		string key = "01234567";
		auto sub_keys = generate_key(key);
		auto input_file = read_file(file_name, key);
		vector<bitset<64>> encrypted_blocks;
		encrypted_blocks.reserve(input_file.size());
		for (auto &block : input_file) {
			encrypted_blocks.push_back(encrypt_text(block, sub_keys));
		}
		// 将加密后的内容写入文件中，（UTF-8）
		std::ofstream output_file("encrypted_" + file_name, std::ios::binary);
		for (auto &block : encrypted_blocks) {
			for (size_t i = 0; i < 8; ++i) {
				bitset<8> temp;
				for (size_t j = 0; j < 8; ++j) {
					temp[j] = block[(7 - i) * 8 + j];
				}
				output_file << static_cast<char>(temp.to_ulong());
			}
		}
		output_file.close();
		cout << "文件加密完成" << endl;
		decrypt_file("encrypted_full_course_reader.pdf", key);
	}
	return 0;
}

