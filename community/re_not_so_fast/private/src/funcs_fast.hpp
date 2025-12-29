#pragma once

#include "common.hpp"
#include <numeric>

template<typename T, typename F>
std::vector<T> c_func(std::vector<T> &vals, F comparator) {
	std::sort(vals.begin(), vals.end(), comparator);
	return vals;
}

template<typename T>
bool ise(T v) {
	return v % 2 == 0;
}

template<typename T>
T a_func(const std::vector<T> &vals) {
	return *std::min_element(vals.begin(), vals.end());
}

template<typename T>
T d_func(const std::vector<T> &vals) {
	if(vals.empty()){
		return 0;
	}

	return std::accumulate(vals.begin(), vals.end(), 0ull) / vals.size();
}

template<typename T>
std::vector<T> g(const std::vector<std::pair<T, T>> &to_extract) {
	std::vector<T> out;
	out.reserve(to_extract.size() * 100);
	for (const auto &[s, e]: to_extract) {
		for (int i = s; i <= e; ++i) {
			out.push_back(i);
		}
	}

	return out;
}

void print_flag() {
	u32 idx = 0;
	for (const auto &char_data: atad) {
		const auto &a_data = char_data[0];
		const auto &c_data = char_data[1];
		const auto &d_data = char_data[2];

		const auto a_vals = g<u32>(a_data);
		const auto a = a_func(a_vals);
//		const auto a = chall_verify[idx][0];
//		debug(idx, 0, a_vals, a);

		auto c_vals = g<u32>(c_data);
		c_func(c_vals, std::less<>());
		const auto c = c_vals.at(c_vals.size() / 2);
//		const auto c = chall_verify[idx][1];
//		debug(idx, 1, c_vals, c);

		const auto d_vals = g<u32>(d_data);
		const auto d = d_func(d_vals);
//		const auto d = chall_verify[idx][2];
//		debug(idx, 2, d_vals, d);

		const auto flag_char = func0(a, c, d, idx);

		idx += 1;
		std::cout << flag_char << std::flush;
	}
}
