#pragma once

#include "common.hpp"

template<typename T, typename F>
void c_func_worker(std::vector<T> &vals, F comparator, size_t i, size_t j) {
	if (i >= j) return;

	size_t m = (i + j) / 2;
	c_func_worker(vals, comparator, i, m);
	c_func_worker(vals, comparator, m + 1, j);

	if (comparator(vals.at(j), vals.at(m))) {
		std::swap(vals.at(j), vals.at(m));
	}

	c_func_worker(vals, comparator, i, j - 1);
}

template<typename T, typename F>
std::vector<T> c_func(std::vector<T> vals, F comparator) {
	if (vals.empty()) return {};
	c_func_worker(vals, comparator, 0, vals.size() - 1);
	return vals;
}

template<typename T>
bool ise(T v) {
	std::vector<T> values;
	for (size_t i = 0; i <= v; ++i) {
		values.push_back(i % 2);
	}

	auto ones = std::count(values.begin(), values.end(), 1);
	auto zeros = std::count(values.begin(), values.end(), 0);
	return zeros > ones;
}

template<typename T>
T a_func_worker(std::vector<T> vals) {
	std::vector<T> leftovers;
	while (vals.size() != 1) {
		leftovers.clear();
		for (size_t i = 0; i < vals.size() && i + 1 < vals.size(); i += 2) {
			if (vals.at(i) < vals.at(i + 1)) {
				leftovers.push_back(vals.at(i + 1));
			} else {
				leftovers.push_back(vals.at(i));
			}
		}
		if (!ise(vals.size())) {
			leftovers.push_back(vals.back());
		}

		vals.assign(leftovers.begin(), leftovers.end());
	}
	return leftovers.front();
}

template<typename T>
T a_func(std::vector<T> vals) {
	std::vector<T> erased;
	std::vector<T> reduced;
	while (true) {
		reduced = vals;

		for (auto v: erased) {
			reduced.erase(std::remove(reduced.begin(), reduced.end(), v),
						  reduced.end());
		}

		if (std::equal(reduced.begin() + 1, reduced.end(), reduced.begin()) ||
			reduced.size() == 1) {
			break;
		}

		erased.insert(erased.begin(), a_func_worker<T>(reduced));
	}
	return reduced.at(0);
}

template<typename T>
T d_func(std::vector<T> vals) {
	u64 result = 0;

	if(vals.empty()){
		return result;
	}

	for(const auto v : vals){
		result += v;
	}

	return func1(result, vals.size());
}

template<typename T>
std::vector<T> g(std::vector<std::pair<T, T>> to_extract) {
	std::vector<T> out;
	for (auto [s, e]: to_extract) {
		for (int i = s; i <= e; ++i) {
			out.push_back(i);
		}
	}

	return out;
}

void print_flag() {
	u32 idx = 0;
	for (auto char_data: atad) {
		u64 a, c, d;
		auto a_data = char_data[0];
		auto c_data = char_data[1];
		auto d_data = char_data[2];

		auto a_vals = g<u32>(a_data);
		a = a_func(a_vals);
//		a = chall_verify[idx][0];
//		debug(idx, 0, a_vals, a);

		auto c_vals = g<u32>(c_data);
		auto c_sorted = c_func(c_vals, std::less<>());
		auto c_size = c_sorted.size();
		for (int i = 0; i < (c_size / 2); i++) {
			c_sorted.erase(c_sorted.begin());
		}
		c = c_sorted.at(0);
//		c = chall_verify[idx][1];
//		debug(idx, 1, c_vals, c);

		auto d_vals = g<u32>(d_data);
		d = d_func(d_vals);
//		d = chall_verify[idx][2];
//		debug(idx, 2, d_vals, d);

		auto flag_char = func0(a, c, d, idx);

		idx += 1;
		std::cout << flag_char << std::flush;
//		std::cout << std::endl;
	}
}
