#include "../msg.h"
#include <climits>
#include <iostream>
#include <string>

int memmove_negative_copy_test()
{
	std::cout << "Testing memmove vulnerability with negative copy length\n";

	af::Msg msg(af::Msg::TNULL, 0);

	// Set some data first to ensure we have a buffer
	std::string data(100, 'A');
	if (!msg.setData(data.size(), data.c_str(), af::Msg::TDATA))
	{
		std::cout << "Failed to set initial data\n";
		return 1;
	}

	std::cout << "Calling setHeader with parameters that force negative copy length in memmove...\n";

	// The key vulnerability: when offset > bytes, it creates a negative copy length
	// This takes the memmove path (not allocateBuffer path)
	int offset = 1000;
	int bytes = 10;		 // bytes < offset creates a negative value for copy length
	int small_size = 50; // Keep size small to avoid allocateBuffer path

	msg.setHeader(af::Msg::TDATA, small_size, offset, bytes);

	if (msg.type() != af::Msg::TInvalid)
	{
		return 2;
	}

	std::cout << "memmove negative copy test passed: message was properly invalidated\n";
	return 0;
}

int memmove_huge_negative_copy_test()
{
	std::cout << "Testing allocateBuffer with potential integer overflow\n";

	af::Msg msg(af::Msg::TNULL, 0);

	// Set initial data
	std::string data(50, 'C');
	if (!msg.setData(data.size(), data.c_str(), af::Msg::TDATA))
	{
		std::cout << "Failed to set initial data\n";
		return 1;
	}

	std::cout << "Calling setHeader with values that could cause integer overflow...\n";

	// Try to cause integer overflow in the calculation
	int large_size = 10000;
	int max_offset = INT_MAX;
	int wrap_bytes = 1000; // This will wrap around when added to max_offset

	// When bytes calculation overflows, it might become negative or small
	// This could lead to unexpected behavior
	msg.setHeader(af::Msg::TDATA, large_size, max_offset, wrap_bytes);

	if (msg.type() != af::Msg::TInvalid)
	{
		return 2;
	}

	std::cout << "memmove Integer overflow test passed: message was properly invalidated\n";
	return 0;
}

int allocate_buffer_negative_copy_test()
{
	std::cout << "Testing allocateBuffer path vulnerability with negative copy length\n";

	af::Msg msg(af::Msg::TNULL, 0);

	// Set initial small data to ensure we have a buffer but small m_data_maxsize
	std::string small_data(50, 'A');
	if (!msg.setData(small_data.size(), small_data.c_str(), af::Msg::TDATA))
	{
		std::cout << "Failed to set initial small data\n";
		return 1;
	}

	std::cout << "Calling setHeader to trigger allocateBuffer path with negative copy length...\n";

	// Force the allocateBuffer path by making i_size larger than current m_data_maxsize
	// AND create negative copy length (i_bytes - i_offset)
	int large_size = 100000; // This will be larger than default 16k m_data_maxsize
	int offset = 2000;
	int bytes = 100; // bytes < offset creates negative copy length (100 - 2000 = -1900)

	// This should trigger:
	// 1. m_data_maxsize < m_int32 (true, because large_size > current buffer)
	// 2. allocateBuffer(large_size + SizeHeader, bytes - offset, offset)
	// 3. bytes - offset = 100 - 2000 = -1900 (negative copy length)
	// 4. Since -1900 <= 0, memcpy is skipped
	msg.setHeader(af::Msg::TDATA, large_size, offset, bytes);

	if (msg.type() != af::Msg::TInvalid)
	{
		return 2;
	}

	std::cout << "allocateBuffer negative test passed: message was properly invalidated\n";
	return 0;
}

int allocate_buffer_memcpy_vulnerability_test()
{
	std::cout << "Testing allocateBuffer memcpy vulnerability with invalid offset\n";

	af::Msg msg(af::Msg::TNULL, 0);

	// Set initial data to ensure we have a buffer
	std::string initial_data(100, 'B');
	if (!msg.setData(initial_data.size(), initial_data.c_str(), af::Msg::TDATA))
	{
		std::cout << "Failed to set initial data\n";
		return 1;
	}

	std::cout << "Calling setHeader to trigger allocateBuffer memcpy with invalid offset...\n";

	// Force the allocateBuffer path AND create a scenario where:
	// 1. i_copy_len > 0 (so memcpy executes)
	// 2. i_copy_offset is very large (potential out-of-bounds read)
	int large_size = 50000;				 // Larger than current buffer to force allocateBuffer
	int huge_offset = 1000000;			 // Very large offset - likely out of bounds
	int large_bytes = huge_offset + 100; // Make bytes > offset so copy_len is positive

	// This should trigger:
	// 1. m_data_maxsize < m_int32 (true, forces allocateBuffer path)
	// 2. allocateBuffer(large_size + SizeHeader, large_bytes - huge_offset, huge_offset)
	// 3. i_copy_len = large_bytes - huge_offset = 100 (positive, so memcpy executes)
	// 4. i_copy_offset = huge_offset = 1000000 (likely out of bounds)
	// 5. memcpy(m_data, old_buffer + 1000000, 100) - reads from invalid memory
	msg.setHeader(af::Msg::TDATA, large_size, huge_offset, large_bytes);

	if (msg.type() != af::Msg::TInvalid)
	{
		return 2;
	}

	std::cout << "memcpy vulnerability test passed: message was properly invalidated\n";
	return 0;
}

int memmove_integer_overflow_test()
{
	std::cout << "Testing allocateBuffer with potential integer overflow\n";

	af::Msg msg(af::Msg::TNULL, 0);

	// Set initial data
	std::string data(50, 'C');
	if (!msg.setData(data.size(), data.c_str(), af::Msg::TDATA))
	{
		std::cout << "Failed to set initial data\n";
		return 1;
	}

	std::cout << "Calling setHeader with values that could cause integer overflow...\n";

	int large_size = 10000;
	int wrap_bytes = 32000;			 // This will be larger than default 16k m_buffer_size
	int max_offset = wrap_bytes - 1; // Set to a large value but smaller than wrap_bytes

	// When bytes calculation overflows, it might become negative or small
	// This could lead to unexpected behavior in: bytes - offset calculation
	msg.setHeader(af::Msg::TDATA, large_size, max_offset, wrap_bytes);

	if (msg.type() != af::Msg::TInvalid)
	{
		return 2;
	}

	std::cout << "Integer overflow test passed: message was properly invalidated\n";
	return 0;
}

int buffer_size_at_limit_test()
{
	std::cout << "Testing buffer size exactly at the size limit\n";

	af::Msg msg(af::Msg::TNULL, 0);

	// Set initial data
	std::string data(1000, 'L');
	if (!msg.setData(data.size(), data.c_str(), af::Msg::TDATA))
	{
		std::cout << "Failed to set initial data\n";
		return 1;
	}

	// Test exactly at the size buffer limit (should be rejected)
	int at_limit_size = af::Msg::SizeBufferLimit;
	std::cout << "Testing size exactly at buffer limit: " << at_limit_size << "\n";
	msg.setHeader(af::Msg::TDATA, at_limit_size, 0, 0);

	if (msg.type() != af::Msg::TInvalid)
	{
		std::cout << "ERROR: Size at limit was accepted\n";
		return 2;
	}

	std::cout << "Buffer size at limit test passed: message was properly invalidated\n";
	return 0;
}

int buffer_size_valid_large_test()
{
	std::cout << "Testing with a large but valid buffer size\n";

	af::Msg msg(af::Msg::TNULL, 0);

	// Set initial data
	std::string data(1000, 'L');
	if (!msg.setData(data.size(), data.c_str(), af::Msg::TDATA))
	{
		std::cout << "Failed to set initial data\n";
		return 1;
	}

	// Test with a reasonably large but valid size (should be accepted)
	int valid_large_size = af::Msg::SizeBufferLimit - 16;
	std::cout << "Testing with valid large size: " << valid_large_size << "\n";
	msg.setHeader(af::Msg::TDATA, valid_large_size, 0, 0);

	if (msg.type() == af::Msg::TInvalid)
	{
		std::cout << "ERROR: Valid large size was rejected\n";
		return 2;
	}

	std::cout << "Valid large buffer size test passed\n";
	return 0;
}

int main()
{
	std::cout << "Running comprehensive buffer vulnerability tests...\n\n";
	int global_result = 0;

	// Last 1A: memmove path with negative copy length should cause memory corruption on finish
	{
		const int result = memmove_negative_copy_test();
		std::cout << "memmove_negative_copy_test returned: " << result << "\n\n";
		global_result += result;
	}

	// Test 1B: memmove path with negative copy length should cause segfault
	{
		const int result = memmove_huge_negative_copy_test();
		std::cout << "memmove_huge_negative_copy_test returned: " << result << "\n\n";
		global_result += result;
	}

	// Test 2: allocateBuffer path with negative copy length (memcpy skipped)
	{
		const int result = allocate_buffer_negative_copy_test();
		std::cout << "allocate_buffer_negative_copy_test returned: " << result << "\n\n";
		global_result += result;
	}

	// Test 3: allocateBuffer path with positive copy length but invalid offset
	{
		const int result = allocate_buffer_memcpy_vulnerability_test();
		std::cout << "allocate_buffer_memcpy_vulnerability_test returned: " << result << "\n\n";
		global_result += result;
	}

	// Test 4: memmove path with integer overflow
	{
		const int result = memmove_integer_overflow_test();
		std::cout << "memmove_integer_overflow_test returned: " << result << "\n\n";
		global_result += result;
	}

	// Test 5: Test buffer size exactly at the limit
	{
		const int result = buffer_size_at_limit_test();
		std::cout << "buffer_size_at_limit_test returned: " << result << "\n\n";
		global_result += result;
	}

	// Test 6: Test buffer size large but valid
	{
		const int result = buffer_size_valid_large_test();
		std::cout << "buffer_size_valid_large_test returned: " << result << "\n\n";
		global_result += result;
	}

	std::cout << "All tests completed. Final return code " << global_result << std::endl;
	return global_result;
}
