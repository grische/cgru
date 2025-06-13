#include "../msg.h"
#include <cstring>
#include <iostream>
#include <string>

// Need to declare the function from name_afnet.cpp since it's defined there
namespace af
{
extern int processHeader(af::Msg *io_msg, int i_bytes);
}

int test_processheader_invalid_free()
{
	std::cout << "Testing processHeader vulnerability with non-null-terminated buffer\n";

	// Create a message with a deliberately crafted buffer
	af::Msg msg(af::Msg::TNULL, 0);

	// First, allocate a buffer with some initial data
	std::string initial_data(100, 'A');
	if (!msg.setData(initial_data.size(), initial_data.c_str(), af::Msg::TDATA))
	{
		std::cout << "Failed to set initial data\n";
		return 1;
	}

	// Get access to the buffer
	char *buffer = msg.writtenBuffer(0); // Get direct access to the buffer
	if (!buffer)
	{
		std::cout << "Failed to get buffer\n";
		return 1;
	}

	// Fill the buffer with the problematic pattern:
	// "AFANASY12345" without a null terminator, followed by non-numeric data
	strcpy(buffer, "AFANASY12345");

	// Fill the rest of the buffer with non-zero data to ensure no accidental null termination
	int header_len = strlen("AFANASY12345");
	int buffer_size = af::Msg::SizeBuffer; // Get the actual buffer size

	// Fill the remainder of the buffer with non-zero bytes
	// Leave the last byte of the buffer as non-zero to ensure no null terminator
	for (int i = header_len; i < buffer_size - 1; i++)
	{
		buffer[i] = 'X'; // Non-numeric character
	}
	buffer[buffer_size - 1] = 'Z'; // Ensure last byte is not null

	std::cout << "Calling processHeader with non-null-terminated buffer...\n";

	// Call processHeader with the crafted buffer
	// This should trigger the bug where sscanf reads past the buffer
	int result = af::processHeader(&msg, buffer_size);

	// If we get here without crashing, check if the function behaved reasonably
	std::cout << "ProcessHeader returned: " << result << std::endl;

	// Since our test involves memory access that might be caught by tools like Valgrind
	// but not cause immediate crashes, we consider the test "passed" if execution continues
	std::cout << "processHeader overflow test completed\n";

	return 0;
}

int main()
{
	std::cout << "Running processHeader vulnerability tests...\n\n";
	int global_result = 0;
	{
		const int result = test_processheader_invalid_free();
		std::cout << "Test test_processheader_invalid_free completed with return code: " << result
				  << std::endl;
		global_result += result;
	}
	return global_result;
}
