#include "../msg.h"
#include <iostream>
#include <cstring>
#include <string>

int main() {
    std::cout << "Simple Buffer Boundary Test\n";
    std::cout << "==========================\n";

    // Step 1: Create a message and fill it to near capacity
    af::Msg msg(af::Msg::TNULL, 0);

    // Calculate size to fill buffer to near boundary
    int dataSize = af::Msg::SizeBuffer - af::Msg::SizeHeader - 1;  // Leave 1 byte free

    std::cout << "Creating buffer with " << dataSize << " bytes of data\n";

    // Create data that doesn't have null terminators
    std::string data(dataSize, 'A');
    data.replace(0, 16, "GET /test HTTP/1.1");

    // Set the data in the message
    if (!msg.setData(data.size(), data.c_str(), af::Msg::THTTPGET)) {
        std::cout << "Failed to set data\n";
        return 1;
    }

    // Step 2: Write exactly at the buffer boundary
    std::cout << "Writing at buffer boundary\n";
    char* boundary = msg.writtenBuffer(1);
    if (!boundary) {
        std::cout << "Failed to get buffer for writing\n";
        return 1;
    }
    boundary[0] = 'X';

    // // Step 3: Access the data and use string functions
    const char* buffer = msg.buffer() + af::Msg::SizeHeader;
    std::cout << "Running sscanf() on buffer (should trigger error)\n";

    int version = 0;
    sscanf(buffer, "GET %*s HTTP/%d", &version);

    std::cout << "Test complete - check Valgrind output for errors\n";
    return 0;
}
