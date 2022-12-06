#pragma once

#include "communication.hpp"

class KernelInterface
{
public:
	HANDLE hDriver;

	KernelInterface(LPCSTR RegistryPath)
	{
		hDriver = CreateFileA(RegistryPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	}

	//ULONGLONG GetClientAddress()
	ClientInfo GetClientAddress()
	{
		if (hDriver == INVALID_HANDLE_VALUE)
		{
			//return 0;
			return { 0, 0 };
		}

		/*ULONGLONG Address;
		DWORD Bytes;

		if (DeviceIoControl(hDriver, IO_GET_CLIENTADDRESS, &Address, sizeof(Address), &Address, sizeof(Address), &Bytes, NULL))
		{
			return Address;
		}*/

		ClientInfo C_Info;
		DWORD Bytes;

		if (DeviceIoControl(hDriver, IO_GET_CLIENTADDRESS, &C_Info, sizeof(C_Info), &C_Info, sizeof(C_Info), &Bytes, NULL))
		{
			return C_Info;
		}

		//return 0;
		return { 0, 0 };
	}

	DWORD GetProcessId()
	{
		if (hDriver == INVALID_HANDLE_VALUE)
		{
			return 0;
		}

		ULONG ProcessID;
		DWORD Bytes;

		if (DeviceIoControl(hDriver, IO_REQUEST_PROCESSID, &ProcessID, sizeof(ProcessID), &ProcessID, sizeof(ProcessID), &Bytes, NULL))
		{
			return ProcessID;
		}

		return 0;
	}

	template <typename type>
	type ReadVirtualMemory(ULONG ProcessId, ULONGLONG ReadAddress, SIZE_T Size)
	{
		type Buffer;

		KERNEL_READ_REQUEST ReadRequest;

		ReadRequest.ProcessId = ProcessId;
		ReadRequest.Address = ReadAddress;
		ReadRequest.pBuff = &Buffer;
		ReadRequest.Size = Size;

		if (DeviceIoControl(hDriver, IO_READ_REQUEST, &ReadRequest, sizeof(ReadRequest), &ReadRequest, sizeof(ReadRequest), 0, 0))
		{
			return Buffer;
		}

		return Buffer;
	}

	template <typename type>
	bool WriteVirtualMemory(ULONG ProcessId, ULONGLONG WriteAddress, type WriteValue, SIZE_T Size)
	{
		if (hDriver == INVALID_HANDLE_VALUE)
		{
			return false;
		}

		DWORD Bytes;

		KERNEL_WRITE_REQUEST WriteRequest;

		WriteRequest.ProcessId = ProcessId;
		WriteRequest.Address = WriteAddress;
		WriteRequest.pBuff = &WriteValue;
		WriteRequest.Size = Size;

		if (DeviceIoControl(hDriver, IO_WRITE_REQUEST, &WriteRequest, sizeof(WriteRequest), 0, 0, &Bytes, NULL))
		{
			return true;
		}

		return false;
	}

	ULONGLONG* QueryVirtualMemory(ULONG pid, ULONGLONG Addr, SIZE_T Size)//, UCHAR* pattern, char* mask)
	{
		//ULONGLONG pBuff = NULL;
		ULONGLONG pBuff[17];
		KERNEL_COPY_REQUEST QueryRequest;

		QueryRequest.ProcessId = pid;
		QueryRequest.Address = Addr;
		QueryRequest.pBuff = &pBuff;
		QueryRequest.Size = Size;
		//QueryRequest.pattern = pattern;
		//QueryRequest.mask = mask;

		if (DeviceIoControl(hDriver, IO_QUERY_REQUEST, &QueryRequest, sizeof(QueryRequest), &QueryRequest, sizeof(QueryRequest), 0, 0))
		{
			//for(int i = 0; i < 17; i++)
				//printf("addr => 0x%p\n", pBuff[i]);
			return pBuff;
		}
		return NULL;
	}
};