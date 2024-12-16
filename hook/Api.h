#pragma once
#ifndef __API_H__
#define __API_H__
#include <Windows.h>
#include <shlwapi.h> // For SHRegGetPathW
#include <fstream>
#include <string>
#include <iostream>
#include <shobjidl_core.h>
#include <regex>
#include <atlcomcli.h> 
#include <atlbase.h> 
#include "resource.h"
#include <shlobj.h>
#include <vector>
#include <algorithm>
#include <nlohmann/json.hpp>
#include <tchar.h>
#include <shobjidl.h>  // for IKnownFolder
#include <comdef.h>     // for CComPtr
#include <shlobj_core.h>
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Mpr.lib")

#define NT_SUCCESS(Status)			((NTSTATUS)(Status) >= 0)
#ifndef STATUS_NO_MORE_FILES
#define STATUS_NO_MORE_FILES ((NTSTATUS)0x80000006L)
#endif

#define SEARCH_PIPE_NAME "\\\\.\\pipe\\SEARCHDEBUGLOG"

#define ALIGN_UP_BY(length, alignment) \
    (((length) + ((alignment) - 1)) & ~((alignment) - 1))

#define ALIGN_UP_POINTER_BY(pointer, alignment) \
    ((PVOID)ALIGN_UP_BY((ULONG_PTR)(pointer), (alignment)))

#define PREFIX_SIZE				8

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

#define NO_MORE_ENTRIES		0

typedef LONG NTSTATUS;
typedef struct _RESULT_ITEM {
	int Type;
	std::wstring Name;
}RESULT_ITEM, * PRESULT_ITEM;


typedef struct _IO_STATUS_BLOCK
{
	NTSTATUS Status;
	ULONG Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PCHAR  Buffer;
} ANSI_STRING, * PANSI_STRING;

typedef struct _OBJECT_NAME_INFORMATION {
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

typedef enum class _FILE_INFORMATION_CLASS
{
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,                   // 2
	FileBothDirectoryInformation,                   // 3
	FileBasicInformation,                           // 4
	FileStandardInformation,                        // 5
	FileInternalInformation,                        // 6
	FileEaInformation,                              // 7
	FileAccessInformation,                          // 8
	FileNameInformation,                            // 9
	FileRenameInformation,                          // 10
	FileLinkInformation,                            // 11
	FileNamesInformation,                           // 12
	FileDispositionInformation,                     // 13
	FilePositionInformation,                        // 14
	FileFullEaInformation,                          // 15
	FileModeInformation,                            // 16
	FileAlignmentInformation,                       // 17
	FileAllInformation,                             // 18
	FileAllocationInformation,                      // 19
	FileEndOfFileInformation,                       // 20
	FileAlternateNameInformation,                   // 21
	FileStreamInformation,                          // 22
	FilePipeInformation,                            // 23
	FilePipeLocalInformation,                       // 24
	FilePipeRemoteInformation,                      // 25
	FileMailslotQueryInformation,                   // 26
	FileMailslotSetInformation,                     // 27
	FileCompressionInformation,                     // 28
	FileObjectIdInformation,                        // 29
	FileCompletionInformation,                      // 30
	FileMoveClusterInformation,                     // 31
	FileQuotaInformation,                           // 32
	FileReparsePointInformation,                    // 33
	FileNetworkOpenInformation,                     // 34
	FileAttributeTagInformation,                    // 35
	FileTrackingInformation,                        // 36
	FileIdBothDirectoryInformation,                 // 37
	FileIdFullDirectoryInformation,                 // 38
	FileValidDataLengthInformation,                 // 39
	FileShortNameInformation,                       // 40
	FileIoCompletionNotificationInformation,        // 41
	FileIoStatusBlockRangeInformation,              // 42
	FileIoPriorityHintInformation,                  // 43
	FileSfioReserveInformation,                     // 44
	FileSfioVolumeInformation,                      // 45
	FileHardLinkInformation,                        // 46
	FileProcessIdsUsingFileInformation,             // 47
	FileNormalizedNameInformation,                  // 48
	FileNetworkPhysicalNameInformation,             // 49
	FileIdGlobalTxDirectoryInformation,             // 50
	FileIsRemoteDeviceInformation,                  // 51
	FileUnusedInformation,                          // 52
	FileNumaNodeInformation,                        // 53
	FileStandardLinkInformation,                    // 54
	FileRemoteProtocolInformation,                  // 55
	FileRenameInformationBypassAccessCheck,         // 56
	FileLinkInformationBypassAccessCheck,           // 57
	FileVolumeNameInformation,                      // 58
	FileIdInformation,                              // 59
	FileIdExtdDirectoryInformation,                 // 60
	FileReplaceCompletionInformation,               // 61
	FileHardLinkFullIdInformation,                  // 62
	FileIdExtdBothDirectoryInformation,             // 63
	FileDispositionInformationEx,                   // 64
	FileRenameInformationEx,                        // 65
	FileRenameInformationExBypassAccessCheck,       // 66
	FileDesiredStorageClassInformation,             // 67
	FileStatInformation,                            // 68
	FileMemoryPartitionInformation,                 // 69
	FileStatLxInformation,                          // 70
	FileCaseSensitiveInformation,                   // 71
	FileLinkInformationEx,                          // 72
	FileLinkInformationExBypassAccessCheck,         // 73
	FileStorageReserveIdInformation,                // 74
	FileCaseSensitiveInformationForceAccessCheck,   // 75
	FileKnownFolderInformation,                     // 76

	FileMaximumInformation
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef struct _FILE_BOTH_DIRECTORY_INFORMATION
{
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaInformationLength;
	UCHAR         AlternateNameLength;
	WCHAR         AlternateName[12];
	WCHAR         FileName[1];
} FILE_BOTH_DIR_INFORMATION, * PFILE_BOTH_DIR_INFORMATION;

typedef struct _FILE_DIRECTORY_INFORMATION
{
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	WCHAR         FileName[1];
} FILE_DIRECTORY_INFORMATION, * PFILE_DIRECTORY_INFORMATION;


typedef struct _FILE_FULL_DIR_INFORMATION
{
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	WCHAR         FileName[1];
} FILE_FULL_DIR_INFORMATION, * PFILE_FULL_DIR_INFORMATION;

typedef struct _FILE_ID_FULL_DIR_INFORMATION
{
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	LARGE_INTEGER FileId;
	WCHAR         FileName[1];
} FILE_ID_FULL_DIR_INFORMATION, * PFILE_ID_FULL_DIR_INFORMATION;

typedef struct _FILE_ID_BOTH_DIR_INFORMATION
{
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	CCHAR         ShortNameLength;
	WCHAR         ShortName[12];
	LARGE_INTEGER FileId;
	WCHAR         FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, * PFILE_ID_BOTH_DIR_INFORMATION;

typedef struct _FILE_ID_GLOBAL_TX_DIR_INFORMATION {
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	LARGE_INTEGER FileId;
	GUID          LockingTransactionId;
	ULONG         TxInfoFlags;
	WCHAR         FileName[1];
} FILE_ID_GLOBAL_TX_DIR_INFORMATION, * PFILE_ID_GLOBAL_TX_DIR_INFORMATION;

typedef struct _FILE_ID_EXTD_DIR_INFORMATION {
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	ULONG         ReparsePointTag;
	FILE_ID_128   FileId;
	WCHAR         FileName[1];
} FILE_ID_EXTD_DIR_INFORMATION, * PFILE_ID_EXTD_DIR_INFORMATION;

typedef struct _FILE_ID_EXTD_BOTH_DIR_INFORMATION {
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	ULONG         ReparsePointTag;
	FILE_ID_128   FileId;
	CCHAR         ShortNameLength;
	WCHAR         ShortName[12];
	WCHAR         FileName[1];
} FILE_ID_EXTD_BOTH_DIR_INFORMATION, * PFILE_ID_EXTD_BOTH_DIR_INFORMATION;

typedef struct _FILE_NAMES_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG FileIndex;
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_NAMES_INFORMATION, * PFILE_NAMES_INFORMATION;

typedef VOID(NTAPI* PIO_APC_ROUTINE)(
	IN PVOID ApcContext,
	IN PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG Reserved);


// Global variables
const WCHAR prefix[] = L"hook";
const WCHAR newPrefix[] = L"yess";

HKEY g_searchkey = NULL;
wchar_t g_pszPath[MAX_PATH] = { 0 };
HANDLE g_hPipe = NULL;
std::wstring g_strSearchDirectory = L"";
std::wstring g_strSearchWord = L"";

void SetGlobalDirectoryString(const std::wstring& newValue) {
	g_strSearchDirectory = newValue;
}
std::wstring GetGlobalDirectoryString() {
	return g_strSearchDirectory;
}
void SetGlobalSearchWord(const std::wstring& newValue) {
	g_strSearchWord = newValue;
}
std::wstring GetGlobalSearchWord() {
	return g_strSearchWord;
}

std::string WStringToString(const std::wstring& wstr)
{
	std::string str;
	size_t size;
	str.resize(wstr.length());
	wcstombs_s(&size, &str[0], str.size() + 1, wstr.c_str(), wstr.size());
	return str;
}

void notify(std::wstring value) {
	//OutputDebugStringA(__FUNCTION__);
	std::string stringvalue = WStringToString(value);
	OutputDebugStringA(stringvalue.c_str());
	if (g_hPipe != NULL)
	{
		WriteFile(g_hPipe, stringvalue.c_str(), stringvalue.length(), NULL, NULL);
	}
}

std::wstring extractLocation(const std::wstring& searchUri) {
	// Constants for search parameters
	const std::wstring locationParam = L"location:";

	// Find the start of the location parameter
	size_t locationStart = searchUri.find(locationParam);
	if (locationStart == std::wstring::npos) {
		throw std::runtime_error("Location parameter not found in the search URI");
	}

	// Extract the encoded location (everything after "location:")
	std::wstring encodedLocation = searchUri.substr(locationStart + locationParam.length());

	// Find the end of the location (next '&' or end of string)
	size_t locationEnd = encodedLocation.find(L'&');
	if (locationEnd != std::wstring::npos) {
		encodedLocation = encodedLocation.substr(0, locationEnd);
	}

	// URL decode the location
	std::wstring decodedLocation;
	decodedLocation.reserve(encodedLocation.length());  // Preallocate for efficiency

	for (size_t i = 0; i < encodedLocation.length(); ++i) {
		if (encodedLocation[i] == L'%' && i + 2 < encodedLocation.length()) {
			// Handle URL-encoded characters
			wchar_t hex[3] = { encodedLocation[i + 1], encodedLocation[i + 2], L'\0' };
			wchar_t ch = static_cast<wchar_t>(std::wcstol(hex, nullptr, 16));
			decodedLocation += ch;
			i += 2;
		}
		else if (encodedLocation[i] == L'+') {
			// Handle space ('+' in URL encoding represents a space)
			decodedLocation += L' ';
		}
		else {
			// Regular character
			decodedLocation += encodedLocation[i];
		}
	}

	return decodedLocation;
}

std::wstring extractCrumbValue(const std::wstring& input) {
	std::wstring crumbKey = L"System.Generic.String%3A";
	std::wstring delimiter = L"&crumb=location:";

	// Find the position of the "&crumb=" substring
	size_t startPos = input.find(crumbKey);
	if (startPos != std::wstring::npos) {
		// Move the start position to the end of "&crumb="
		startPos += crumbKey.length();

		// Find the position of the "String%3" substring
		size_t endPos = input.find(delimiter, startPos);
		if (endPos != std::wstring::npos) {
			// Extract the substring between startPos and endPos
			return input.substr(startPos, endPos - startPos);
		}
	}
	// Return an empty string if not found
	return L"";
}

std::wstring extractSearchLocation(const std::wstring& input) {
	// Constants for string matching
	const std::wstring PREFIX = L"search-ms";
	const std::wstring LOCATION_MARKER = L"crumb=&crumb=location:";

	// Check if input starts with "search-ms"
	if (input.length() < PREFIX.length() || input.substr(0, PREFIX.length()) != PREFIX) {
		return L""; // Return empty string if prefix doesn't match
	}

	// Find the location marker
	size_t locationStart = input.find(LOCATION_MARKER);
	if (locationStart == std::wstring::npos) {
		return L""; // Return empty string if location marker not found
	}

	// Extract the encoded path (everything after the location marker)
	std::wstring encodedPath = input.substr(locationStart + LOCATION_MARKER.length());

	// Decode the URL-encoded path
	std::wstring decodedPath;
	decodedPath.reserve(encodedPath.length()); // Reserve space for efficiency

	for (size_t i = 0; i < encodedPath.length(); ++i) {
		if (encodedPath[i] == L'%' && i + 2 < encodedPath.length()) {
			// Handle URL encoding (e.g., %3A -> :)
			wchar_t hex1 = encodedPath[i + 1];
			wchar_t hex2 = encodedPath[i + 2];

			// Convert hex characters to integer
			int value = 0;

			// Process first hex digit
			if (hex1 >= L'0' && hex1 <= L'9') value = (hex1 - L'0') << 4;
			else if (hex1 >= L'A' && hex1 <= L'F') value = (hex1 - L'A' + 10) << 4;
			else if (hex1 >= L'a' && hex1 <= L'f') value = (hex1 - L'a' + 10) << 4;

			// Process second hex digit
			if (hex2 >= L'0' && hex2 <= L'9') value |= (hex2 - L'0');
			else if (hex2 >= L'A' && hex2 <= L'F') value |= (hex2 - L'A' + 10);
			else if (hex2 >= L'a' && hex2 <= L'f') value |= (hex2 - L'a' + 10);

			decodedPath += static_cast<wchar_t>(value);
			i += 2; // Skip the next two characters
		}
		else {
			decodedPath += encodedPath[i];
		}
	}

	return decodedPath;
}

DWORD WINAPI CreatePipe(LPVOID lpParam)
{
	//create pipe
	g_hPipe = CreateNamedPipe(SEARCH_PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT,
		PIPE_UNLIMITED_INSTANCES, 0, 0, 0, NULL);
	if (g_hPipe == INVALID_HANDLE_VALUE) {
		//printf("Failed to create the keyboard named pipe.\n");
		return 0;
	}

	BOOL fConnected = false;
	while (!fConnected)
	{
		fConnected = ConnectNamedPipe(g_hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
		Sleep(1000);
	}
	OutputDebugStringA("Pipe is created");
}

std::string GetFullPathFromHandle(HANDLE hFile) {
	// Check if the handle is valid
	if (hFile == INVALID_HANDLE_VALUE) {
		return "Invalid handle";
	}

	// Buffer to hold the path
	char buffer[MAX_PATH];
	DWORD result = GetFinalPathNameByHandleA(hFile, buffer, sizeof(buffer), FILE_NAME_NORMALIZED);

	if (result == 0) {
		// Handle error
		return "Error getting path: " + std::to_string(GetLastError());
	}

	return std::string(buffer);
}

typedef HRESULT(WINAPI* SHGetIDListFromObject_t)(IUnknown* punk, PIDLIST_ABSOLUTE* ppidl);
SHGetIDListFromObject_t TrueSHGetIDListFromObject = nullptr;

HRESULT WINAPI HookSHGetIDListFromObject(IUnknown* punk, PIDLIST_ABSOLUTE* ppidl) {
	// Call the original function
	HRESULT result = TrueSHGetIDListFromObject(punk, ppidl);

	// Check if the function succeeded and log the PIDL if available
	if (SUCCEEDED(result) && ppidl && *ppidl) {
		CComHeapPtr<wchar_t> pSearch;
		CComHeapPtr<wchar_t> pPath;
		::SHGetNameFromIDList(*ppidl, SIGDN_PARENTRELATIVEFORADDRESSBAR, &pSearch);
		std::wstring input = static_cast<LPWSTR>(pSearch);
		std::wstring searchword = extractCrumbValue(input);
		SetGlobalSearchWord(searchword);
		if (searchword.length() > 0)
		{
			std::wstring searchpath = extractLocation(input);
			SetGlobalDirectoryString(searchpath);
			const std::wstring prefix = L"C:\\";
			if (searchpath.compare(0, prefix.length(), prefix) == 0)
			{
				//ppidl = NULL;
				//return E_UNEXPECTED;
				PIDLIST_ABSOLUTE newPidl = nullptr;
				HRESULT hr = SHParseDisplayName(L"C:\\", nullptr, &newPidl, 0, nullptr);
				*ppidl = newPidl;
			}
		}

		//check if this is search context. some keywords are not showed
		std::wstring specialsearchpath = extractSearchLocation(input);
		if (specialsearchpath.length() > 0)
		{
			notify(L"speical context &" + specialsearchpath);
			const std::wstring prefix = L"C:\\";
			if (specialsearchpath.compare(0, prefix.length(), prefix) == 0)
			{
				ppidl = NULL;
				return E_UNEXPECTED;
			}
		}
	}
	else {
		OutputDebugStringA("SHGetIDListFromObject failed or PIDL not obtained.\n");
	}

	return result;
}

std::wstring GetFilePathFromHandle(HANDLE fileHandle) {
	// Buffer to store the path
	const DWORD bufferSize = MAX_PATH;
	wchar_t buffer[bufferSize];

	// Retrieve the path
	DWORD result = GetFinalPathNameByHandleW(fileHandle, buffer, bufferSize, FILE_NAME_NORMALIZED);
	if (result == 0 || result > bufferSize) {
		OutputDebugStringA("error in getting path");
		return L"";
	}

	return std::wstring(buffer);
}


// check if the file is need to be hidden
BOOLEAN checkIfHiddenFile(WCHAR fileName[])
{

	SIZE_T				nBytesEqual;
	nBytesEqual = 0;
	nBytesEqual = RtlCompareMemory
	(
		(PVOID) & (fileName[0]),
		(PVOID) & (prefix[0]),
		PREFIX_SIZE
	);
	if (nBytesEqual == PREFIX_SIZE)
	{
		OutputDebugStringA("[checkIfHiddenFile]: known file detected : %S\n");
		OutputDebugStringW(fileName);

		// Change the prefix to "yess"
		for (int i = 0; i < wcslen(newPrefix); i++)
		{
			fileName[i] = newPrefix[i];
		}

		OutputDebugStringA("\n[checkIfHiddenFile]: prefix updated to : ");
		OutputDebugStringW(fileName);

		return(TRUE);
	}

	return FALSE;
}

PVOID getDirEntryFileName
(
	IN PVOID FileInformation,
	IN FILE_INFORMATION_CLASS FileInfoClass
)
{
	PVOID result = 0;
	switch (FileInfoClass) {
	case FILE_INFORMATION_CLASS::FileDirectoryInformation:
		result = (PVOID) & ((PFILE_DIRECTORY_INFORMATION)FileInformation)->FileName;
		break;
	case FILE_INFORMATION_CLASS::FileFullDirectoryInformation:
		result = (PVOID) & ((PFILE_FULL_DIR_INFORMATION)FileInformation)->FileName;
		break;
	case FILE_INFORMATION_CLASS::FileIdFullDirectoryInformation:
		result = (PVOID) & ((PFILE_ID_FULL_DIR_INFORMATION)FileInformation)->FileName;
		break;
	case FILE_INFORMATION_CLASS::FileBothDirectoryInformation:
		result = (PVOID) & ((PFILE_BOTH_DIR_INFORMATION)FileInformation)->FileName;
		break;
	case FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation:
		result = (PVOID) & ((PFILE_ID_BOTH_DIR_INFORMATION)FileInformation)->FileName;
		break;
	case FILE_INFORMATION_CLASS::FileNamesInformation:
		result = (PVOID) & ((PFILE_NAMES_INFORMATION)FileInformation)->FileName;
		break;
	}
	return result;
}

ULONG getNextEntryOffset
(
	IN PVOID FileInformation,
	IN FILE_INFORMATION_CLASS FileInfoClass
)
{
	ULONG result = 0;
	switch (FileInfoClass) {
	case FILE_INFORMATION_CLASS::FileDirectoryInformation:
		result = (ULONG)((PFILE_DIRECTORY_INFORMATION)FileInformation)->NextEntryOffset;
		break;
	case FILE_INFORMATION_CLASS::FileFullDirectoryInformation:
		result = (ULONG)((PFILE_FULL_DIR_INFORMATION)FileInformation)->NextEntryOffset;
		break;
	case FILE_INFORMATION_CLASS::FileIdFullDirectoryInformation:
		result = (ULONG)((PFILE_ID_FULL_DIR_INFORMATION)FileInformation)->NextEntryOffset;
		break;
	case FILE_INFORMATION_CLASS::FileBothDirectoryInformation:
		result = (ULONG)((PFILE_BOTH_DIR_INFORMATION)FileInformation)->NextEntryOffset;
		break;
	case FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation:
		result = (ULONG)((PFILE_ID_BOTH_DIR_INFORMATION)FileInformation)->NextEntryOffset;
		break;
	case FILE_INFORMATION_CLASS::FileNamesInformation:
		result = (ULONG)((PFILE_NAMES_INFORMATION)FileInformation)->NextEntryOffset;
		break;
	}
	return result;
}

void setNextEntryOffset
(
	IN PVOID FileInformation,
	IN FILE_INFORMATION_CLASS FileInfoClass,
	IN ULONG newValue
)
{
	switch (FileInfoClass) {
	case FILE_INFORMATION_CLASS::FileDirectoryInformation:
		((PFILE_DIRECTORY_INFORMATION)FileInformation)->NextEntryOffset = newValue;
		break;
	case FILE_INFORMATION_CLASS::FileFullDirectoryInformation:
		((PFILE_FULL_DIR_INFORMATION)FileInformation)->NextEntryOffset = newValue;
		break;
	case FILE_INFORMATION_CLASS::FileIdFullDirectoryInformation:
		((PFILE_ID_FULL_DIR_INFORMATION)FileInformation)->NextEntryOffset = newValue;
		break;
	case FILE_INFORMATION_CLASS::FileBothDirectoryInformation:
		((PFILE_BOTH_DIR_INFORMATION)FileInformation)->NextEntryOffset = newValue;
		break;
	case FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation:
		((PFILE_ID_BOTH_DIR_INFORMATION)FileInformation)->NextEntryOffset = newValue;
		break;
	case FILE_INFORMATION_CLASS::FileNamesInformation:
		((PFILE_NAMES_INFORMATION)FileInformation)->NextEntryOffset = newValue;
		break;
	}
}

BOOL CheckPermittedDrive(const std::wstring& directory) {

	std::vector<std::string> permittedDrives;

	std::ifstream configFile("C:\\SearchConfig\\config.json");
	if (!configFile.is_open()) {
		OutputDebugStringA("Error opening config.json");
		return FALSE;
	}
	nlohmann::json configJson;
	configFile >> configJson;
	configFile.close();

	// Extract permitted drives
	permittedDrives = configJson["PermittedDrives"].get<std::vector<std::string>>();
	// Extract drive letter from the directory path
	std::string directoryStr(directory.begin(), directory.end());
	//std::string driveLetter = directoryStr.substr(0, directoryStr.find(':'));
	return std::find(permittedDrives.begin(), permittedDrives.end(), directoryStr) != permittedDrives.end();
}

std::vector<RESULT_ITEM> items;
bool isRootDirectory(const std::string& path) {
	// Check if the path is in the format "X:\"
	return (path.size() == 3 && path[1] == ':' && path[2] == '\\');
}

bool isCommonDirectory(const std::string& path) {
	// Check if the path is a valid directory (not a root) and ends with a backslash
	return (path.size() > 3 && path[1] == ':' && path[2] == '\\' && path.back() == '\\');
}

BOOL AssignItems(const std::wstring& directory) {
	items.clear();
	std::ifstream resultFile("C:\\SearchConfig\\result.json");
	if (!resultFile.is_open()) {
		OutputDebugStringA("Error opening result.json");
		return FALSE;
	}
	nlohmann::json resultJson;
	resultFile >> resultJson;
	resultFile.close();

	std::string directoryStr(directory.begin(), directory.end());

	for (const auto& entry : resultJson["ResultSet"]) {
		std::string location = entry["Location"].get<std::string>();

		// Check if the location is under the given directory
		std::string searchterm;
		if (isRootDirectory(directoryStr))
			searchterm = directoryStr;
		else
			searchterm = directoryStr + "\\";
		if (location.find(searchterm) == 0) {
			RESULT_ITEM item;
			size_t pos = location.find_last_of('\\');
			std::string name = location.substr(pos + 1);
			std::wstring wideName = std::wstring(name.begin(), name.end());
			item.Name = wideName; // Assign as PCWSTR
			item.Type = (entry["Type"].get<std::string>() == "File") ? 0 : 1;

			items.push_back(item);
		}
	}

	return !items.empty();
}

std::wstring NormalizeFilePath(const std::wstring& filePath) {
	// Remove the "\\\\?\\" prefix if it exists
	if (filePath.rfind(L"\\\\?\\", 0) == 0) {
		return filePath.substr(4);
	}
	return filePath;
}

void AddEntries(PVOID startEntry) {
	const ULONG FixedSize = offsetof(FILE_ID_BOTH_DIR_INFORMATION, FileName);
	// Total size before alignment
	PFILE_ID_BOTH_DIR_INFORMATION tempEntry = (PFILE_ID_BOTH_DIR_INFORMATION)startEntry;

	((PFILE_ID_BOTH_DIR_INFORMATION)startEntry)->NextEntryOffset = ALIGN_UP_BY(FixedSize + ((PFILE_ID_BOTH_DIR_INFORMATION)startEntry)->FileNameLength, sizeof(LONGLONG));

	for (int i = 0; i < items.size(); i++) {
		PFILE_ID_BOTH_DIR_INFORMATION newEntry = (PFILE_ID_BOTH_DIR_INFORMATION)((BYTE*)tempEntry + tempEntry->NextEntryOffset);

		if (newEntry != nullptr) {
			// Fill in the new entry's data
			newEntry->FileNameLength = (wcslen(items.at(i).Name.c_str())) * sizeof(wchar_t);
			wcscpy_s(newEntry->FileName, items.at(i).Name.length() + 1, items.at(i).Name.c_str()); // Copy string
			if (i != items.size() - 1) newEntry->NextEntryOffset = ALIGN_UP_BY(FixedSize + newEntry->FileNameLength, sizeof(LONGLONG)); // This will be the last entry
			if (i == items.size() - 1) newEntry->NextEntryOffset = NO_MORE_ENTRIES;
			if (items.at(i).Type == 1) newEntry->FileAttributes = FILE_ATTRIBUTE_DIRECTORY; // Set desired attributes
			if (items.at(i).Type == 0) newEntry->FileAttributes = FILE_ATTRIBUTE_NORMAL; // Set desired attributes

			//newEntry->FileIndex = ((PFILE_ID_BOTH_DIR_INFORMATION)startEntry)->FileIndex; // Set file index appropriately
			//newEntry->CreationTime.QuadPart = ((PFILE_ID_BOTH_DIR_INFORMATION)startEntry)->CreationTime.QuadPart; // Set creation time if needed
			//newEntry->LastAccessTime.QuadPart = ((PFILE_ID_BOTH_DIR_INFORMATION)startEntry)->LastAccessTime.QuadPart; // Set last access time if needed
			//newEntry->LastWriteTime.QuadPart = ((PFILE_ID_BOTH_DIR_INFORMATION)startEntry)->LastWriteTime.QuadPart; // Set last write time if needed
			//newEntry->ChangeTime.QuadPart = ((PFILE_ID_BOTH_DIR_INFORMATION)startEntry)->ChangeTime.QuadPart; // Set change time if needed
			//newEntry->EndOfFile.QuadPart = ((PFILE_ID_BOTH_DIR_INFORMATION)startEntry)->EndOfFile.QuadPart; // Set end of file size if needed
			//newEntry->AllocationSize.QuadPart = ((PFILE_ID_BOTH_DIR_INFORMATION)startEntry)->AllocationSize.QuadPart; // Set allocation size if needed
			//newEntry->FileId.QuadPart = ((PFILE_ID_BOTH_DIR_INFORMATION)startEntry)->FileId.QuadPart; // Set file ID if needed
			//newEntry->EaSize = ((PFILE_ID_BOTH_DIR_INFORMATION)startEntry)->EaSize; // Set file ID if needed

			newEntry->ShortNameLength = 0;

		}
		tempEntry = newEntry;
		//free(newEntry); // Don't forget to free allocated memory
	}
};

// Check if the path starts with "UNC\"
bool IsUNCPath(const std::wstring& path) {
	return path.find(L"UNC") == 0;
}

std::wstring GetMappedDrive(const std::wstring& uncPath) {
	WCHAR localName[3] = L"A:";  // Start with A:
	WCHAR remoteName[MAX_PATH];
	DWORD bufferSize = MAX_PATH;
	// Ensure the UNC path is formatted correctly
	std::wstring formattedUNC = uncPath;
	if (formattedUNC.find(L"UNC") == 0) {
		formattedUNC = L"\\" + formattedUNC.substr(3);
	}
	// Iterate through possible drive letters (A: to Z:)
	for (char drive = 'A'; drive <= 'Z'; ++drive) {
		localName[0] = drive;  // Update the drive letter
		// Get the remote name for the current drive letter
		if (WNetGetConnectionW(localName, remoteName, &bufferSize) == NO_ERROR) {
			// Compare the UNC path with the remote name

			if (formattedUNC == remoteName) {
				return std::wstring(localName);
			}
		}
	}
	return L"No Mapped Drive";
}

std::wstring GetLocalDriveFromUNC(const std::wstring& uncPath) {

	for (wchar_t drive = L'A'; drive <= L'Z'; ++drive) {
		// Create the local drive letter (e.g., "M:")
		std::wstring localDrive = std::wstring(1, drive) + L":";

		DWORD bufferSize = 0;

		// First call to determine the required buffer size
		DWORD result = WNetGetUniversalNameW(
			localDrive.c_str(),
			UNIVERSAL_NAME_INFO_LEVEL,
			NULL,
			&bufferSize
		);

		if (result == ERROR_MORE_DATA) {
			// Allocate buffer for UNIVERSAL_NAME_INFO
			auto buffer = new BYTE[bufferSize];

			// Second call to retrieve the UNC path
			result = WNetGetUniversalNameW(
				localDrive.c_str(),
				UNIVERSAL_NAME_INFO_LEVEL,
				buffer,
				&bufferSize
			);

			if (result == NO_ERROR) {
				// Extract the UNC path
				UNIVERSAL_NAME_INFOW* info = (UNIVERSAL_NAME_INFOW*)buffer;

				// Compare with the target UNC path
				if (_wcsicmp(info->lpUniversalName, uncPath.c_str()) == 0) {
					// Match found
					delete[] buffer;
					return localDrive.substr(0, 2); // Return the drive letter (e.g., "M:")
				}
			}

			// Clean up the buffer
			delete[] buffer;
		}
	}

	// If no match is found
	return L"";
}


// Function pointer for the original NtQueryDirectoryFile
typedef NTSTATUS(WINAPI* NtQueryDirectoryFile_t)(
	HANDLE FileHandle,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation,
	ULONG Length,
	FILE_INFORMATION_CLASS FileInformationClass,
	BOOLEAN ReturnSingleEntry,
	PUNICODE_STRING FileName,
	BOOLEAN RestartScan
	);

NtQueryDirectoryFile_t Real_NtQueryDirectoryFile = nullptr;

NTSTATUS WINAPI Hooked_NtQueryDirectoryFile(
	HANDLE FileHandle,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation,
	ULONG Length,
	FILE_INFORMATION_CLASS FileInformationClass,
	BOOLEAN ReturnSingleEntry,
	PUNICODE_STRING FileName,
	BOOLEAN RestartScan
) {
	PVOID	currFile;
	PVOID	prevFile;

	// Call the original function
	NTSTATUS status = Real_NtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);

	if (NT_SUCCESS(status) && FileInformationClass == FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation) {
		// Query the file path associated with the FileHandle
		std::wstring filePath = GetFilePathFromHandle(FileHandle);
		std::wstring normalizedPath0 = NormalizeFilePath(filePath);
		std::wstring normalizedPath = normalizedPath0;
		if (IsUNCPath(normalizedPath0)) {
			normalizedPath0.pop_back();
			std::wstring formattedUNC = normalizedPath0;
			if (formattedUNC.find(L"UNC") == 0) {
				formattedUNC = L"\\" + formattedUNC.substr(3);
			}
			//OutputDebugStringW(formattedUNC.c_str());
			normalizedPath = GetLocalDriveFromUNC(formattedUNC) + L"\\";
		}
		//OutputDebugStringW((L"First normalized path : " + normalizedPath0).c_str());
		//OutputDebugStringW((L"Second normalized path : " + normalizedPath).c_str());
		if (normalizedPath == GetGlobalDirectoryString() && normalizedPath != L"") {
			if (CheckPermittedDrive(normalizedPath)) {
				currFile = FileInformation;
				prevFile = NULL;
				if (AssignItems(normalizedPath)) {
					AddEntries(currFile);
				}
			}
		}
		else SetGlobalDirectoryString(L"");
	}

	return status;
}


#endif