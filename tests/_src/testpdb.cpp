/*
* This CPP file is used to generate the .pdb files that are used to test dissect.executable.pdb.
* The following build command can be used in the Visual Studio settings to compile and generate the .pdb file:
* 
* For 64-bit:
* /OUT:"<OUTPUT_DIR>\testpdb_x64.exe" /MANIFEST /NXCOMPAT /PDB:"<OUTPUT_DIR>\testpdb_x64.pdb" /DYNAMICBASE "kernel32.lib" "user32.lib" "gdi32.lib" "winspool.lib" "comdlg32.lib" "advapi32.lib" "shell32.lib" "ole32.lib" "oleaut32.lib" "uuid.lib" "odbc32.lib" "odbccp32.lib" /DEBUG /MACHINE:X64 /INCREMENTAL /SUBSYSTEM:CONSOLE /ERRORREPORT:PROMPT /NOLOGO /TLBID:1 
* 
* For 32-bit:
* /OUT:"<OUTPUT_DIR>\testpdb_x86.exe" /MANIFEST /NXCOMPAT /PDB:"<OUTPUT_DIR>\testpdb_x86.pdb" /DYNAMICBASE "kernel32.lib" "user32.lib" "gdi32.lib" "winspool.lib" "comdlg32.lib" "advapi32.lib" "shell32.lib" "ole32.lib" "oleaut32.lib" "uuid.lib" "odbc32.lib" "odbccp32.lib" /DEBUG /MACHINE:X86 /INCREMENTAL /SUBSYSTEM:CONSOLE /ERRORREPORT:PROMPT /NOLOGO /TLBID:1 
*/

#include <iostream>
#include <Windows.h>


typedef unsigned __int64 QWORD, * PQWORD;


typedef struct _UNICODE_STRING {
    USHORT  Length;
    USHORT  MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;


// --------------------------------------------------------------------------
// Simple structs
struct simple_datatypes_struct {
    char datatype_char;
    byte datatype_byte;
    short int datatype_short;
    int datatype_int;
    unsigned int datatype_unsigned_int;
    float datatype_float;
    double datatype_double;
    long int datatype_long;
    long long int datatype_longlong;
    unsigned long int datatype_unsigned_long;
    unsigned long long int datatype_unsigned_longlong;
    signed char datatype_signed_char;
    unsigned char datatype_unsigned_char;
    long double datatype_long_double;
    wchar_t datatype_wchar_t;
    char16_t datatype_char16_t;
    char32_t datatype_char32_t;
} simple_datatypes_struct;

struct windows_datatypes_struct {
    ATOM datatype_ATOM;
    BOOL datatype_BOOL;
    BOOLEAN datatype_BOOLEAN;
    BYTE datatype_BYTE;
    CCHAR datatype_CCHAR;
    CHAR datatype_CHAR;
    COLORREF datatype_COLORREF;
    DWORD datatype_DWORD;
    DWORDLONG datatype_DWORDLONG;
    DWORD_PTR datatype_DWORD_PTR;
    DWORD32 datatype_DWORD32;
    DWORD64 datatype_DWORD64;
    FLOAT datatype_FLOAT;
    HACCEL datatype_HACCEL;
    HALF_PTR datatype_HALF_PTR;
    HANDLE datatype_HANDLE;
    HBITMAP datatype_HBITMAP;
    HBRUSH datatype_HBRUSH;
    HCOLORSPACE datatype_HCOLORSPACE;
    HCONV datatype_HCONV;
    HCONVLIST datatype_HCONVLIST;
    HCURSOR datatype_HCURSOR;
    HDC datatype_HDC;
    HDDEDATA datatype_HDDEDATA;
    HDESK datatype_HDESK;
    HDROP datatype_HDROP;
    HDWP datatype_HDWP;
    HENHMETAFILE datatype_HENHMETAFILE;
    HFILE datatype_HFILE;
    HFONT datatype_HFONT;
    HGDIOBJ datatype_HGDIOBJ;
    HGLOBAL datatype_HGLOBAL;
    HHOOK datatype_HHOOK;
    HICON datatype_HICON;
    HINSTANCE datatype_HINSTANCE;
    HKEY datatype_HKEY;
    HKL datatype_HKL;
    HLOCAL datatype_HLOCAL;
    HMENU datatype_HMENU;
    HMETAFILE datatype_HMETAFILE;
    HMODULE datatype_HMODULE;
    HMONITOR datatype_HMONITOR;
    HPALETTE datatype_HPALETTE;
    HPEN datatype_HPEN;
    HRESULT datatype_HRESULT;
    HRGN datatype_HRGN;
    HRSRC datatype_HRSRC;
    HSZ datatype_HSZ;
    HWINSTA datatype_HWINSTA;
    HWND datatype_HWND;
    INT datatype_INT;
    INT_PTR datatype_INT_PTR;
    INT8 datatype_INT8;
    INT16 datatype_INT16;
    INT32 datatype_INT32;
    INT64 datatype_INT64;
    LANGID datatype_LANGID;
    LCID datatype_LCID;
    LCTYPE datatype_LCTYPE;
    LGRPID datatype_LGRPID;
    LONG datatype_LONG;
    LONGLONG datatype_LONGLONG;
    LONG_PTR datatype_LONG_PTR;
    LONG32 datatype_LONG32;
    LONG64 datatype_LONG64;
    LPARAM datatype_LPARAM;
    LPBOOL datatype_LPBOOL;
    LPBYTE datatype_LPBYTE;
    LPCOLORREF datatype_LPCOLORREF;
    LPCSTR datatype_LPCSTR;
    LPCTSTR datatype_LPCTSTR;
    LPCVOID datatype_LPCVOID;
    LPCWSTR datatype_LPCWSTR;
    LPDWORD datatype_LPDWORD;
    LPHANDLE datatype_LPHANDLE;
    LPINT datatype_LPINT;
    LPLONG datatype_LPLONG;
    LPSTR datatype_LPSTR;
    LPTSTR datatype_LPTSTR;
    LPVOID datatype_LPVOID;
    LPWORD datatype_LPWORD;
    LPWSTR datatype_LPWSTR;
    LRESULT datatype_LRESULT;
    PBOOL datatype_PBOOL;
    PBOOLEAN datatype_PBOOLEAN;
    PBYTE datatype_PBYTE;
    PCHAR datatype_PCHAR;
    PCSTR datatype_PCSTR;
    PCTSTR datatype_PCTSTR;
    PCWSTR datatype_PCWSTR;
    PDWORD datatype_PDWORD;
    PDWORDLONG datatype_PDWORDLONG;
    PDWORD_PTR datatype_PDWORD_PTR;
    PDWORD32 datatype_PDWORD32;
    PDWORD64 datatype_PDWORD64;
    PFLOAT datatype_PFLOAT;
    PHALF_PTR datatype_PHALF_PTR;
    PHANDLE datatype_PHANDLE;
    PHKEY datatype_PHKEY;
    PINT datatype_PINT;
    PINT_PTR datatype_PINT_PTR;
    PINT8 datatype_PINT8;
    PINT16 datatype_PINT16;
    PINT32 datatype_PINT32;
    PINT64 datatype_PINT64;
    PLCID datatype_PLCID;
    PLONG datatype_PLONG;
    PLONGLONG datatype_PLONGLONG;
    PLONG_PTR datatype_PLONG_PTR;
    PLONG32 datatype_PLONG32;
    PLONG64 datatype_PLONG64;
    PSHORT datatype_PSHORT;
    PSIZE_T datatype_PSIZE_T;
    PSSIZE_T datatype_PSSIZE_T;
    PSTR datatype_PSTR;
    PTBYTE datatype_PTBYTE;
    PTCHAR datatype_PTCHAR;
    PTSTR datatype_PTSTR;
    PUCHAR datatype_PUCHAR;
    PUHALF_PTR datatype_PUHALF_PTR;
    PUINT datatype_PUINT;
    PUINT_PTR datatype_PUINT_PTR;
    PUINT8 datatype_PUINT8;
    PUINT16 datatype_PUINT16;
    PUINT32 datatype_PUINT32;
    PUINT64 datatype_PUINT64;
    PULONG datatype_PULONG;
    PULONGLONG datatype_PULONGLONG;
    PULONG_PTR datatype_PULONG_PTR;
    PULONG32 datatype_PULONG32;
    PULONG64 datatype_PULONG64;
    PUSHORT datatype_PUSHORT;
    PVOID datatype_PVOID;
    PWCHAR datatype_PWCHAR;
    PWORD datatype_PWORD;
    PWSTR datatype_PWSTR;
    QWORD datatype_QWORD;
    SC_HANDLE datatype_SC_HANDLE;
    SC_LOCK datatype_SC_LOCK;
    SERVICE_STATUS_HANDLE datatype_SERVICE_STATUS_HANDLE;
    SHORT datatype_SHORT;
    SIZE_T datatype_SIZE_T;
    SSIZE_T datatype_SSIZE_T;
    TBYTE datatype_TBYTE;
    TCHAR datatype_TCHAR;
    UCHAR datatype_UCHAR;
    UHALF_PTR datatype_UHALF_PTR;
    UINT datatype_UINT;
    UINT_PTR datatype_UINT_PTR;
    UINT8 datatype_UINT8;
    UINT16 datatype_UINT16;
    UINT32 datatype_UINT32;
    UINT64 datatype_UINT64;
    ULONG datatype_ULONG;
    ULONGLONG datatype_ULONGLONG;
    ULONG_PTR datatype_ULONG_PTR;
    ULONG32 datatype_ULONG32;
    ULONG64 datatype_ULONG64;
    UNICODE_STRING datatype_UNICODE_STRING;
    USHORT datatype_USHORT;
    USN datatype_USN;
    VOID *datatype_VOID;
    WCHAR datatype_WCHAR;
    WORD datatype_WORD;
    WPARAM datatype_WPARAM;
    std::nullptr_t datatype_nullptr_t;
    __wchar_t datatype___wchar_t;
    __int8 datatype___int8;
    __int16 datatype___int16;
    __int32 datatype___int32;
    __int64 datatype___int64;
} windows_datatypes_struct;
// --------------------------------------------------------------------------

// --------------------------------------------------------------------------
// Simple enum definitions
typedef enum _enum_uint16_t : uint16_t {
    a = 0x0,
    b = 0xFF,
} enum_uint16_t;

typedef enum _enum_int : int {
    c = 0x0,
    d = 0xFFFF,
} enum_int;

typedef enum _enum_int64 : int64_t {
    e = 0x0,
    f = 0xFFFFFFFF,
} enum_int64;
// --------------------------------------------------------------------------

// --------------------------------------------------------------------------
// Combined types
// Structure definitions containing an enum

struct _enum_structure {
    char datatype_char;
    enum_uint16_t datatype_enum_uint16_t;
    enum_int datatype_enum_int;
    enum_int64 datatype_enum_int64_t;
    HRESULT datatype_HRESULT;
} enum_structure;

// Structure containing a struct
struct _struct_structure {
    char datatype_char;
    _enum_structure datatype_enumstruct;
    UNICODE_STRING datatype_unicodestring;
    __int64 datatype_int64;
} struct_structure;

// Structure containing an enum and a struct
struct _enum_and_struct_structure {
    char datatype_char;
    _enum_structure datatype_enum_struct;
    _struct_structure datatype_struct_struct;
    LONGLONG datatype_LONGLONG;
} enum_and_struct_struct;
// --------------------------------------------------------------------------


int main()
{
    std::cout << "kusjesvanSRT<3\n";
}
