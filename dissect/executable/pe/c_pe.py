from dissect.cstruct import cstruct

c_pe_def = """
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_SIZEOF_SHORT_NAME          8

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

// --- PE HEADERS ---

typedef struct IMAGE_DOS_HEADER {
     WORD e_magic;
     WORD e_cblp;
     WORD e_cp;
     WORD e_crlc;
     WORD e_cparhdr;
     WORD e_minalloc;
     WORD e_maxalloc;
     WORD e_ss;
     WORD e_sp;
     WORD e_csum;
     WORD e_ip;
     WORD e_cs;
     WORD e_lfarlc;
     WORD e_ovno;
     WORD e_res[4];
     WORD e_oemid;
     WORD e_oeminfo;
     WORD e_res2[10];
     LONG e_lfanew;
};

typedef enum MachineType : WORD {
    IMAGE_FILE_MACHINE_UNKNOWN = 0x0,
    IMAGE_FILE_MACHINE_AM33 = 0x1d3,
    IMAGE_FILE_MACHINE_AMD64 = 0x8664,
    IMAGE_FILE_MACHINE_ARM = 0x1c0,
    IMAGE_FILE_MACHINE_ARM64 = 0xaa64,
    IMAGE_FILE_MACHINE_ARMNT = 0x1c4,
    IMAGE_FILE_MACHINE_EBC = 0xebc,
    IMAGE_FILE_MACHINE_I386 = 0x14c,
    IMAGE_FILE_MACHINE_IA64 = 0x200,
    IMAGE_FILE_MACHINE_M32R = 0x9041,
    IMAGE_FILE_MACHINE_MIPS16 = 0x266,
    IMAGE_FILE_MACHINE_MIPSFPU = 0x366,
    IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466,
    IMAGE_FILE_MACHINE_POWERPC = 0x1f0,
    IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1,
    IMAGE_FILE_MACHINE_R4000 = 0x166,
    IMAGE_FILE_MACHINE_RISCV32 = 0x5032,
    IMAGE_FILE_MACHINE_RISCV64 = 0x5064,
    IMAGE_FILE_MACHINE_RISCV128 = 0x5128,
    IMAGE_FILE_MACHINE_SH3 = 0x1a2,
    IMAGE_FILE_MACHINE_SH3DSP = 0x1a3,
    IMAGE_FILE_MACHINE_SH4 = 0x1a6,
    IMAGE_FILE_MACHINE_SH5 = 0x1a8,
    IMAGE_FILE_MACHINE_THUMB = 0x1c2,
    IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169,
};

flag ImageCharacteristics : WORD {
    IMAGE_FILE_RELOCS_STRIPPED = 0x0001,
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002,
    IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004,
    IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008,
    IMAGE_FILE_AGGRESSIVE_WS_TRIM = 0x0010,
    IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020,
    Reserved = 0x0040,
    IMAGE_FILE_BYTES_REVERSED_LO = 0x0080,
    IMAGE_FILE_32BIT_MACHINE = 0x0100,
    IMAGE_FILE_DEBUG_STRIPPED = 0x0200,
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400,
    IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800,
    IMAGE_FILE_SYSTEM = 0x1000,
    IMAGE_FILE_DLL = 0x2000,
    IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000,
    IMAGE_FILE_BYTES_REVERSED_HI = 0x8000,
};

typedef struct IMAGE_FILE_HEADER {
  MachineType           Machine;
  WORD                  NumberOfSections;
  DWORD                 TimeDateStamp;
  DWORD                 PointerToSymbolTable;
  DWORD                 NumberOfSymbols;
  WORD                  SizeOfOptionalHeader;
  ImageCharacteristics  Characteristics;
};

typedef struct IMAGE_DATA_DIRECTORY {
    ULONG   VirtualAddress;
    ULONG   Size;
};

typedef enum WindowsSubsystem : WORD {
    IMAGE_SUBSYSTEM_UNKNOWN = 0,
    IMAGE_SUBSYSTEM_NATIVE = 1,
    IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
    IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
    IMAGE_SUBSYSTEM_OS2_CUI = 5,
    IMAGE_SUBSYSTEM_POSIX_CUI = 7,
    IMAGE_SUBSYSTEM_NATIVE_WINDOWS = 8,
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
    IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
    IMAGE_SUBSYSTEM_EFI_ROM = 13,
    IMAGE_SUBSYSTEM_XBOX = 14,
    IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16,
};

typedef enum DLLCharacteristics : WORD {
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020,
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040,
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100,
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
    IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
    IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000,
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
    IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000,
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000,
};

typedef struct IMAGE_OPTIONAL_HEADER {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  DWORD                BaseOfData;
  DWORD                ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WindowsSubsystem     Subsystem;
  DLLCharacteristics   DllCharacteristics;
  DWORD                SizeOfStackReserve;
  DWORD                SizeOfStackCommit;
  DWORD                SizeOfHeapReserve;
  DWORD                SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

typedef struct IMAGE_OPTIONAL_HEADER64 {
 WORD        Magic;
 BYTE        MajorLinkerVersion;
 BYTE        MinorLinkerVersion;
 DWORD       SizeOfCode;
 DWORD       SizeOfInitializedData;
 DWORD       SizeOfUninitializedData;
 DWORD       AddressOfEntryPoint;
 DWORD       BaseOfCode;
 ULONGLONG   ImageBase;
 DWORD       SectionAlignment;
 DWORD       FileAlignment;
 WORD        MajorOperatingSystemVersion;
 WORD        MinorOperatingSystemVersion;
 WORD        MajorImageVersion;
 WORD        MinorImageVersion;
 WORD        MajorSubsystemVersion;
 WORD        MinorSubsystemVersion;
 DWORD       Win32VersionValue;
 DWORD       SizeOfImage;
 DWORD       SizeOfHeaders;
 DWORD       CheckSum;
 WORD        Subsystem;
 WORD        DllCharacteristics;
 ULONGLONG   SizeOfStackReserve;
 ULONGLONG   SizeOfStackCommit;
 ULONGLONG   SizeOfHeapReserve;
 ULONGLONG   SizeOfHeapCommit;
 DWORD       LoaderFlags;
 DWORD       NumberOfRvaAndSizes;
 IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

typedef struct IMAGE_NT_HEADERS {
  DWORD                 Signature;
  IMAGE_FILE_HEADER     FileHeader;
  IMAGE_OPTIONAL_HEADER OptionalHeader;
};

typedef struct IMAGE_NT_HEADERS64 {
  DWORD                     Signature;
  IMAGE_FILE_HEADER         FileHeader;
  IMAGE_OPTIONAL_HEADER64   OptionalHeader;
};

flag SectionFlags : DWORD {
    IMAGE_SCN_TYPE_NO_PAD = 0x00000008,
    IMAGE_SCN_CNT_CODE = 0x00000020,
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080,
    IMAGE_SCN_LNK_OTHER = 0x00000100,
    IMAGE_SCN_LNK_INFO = 0x00000200,
    IMAGE_SCN_LNK_REMOVE = 0x00000800,
    IMAGE_SCN_LNK_COMDAT = 0x00001000,
    IMAGE_SCN_NO_DEFER_SPEC_EXC = 0x00004000,
    IMAGE_SCN_GPREL = 0x00008000,
    IMAGE_SCN_MEM_FARDATA = 0x00008000,
    IMAGE_SCN_MEM_PURGEABLE = 0x00020000,
    IMAGE_SCN_MEM_16BIT = 0x00020000,
    IMAGE_SCN_MEM_LOCKED = 0x00040000,
    IMAGE_SCN_MEM_PRELOAD = 0x00080000,
    IMAGE_SCN_ALIGN_1BYTES = 0x00100000,
    IMAGE_SCN_ALIGN_2BYTES = 0x00200000,
    IMAGE_SCN_ALIGN_4BYTES = 0x00300000,
    IMAGE_SCN_ALIGN_8BYTES = 0x00400000,
    IMAGE_SCN_ALIGN_16BYTES = 0x00500000,
    IMAGE_SCN_ALIGN_32BYTES = 0x00600000,
    IMAGE_SCN_ALIGN_64BYTES = 0x00700000,
    IMAGE_SCN_ALIGN_128BYTES = 0x00800000,
    IMAGE_SCN_ALIGN_256BYTES = 0x00900000,
    IMAGE_SCN_ALIGN_512BYTES = 0x00A00000,
    IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000,
    IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000,
    IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000,
    IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000,
    IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000,
    IMAGE_SCN_MEM_DISCARDABLE = 0x02000000,
    IMAGE_SCN_MEM_NOT_CACHED = 0x04000000,
    IMAGE_SCN_MEM_NOT_PAGED = 0x08000000,
    IMAGE_SCN_MEM_SHARED = 0x10000000,
    IMAGE_SCN_MEM_EXECUTE = 0x20000000,
    IMAGE_SCN_MEM_READ = 0x40000000,
    IMAGE_SCN_MEM_WRITE = 0x80000000
};

typedef struct IMAGE_SECTION_HEADER {
    char            Name[IMAGE_SIZEOF_SHORT_NAME];
    ULONG           VirtualSize;
    ULONG           VirtualAddress;
    ULONG           SizeOfRawData;
    ULONG           PointerToRawData;
    ULONG           PointerToRelocations;
    ULONG           PointerToLinenumbers;
    USHORT          NumberOfRelocations;
    USHORT          NumberOfLinenumbers;
    SectionFlags    Characteristics;
};

// --- END OF PE HEADERS

// --- EXPORTS

typedef struct IMAGE_EXPORT_DIRECTORY {
    ULONG   Characteristics;
    ULONG   TimeDateStamp;
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    ULONG   Name;
    ULONG   Base;
    ULONG   NumberOfFunctions;
    ULONG   NumberOfNames;
    ULONG   AddressOfFunctions;     // RVA from base of image
    ULONG   AddressOfNames;         // RVA from base of image
    ULONG   AddressOfNameOrdinals;  // RVA from base of image
};

// --- END OF EXPORTS

// --- IMPORTS

typedef struct IMAGE_IMPORT_DESCRIPTOR {
    DWORD   OriginalFirstThunk;
    DWORD   TimeDateStamp;
    DWORD   ForwarderChain;
    DWORD   Name;
    DWORD   FirstThunk;
};

typedef struct IMAGE_IMPORT_BY_NAME {
    uint16 Hint;
    // char Name;
};

typedef struct IMAGE_THUNK_DATA32 {
    union {
        DWORD ForwarderString;
        DWORD Function;
        DWORD Ordinal;
        DWORD AddressOfData;
    } u1;
};

typedef struct IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG ForwarderString;
        ULONGLONG Function;
        ULONGLONG Ordinal;
        ULONGLONG AddressOfData;
    } u1;
}

// --- END OF IMPORTS

// --- RESOURCE DIRECTORY

enum ResourceID : WORD {
    Cursor = 0x1,
    Bitmap = 0x2,
    Icon = 0x3,
    Menu = 0x4,
    Dialog = 0x5,
    String = 0x6,
    FontDirectory = 0x7,
    Font = 0x8,
    Accelerator = 0x9,
    RcData = 0xA,
    MessageTable = 0xB,
    Version = 0x10,
    DlgInclude = 0x11,
    PlugAndPlay = 0x13,
    VXD = 0x14,
    AnimatedCursor = 0x15,
    AnimatedIcon = 0x16,
    HTML = 0x17,
    Manifest = 0x18,
};

struct IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union {
        struct {
            DWORD NameOffset:31;
            DWORD NameIsString:1;
        };
        DWORD   Name;
        WORD    Id;
    };
    union {
        DWORD   OffsetToData;
        struct {
            DWORD   OffsetToDirectory:31;
            DWORD   DataIsDirectory:1;
        };
    };
}

struct IMAGE_RESOURCE_DIRECTORY {
    uint32 Characteristics;
    uint32 TimeDateStamp;
    ushort MajorVersion;
    ushort MinorVersion;
    ushort NumberOfNamedEntries;
    ushort NumberOfIdEntries;
};

/*
struct IMAGE_RESOURCE_DIRECTORY_ENTRY {
    uint32 Name;
    uint32 OffsetToDirectory:31;
    uint32 DataIsDirectory:1;
};
*/

typedef struct IMAGE_RESOURCE_DATA_ENTRY {
    uint32   OffsetToData;
    uint32   Size;
    uint32   CodePage;
    uint32   Reserved;
};

// --- END OF RESOURCE DIRECTORY

// --- DEBUG DIRECTORY

typedef struct IMAGE_DEBUG_DIRECTORY {
  DWORD Characteristics;
  DWORD TimeDateStamp;
  WORD  MajorVersion;
  WORD  MinorVersion;
  DWORD Type;
  DWORD SizeOfData;
  DWORD AddressOfRawData;
  DWORD PointerToRawData;
};

// --- END OF DEBUG DIRECTORY

// --- RELOCATION DIRECTORY

typedef struct _IMAGE_BASE_RELOCATION {
    DWORD   VirtualAddress;
    DWORD   SizeOfBlock;
//  WORD    TypeOffset[1];
} IMAGE_BASE_RELOCATION;

// --- END OF RELOCATION DIRECTORY

// --- TLS DIRECTORY

typedef struct _IMAGE_TLS_DIRECTORY32 {
    DWORD  StartAddressOfRawData;
    DWORD  EndAddressOfRawData;
    DWORD  AddressOfIndex;             // PDWORD
    DWORD  AddressOfCallBacks;         // PIMAGE_TLS_CALLBACK *
    DWORD  SizeOfZeroFill;
    DWORD  Characteristics;
} IMAGE_TLS_DIRECTORY32;

typedef struct _IMAGE_TLS_DIRECTORY64 {
    ULONGLONG   StartAddressOfRawData;
    ULONGLONG   EndAddressOfRawData;
    ULONGLONG   AddressOfIndex;
    ULONGLONG   AddressOfCallBacks;
    DWORD       SizeOfZeroFill;
    DWORD       Characteristics;
} IMAGE_TLS_DIRECTORY64;

// --- END OF TLS DIRECTORY
"""

c_pe = cstruct().load(c_pe_def)

c_cv_info_def = """
struct GUID {
    DWORD Data1;
    WORD Data2;
    WORD Data3;
    char Data4[8];
};

struct CV_INFO_PDB70 {
    DWORD      CvSignature;
    GUID       Signature;       // unique identifier
    DWORD      Age;             // an always-incrementing value
    char       PdbFileName[];   // zero terminated string with the name of the PDB file
};
"""

c_cv_info = cstruct().load(c_cv_info_def)
