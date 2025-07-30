# References:
# - ntimage.h
# - winnt.h
from __future__ import annotations

from dissect.cstruct import cstruct

c_pe_def = """
typedef BYTE BOOLEAN;

//
// Image Format
//

#define IMAGE_DOS_SIGNATURE                     0x5A4D      // MZ
#define IMAGE_OS2_SIGNATURE                     0x454E      // NE
#define IMAGE_OS2_SIGNATURE_LE                  0x454C      // LE
#define IMAGE_VXD_SIGNATURE                     0x454C      // LE
#define IMAGE_NT_SIGNATURE                      0x00004550  // PE00

typedef struct _IMAGE_DOS_HEADER {              // DOS .EXE header
    USHORT      e_magic;                        // Magic number
    USHORT      e_cblp;                         // Bytes on last page of file
    USHORT      e_cp;                           // Pages in file
    USHORT      e_crlc;                         // Relocations
    USHORT      e_cparhdr;                      // Size of header in paragraphs
    USHORT      e_minalloc;                     // Minimum extra paragraphs needed
    USHORT      e_maxalloc;                     // Maximum extra paragraphs needed
    USHORT      e_ss;                           // Initial (relative) SS value
    USHORT      e_sp;                           // Initial SP value
    USHORT      e_csum;                         // Checksum
    USHORT      e_ip;                           // Initial IP value
    USHORT      e_cs;                           // Initial (relative) CS value
    USHORT      e_lfarlc;                       // File address of relocation table
    USHORT      e_ovno;                         // Overlay number
    USHORT      e_res[4];                       // Reserved words
    USHORT      e_oemid;                        // OEM identifier (for e_oeminfo)
    USHORT      e_oeminfo;                      // OEM information; e_oemid specific
    USHORT      e_res2[10];                     // Reserved words
    LONG        e_lfanew;                       // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_OS2_HEADER {              // OS/2 .EXE header
    USHORT      ne_magic;                       // Magic number
    CHAR        ne_ver;                         // Version number
    CHAR        ne_rev;                         // Revision number
    USHORT      ne_enttab;                      // Offset of Entry Table
    USHORT      ne_cbenttab;                    // Number of bytes in Entry Table
    LONG        ne_crc;                         // Checksum of whole file
    USHORT      ne_flags;                       // Flag word
    USHORT      ne_autodata;                    // Automatic data segment number
    USHORT      ne_heap;                        // Initial heap allocation
    USHORT      ne_stack;                       // Initial stack allocation
    LONG        ne_csip;                        // Initial CS:IP setting
    LONG        ne_sssp;                        // Initial SS:SP setting
    USHORT      ne_cseg;                        // Count of file segments
    USHORT      ne_cmod;                        // Entries in Module Reference Table
    USHORT      ne_cbnrestab;                   // Size of non-resident name table
    USHORT      ne_segtab;                      // Offset of Segment Table
    USHORT      ne_rsrctab;                     // Offset of Resource Table
    USHORT      ne_restab;                      // Offset of resident name table
    USHORT      ne_modtab;                      // Offset of Module Reference Table
    USHORT      ne_imptab;                      // Offset of Imported Names Table
    LONG        ne_nrestab;                     // Offset of Non-resident Names Table
    USHORT      ne_cmovent;                     // Count of movable entries
    USHORT      ne_align;                       // Segment alignment shift count
    USHORT      ne_cres;                        // Count of resource segments
    UCHAR       ne_exetyp;                      // Target Operating system
    UCHAR       ne_flagsothers;                 // Other .EXE flags
    USHORT      ne_pretthunks;                  // offset to return thunks
    USHORT      ne_psegrefbytes;                // offset to segment ref. bytes
    USHORT      ne_swaparea;                    // Minimum code swap area size
    USHORT      ne_expver;                      // Expected Windows version number
} IMAGE_OS2_HEADER, *PIMAGE_OS2_HEADER;

typedef struct _IMAGE_VXD_HEADER {              // Windows VXD header
    USHORT      e32_magic;                      // Magic number
    UCHAR       e32_border;                     // The byte ordering for the VXD
    UCHAR       e32_worder;                     // The word ordering for the VXD
    ULONG       e32_level;                      // The EXE format level for now = 0
    USHORT      e32_cpu;                        // The CPU type
    USHORT      e32_os;                         // The OS type
    ULONG       e32_ver;                        // Module version
    ULONG       e32_mflags;                     // Module flags
    ULONG       e32_mpages;                     // Module # pages
    ULONG       e32_startobj;                   // Object # for instruction pointer
    ULONG       e32_eip;                        // Extended instruction pointer
    ULONG       e32_stackobj;                   // Object # for stack pointer
    ULONG       e32_esp;                        // Extended stack pointer
    ULONG       e32_pagesize;                   // VXD page size
    ULONG       e32_lastpagesize;               // Last page size in VXD
    ULONG       e32_fixupsize;                  // Fixup section size
    ULONG       e32_fixupsum;                   // Fixup section checksum
    ULONG       e32_ldrsize;                    // Loader section size
    ULONG       e32_ldrsum;                     // Loader section checksum
    ULONG       e32_objtab;                     // Object table offset
    ULONG       e32_objcnt;                     // Number of objects in module
    ULONG       e32_objmap;                     // Object page map offset
    ULONG       e32_itermap;                    // Object iterated data map offset
    ULONG       e32_rsrctab;                    // Offset of Resource Table
    ULONG       e32_rsrccnt;                    // Number of resource entries
    ULONG       e32_restab;                     // Offset of resident name table
    ULONG       e32_enttab;                     // Offset of Entry Table
    ULONG       e32_dirtab;                     // Offset of Module Directive Table
    ULONG       e32_dircnt;                     // Number of module directives
    ULONG       e32_fpagetab;                   // Offset of Fixup Page Table
    ULONG       e32_frectab;                    // Offset of Fixup Record Table
    ULONG       e32_impmod;                     // Offset of Import Module Name Table
    ULONG       e32_impmodcnt;                  // Number of entries in Import Module Name Table
    ULONG       e32_impproc;                    // Offset of Import Procedure Name Table
    ULONG       e32_pagesum;                    // Offset of Per-Page Checksum Table
    ULONG       e32_datapage;                   // Offset of Enumerated Data Pages
    ULONG       e32_preload;                    // Number of preload pages
    ULONG       e32_nrestab;                    // Offset of Non-resident Names Table
    ULONG       e32_cbnrestab;                  // Size of Non-resident Name Table
    ULONG       e32_nressum;                    // Non-resident Name Table Checksum
    ULONG       e32_autodata;                   // Object # for automatic data object
    ULONG       e32_debuginfo;                  // Offset of the debugging information
    ULONG       e32_debuglen;                   // The length of the debugging info. in bytes
    ULONG       e32_instpreload;                // Number of instance pages in preload section of VXD file
    ULONG       e32_instdemand;                 // Number of instance pages in demand load section of VXD file
    ULONG       e32_heapsize;                   // Size of heap - for 16-bit apps
    UCHAR       e32_res3[12];                   // Reserved words
    ULONG       e32_winresoff;
    ULONG       e32_winreslen;
    USHORT      e32_devid;                      // Device ID for VxD
    USHORT      e32_ddkver;                     // DDK version for VxD
} IMAGE_VXD_HEADER, *PIMAGE_VXD_HEADER;

//
// File header format.
//

flag IMAGE_FILE : USHORT {
    RELOCS_STRIPPED             = 0x0001,       // Relocation info stripped from file.
    EXECUTABLE_IMAGE            = 0x0002,       // File is executable  (i.e. no unresolved externel references).
    LINE_NUMS_STRIPPED          = 0x0004,       // Line nunbers stripped from file.
    LOCAL_SYMS_STRIPPED         = 0x0008,       // Local symbols stripped from file.
    AGGRESSIVE_WS_TRIM          = 0x0010,       // Agressively trim working set
    LARGE_ADDRESS_AWARE         = 0x0020,       // App can handle >2gb addresses
    BYTES_REVERSED_LO           = 0x0080,       // Bytes of machine word are reversed.
    32BIT_MACHINE               = 0x0100,       // 32 bit word machine.
    DEBUG_STRIPPED              = 0x0200,       // Debugging info stripped from file in .DBG file
    REMOVABLE_RUN_FROM_SWAP     = 0x0400,       // If Image is on removable media, copy and run from the swap file.
    NET_RUN_FROM_SWAP           = 0x0800,       // If Image is on Net, copy and run from the swap file.
    SYSTEM                      = 0x1000,       // System File.
    DLL                         = 0x2000,       // File is a DLL.
    UP_SYSTEM_ONLY              = 0x4000,       // File should only be run on a UP machine
    BYTES_REVERSED_HI           = 0x8000,       // Bytes of machine word are reversed.
};

enum IMAGE_FILE_MACHINE : USHORT {
    UNKNOWN                     = 0,
    TARGET_HOST                 = 0x0001,       // Useful for indicating we want to interact with the host and not a WoW guest.
    I386                        = 0x014c,       // Intel 386.
    R3000                       = 0x0162,       // MIPS little-endian, 0x160 big-endian
    R4000                       = 0x0166,       // MIPS little-endian
    R10000                      = 0x0168,       // MIPS little-endian
    WCEMIPSV2                   = 0x0169,       // MIPS little-endian WCE v2
    ALPHA                       = 0x0184,       // Alpha_AXP
    SH3                         = 0x01a2,       // SH3 little-endian
    SH3DSP                      = 0x01a3,
    SH3E                        = 0x01a4,       // SH3E little-endian
    SH4                         = 0x01a6,       // SH4 little-endian
    SH5                         = 0x01a8,       // SH5
    ARM                         = 0x01c0,       // ARM Little-Endian
    THUMB                       = 0x01c2,       // ARM Thumb/Thumb-2 Little-Endian
    ARMNT                       = 0x01c4,       // ARM Thumb-2 Little-Endian
    AM33                        = 0x01d3,
    POWERPC                     = 0x01F0,       // IBM PowerPC Little-Endian
    POWERPCFP                   = 0x01f1,
    IA64                        = 0x0200,       // Intel 64
    MIPS16                      = 0x0266,       // MIPS
    ALPHA64                     = 0x0284,       // ALPHA64
    MIPSFPU                     = 0x0366,       // MIPS
    MIPSFPU16                   = 0x0466,       // MIPS
    AXP64                       = 0x0284,       // IMAGE_FILE_MACHINE_ALPHA64
    TRICORE                     = 0x0520,       // Infineon
    CEF                         = 0x0CEF,
    EBC                         = 0x0EBC,       // EFI Byte Code
    CHPE_X86                    = 0x3A64,
    RISCV32 		            = 0x5032,
    RISCV64                     = 0x5064,
    RISCV128                    = 0x5128,
    AMD64                       = 0x8664,       // AMD64 (K8)
    M32R                        = 0x9041,       // M32R little-endian
    ARM64                       = 0xAA64,       // ARM64 Little-Endian
    CEE                         = 0xC0EE,
};

typedef struct _IMAGE_FILE_HEADER {
    IMAGE_FILE_MACHINE  Machine;
    USHORT      NumberOfSections;
    ULONG       TimeDateStamp;
    ULONG       PointerToSymbolTable;
    ULONG       NumberOfSymbols;
    USHORT      SizeOfOptionalHeader;
    IMAGE_FILE  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

//
// Directory format.
//

typedef struct _IMAGE_DATA_DIRECTORY {
    ULONG       VirtualAddress;
    ULONG       Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES        16

//
// Optional header format.
//

// Subsystem Values

enum IMAGE_SUBSYSTEM : USHORT {
    UNKNOWN                     = 0,            // Unknown subsystem.
    NATIVE                      = 1,            // Image doesn't require a subsystem.
    WINDOWS_GUI                 = 2,            // Image runs in the Windows GUI subsystem.
    WINDOWS_CUI                 = 3,            // Image runs in the Windows character subsystem.
    OS2_CUI                     = 5,            // image runs in the OS/2 character subsystem.
    POSIX_CUI                   = 7,            // image runs in the Posix character subsystem.
    NATIVE_WINDOWS              = 8,            // image is a native Win9x driver.
    WINDOWS_CE_GUI              = 9,            // Image runs in the Windows CE subsystem.
    EFI_APPLICATION             = 10,
    EFI_BOOT_SERVICE_DRIVER     = 11,
    EFI_RUNTIME_DRIVER          = 12,
    EFI_ROM                     = 13,
    XBOX                        = 14,
    WINDOWS_BOOT_APPLICATION    = 16,
    XBOX_CODE_CATALOG           = 17,
};

// DllCharacteristics Entries

flag IMAGE_DLLCHARACTERISTICS : USHORT {
    PROCESS_INIT                = 0x0001,       // Reserved. (IMAGE_LIBRARY_PROCESS_INIT)
    PROCESS_TERM                = 0x0002,       // Reserved. (IMAGE_LIBRARY_PROCESS_TERM)
    THREAD_INIT                 = 0x0004,       // Reserved. (IMAGE_LIBRARY_THREAD_INIT)
    THREAD_TERM                 = 0x0008,       // Reserved. (IMAGE_LIBRARY_THREAD_TERM)
    HIGH_ENTROPY_VA             = 0x0020,       // Image can handle a high entropy 64-bit virtual address space.
    DYNAMIC_BASE                = 0x0040,       // DLL can move.
    FORCE_INTEGRITY             = 0x0080,       // Code Integrity Image
    NX_COMPAT                   = 0x0100,       // Image is NX compatible
    NO_ISOLATION                = 0x0200,       // Image understands isolation and doesn't want it
    NO_SEH                      = 0x0400,       // Image does not use SEH.  No SE handler may reside in this image
    NO_BIND                     = 0x0800,       // Do not bind this image.
    APPCONTAINER                = 0x1000,       // Image should execute in an AppContainer
    WDM_DRIVER                  = 0x2000,       // Driver uses WDM model
    GUARD_CF                    = 0x4000,       // Image supports Control Flow Guard.
    TERMINAL_SERVER_AWARE       = 0x8000,
};

typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //

    USHORT      Magic;
    UCHAR       MajorLinkerVersion;
    UCHAR       MinorLinkerVersion;
    ULONG       SizeOfCode;
    ULONG       SizeOfInitializedData;
    ULONG       SizeOfUninitializedData;
    ULONG       AddressOfEntryPoint;
    ULONG       BaseOfCode;
    ULONG       BaseOfData;

    //
    // NT additional fields.
    //

    ULONG       ImageBase;
    ULONG       SectionAlignment;
    ULONG       FileAlignment;
    USHORT      MajorOperatingSystemVersion;
    USHORT      MinorOperatingSystemVersion;
    USHORT      MajorImageVersion;
    USHORT      MinorImageVersion;
    USHORT      MajorSubsystemVersion;
    USHORT      MinorSubsystemVersion;
    ULONG       Win32VersionValue;
    ULONG       SizeOfImage;
    ULONG       SizeOfHeaders;
    ULONG       CheckSum;
    IMAGE_SUBSYSTEM             Subsystem;
    IMAGE_DLLCHARACTERISTICS    DllCharacteristics;
    ULONG       SizeOfStackReserve;
    ULONG       SizeOfStackCommit;
    ULONG       SizeOfHeapReserve;
    ULONG       SizeOfHeapCommit;
    ULONG       LoaderFlags;
    ULONG       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY        DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    USHORT      Magic;
    UCHAR       MajorLinkerVersion;
    UCHAR       MinorLinkerVersion;
    ULONG       SizeOfCode;
    ULONG       SizeOfInitializedData;
    ULONG       SizeOfUninitializedData;
    ULONG       AddressOfEntryPoint;
    ULONG       BaseOfCode;
    ULONGLONG   ImageBase;
    ULONG       SectionAlignment;
    ULONG       FileAlignment;
    USHORT      MajorOperatingSystemVersion;
    USHORT      MinorOperatingSystemVersion;
    USHORT      MajorImageVersion;
    USHORT      MinorImageVersion;
    USHORT      MajorSubsystemVersion;
    USHORT      MinorSubsystemVersion;
    ULONG       Win32VersionValue;
    ULONG       SizeOfImage;
    ULONG       SizeOfHeaders;
    ULONG       CheckSum;
    IMAGE_SUBSYSTEM             Subsystem;
    IMAGE_DLLCHARACTERISTICS    DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    ULONG       LoaderFlags;
    ULONG       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY        DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC           0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC           0x20b
#define IMAGE_ROM_OPTIONAL_HDR_MAGIC            0x107

typedef struct _IMAGE_NT_HEADERS64 {
    ULONG                       Signature;
    IMAGE_FILE_HEADER           FileHeader;
    IMAGE_OPTIONAL_HEADER64     OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
    ULONG                       Signature;
    IMAGE_FILE_HEADER           FileHeader;
    IMAGE_OPTIONAL_HEADER32     OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

// Directory Entries

enum IMAGE_DIRECTORY_ENTRY {
    EXPORT                      = 0,            // Export Directory
    IMPORT                      = 1,            // Import Directory
    RESOURCE                    = 2,            // Resource Directory
    EXCEPTION                   = 3,            // Exception Directory
    SECURITY                    = 4,            // Security Directory
    BASERELOC                   = 5,            // Base Relocation Table
    DEBUG                       = 6,            // Debug Directory
    COPYRIGHT                   = 7,            // (X86 usage)
    ARCHITECTURE                = 7,            // Architecture Specific Data
    GLOBALPTR                   = 8,            // RVA of GP
    TLS                         = 9,            // TLS Directory
    LOAD_CONFIG                 = 10,           // Load Configuration Directory
    BOUND_IMPORT                = 11,           // Bound Import Directory in headers
    IAT                         = 12,           // Import Address Table
    DELAY_IMPORT                = 13,           // Delay Load Import Descriptors
    COM_DESCRIPTOR              = 14,           // COM Runtime descriptor
};

//
// Section header format.
//

flag IMAGE_SCN : ULONG {
    TYPE_REG                    = 0x00000000,   // Reserved.
    TYPE_DSECT                  = 0x00000001,   // Reserved.
    TYPE_NOLOAD                 = 0x00000002,   // Reserved.
    TYPE_GROUP                  = 0x00000004,   // Reserved.
    TYPE_NO_PAD                 = 0x00000008,   // Reserved.
    TYPE_COPY                   = 0x00000010,   // Reserved.

    CNT_CODE                    = 0x00000020,   // Section contains code.
    CNT_INITIALIZED_DATA        = 0x00000040,   // Section contains initialized data.
    CNT_UNINITIALIZED_DATA      = 0x00000080,   // Section contains uninitialized data.

    LNK_OTHER                   = 0x00000100,   // Reserved.
    LNK_INFO                    = 0x00000200,   // Section contains comments or some other type of information.
    TYPE_OVER                   = 0x00000400,   // Reserved.
    LNK_REMOVE                  = 0x00000800,   // Section contents will not become part of image.
    LNK_COMDAT                  = 0x00001000,   // Section contents comdat.
//  //                          = 0x00002000,   // Reserved.
    NO_DEFER_SPEC_EXC           = 0x00004000,   // Reset speculative exceptions handling bits in the TLB entries for this section.
    GPREL                       = 0x00008000,   // Section content can be accessed relative to GP
    MEM_FARDATA                 = 0x00008000,
//  MEM_SYSHEAP                 = 0x00010000,   // Obsolete
    MEM_PURGEABLE               = 0x00020000,
    MEM_16BIT                   = 0x00020000,
    MEM_LOCKED                  = 0x00040000,
    MEM_PRELOAD                 = 0x00080000,

    ALIGN_1BYTES                = 0x00100000,
    ALIGN_2BYTES                = 0x00200000,
    ALIGN_4BYTES                = 0x00300000,
    ALIGN_8BYTES                = 0x00400000,
    ALIGN_16BYTES               = 0x00500000,   // Default alignment if no others are specified.
    ALIGN_32BYTES               = 0x00600000,
    ALIGN_64BYTES               = 0x00700000,
    ALIGN_128BYTES              = 0x00800000,
    ALIGN_256BYTES              = 0x00900000,
    ALIGN_512BYTES              = 0x00A00000,
    ALIGN_1024BYTES             = 0x00B00000,
    ALIGN_2048BYTES             = 0x00C00000,
    ALIGN_4096BYTES             = 0x00D00000,
    ALIGN_8192BYTES             = 0x00E00000,
//  // Unused                   = 0x00F00000,
    ALIGN_MASK                  = 0x00F00000,

    LNK_NRELOC_OVFL             = 0x01000000,   // Section contains extended relocations.
    MEM_DISCARDABLE             = 0x02000000,   // Section can be discarded.
    MEM_NOT_CACHED              = 0x04000000,   // Section is not cachable.
    MEM_NOT_PAGED               = 0x08000000,   // Section is not pageable.
    MEM_SHARED                  = 0x10000000,   // Section is shareable.
    MEM_EXECUTE                 = 0x20000000,   // Section is executable.
    MEM_READ                    = 0x40000000,   // Section is readable.
    MEM_WRITE                   = 0x80000000,   // Section is writeable.
};

#define IMAGE_SIZEOF_SHORT_NAME                 8

typedef struct _IMAGE_SECTION_HEADER {
    CHAR        Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        ULONG   PhysicalAddress;
        ULONG   VirtualSize;
    } Misc;
    ULONG       VirtualAddress;
    ULONG       SizeOfRawData;
    ULONG       PointerToRawData;
    ULONG       PointerToRelocations;
    ULONG       PointerToLinenumbers;
    USHORT      NumberOfRelocations;
    USHORT      NumberOfLinenumbers;
    IMAGE_SCN   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

//
// Symbol format.
//

/* TODO */

//
// Based relocation format.
//

//
// Based relocation types.
//

enum IMAGE_REL_BASED {
    ABSOLUTE                    = 0,            // The base relocation is skipped. This type can be used to pad a block.
    HIGH                        = 1,            // The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word.
    LOW                         = 2,            // The base relocation adds the low 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the low half of a 32-bit word.
    HIGHLOW                     = 3,            // The base relocation applies all 32 bits of the difference to the 32-bit field at offset.
    HIGHADJ                     = 4,            // The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word. The low 16 bits of the 32-bit value are stored in the 16-bit word that follows this base relocation. This means that this base relocation occupies two slots.
    MIPS_JMPADDR                = 5,            // The relocation interpretation is dependent on the machine type. When the machine type is MIPS, the base relocation applies to a MIPS jump instruction.
    ARM_MOV32                   = 5,            // This relocation is meaningful only when the machine type is ARM or Thumb. The base relocation applies the 32-bit address of a symbol across a consecutive MOVW/MOVT instruction pair.
    RISCV_HIGH20                = 5,            // This relocation is only meaningful when the machine type is RISC-V. The base relocation applies to the high 20 bits of a 32-bit absolute address.
    MACHINE_SPECIFIC_5          = 5,            // The relocation interpretation is dependent on the machine type.
    RESERVED                    = 6,            // Reserved, must be zero.
    THUMB_MOV32                 = 7,            // This relocation is meaningful only when the machine type is Thumb. The base relocation applies the 32-bit address of a symbol to a consecutive MOVW/MOVT instruction pair.
    RISCV_LOW12I                = 7,            // This relocation is only meaningful when the machine type is RISC-V. The base relocation applies to the low 12 bits of a 32-bit absolute address formed in RISC-V I-type instruction format.
    REL32                       = 7,
    MACHINE_SPECIFIC_7          = 7,            // The relocation interpretation is dependent on the machine type.
    RISCV_LOW12S                = 8,            // This relocation is only meaningful when the machine type is RISC-V. The base relocation applies to the low 12 bits of a 32-bit absolute address formed in RISC-V S-type instruction format.
    LOONGARCH32_MARK_LA         = 8,            // This relocation is only meaningful when the machine type is LoongArch 32-bit. The base relocation applies to a 32-bit absolute address formed in two consecutive instructions.
    LOONGARCH64_MARK_LA         = 8,            // This relocation is only meaningful when the machine type is LoongArch 64-bit. The base relocation applies to a 64-bit absolute address formed in four consecutive instructions.
    VXD_RELATIVE                = 8,
    MACHINE_SPECIFIC_8          = 8,            // The relocation interpretation is dependent on the machine type.
    MIPS_JMPADDR16              = 9,            // The relocation is only meaningful when the machine type is MIPS. The base relocation applies to a MIPS16 jump instruction.
    IA64_IMM64                  = 9,
    MACHINE_SPECIFIC_9          = 9,            // The relocation interpretation is dependent on the machine type.
    DIR64                       = 10,           // The base relocation applies the difference to the 64-bit field at offset.
};

typedef struct _IMAGE_BASE_RELOCATION {
    ULONG       VirtualAddress;
    ULONG       SizeOfBlock;
//  USHORT      TypeOffset[1];
} IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;

//
// Archive format.
//

#define IMAGE_ARCHIVE_START_SIZE             8
#define IMAGE_ARCHIVE_START                  b"!<arch>\n"
#define IMAGE_ARCHIVE_END                    b"`\n"
#define IMAGE_ARCHIVE_PAD                    b"\n"
#define IMAGE_ARCHIVE_LINKER_MEMBER          b"/               "
#define IMAGE_ARCHIVE_LONGNAMES_MEMBER       b"//              "

typedef struct _IMAGE_ARCHIVE_MEMBER_HEADER {
    CHAR        Name[16];                       // File member name - `/' terminated.
    CHAR        Date[12];                       // File member date - decimal.
    CHAR        UserID[6];                      // File member user id - decimal.
    CHAR        GroupID[6];                     // File member group id - decimal.
    CHAR        Mode[8];                        // File member mode - octal.
    CHAR        Size[10];                       // File member size - decimal.
    CHAR        EndHeader[2];                   // String to end header.
} IMAGE_ARCHIVE_MEMBER_HEADER, *PIMAGE_ARCHIVE_MEMBER_HEADER;

//
// DLL support.
//

//
// Export Format
//

typedef struct _IMAGE_EXPORT_DIRECTORY {
    ULONG       Characteristics;
    ULONG       TimeDateStamp;
    USHORT      MajorVersion;
    USHORT      MinorVersion;
    ULONG       Name;
    ULONG       Base;
    ULONG       NumberOfFunctions;
    ULONG       NumberOfNames;
    ULONG       AddressOfFunctions;             // RVA from base of image
    ULONG       AddressOfNames;                 // RVA from base of image
    ULONG       AddressOfNameOrdinals;          // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

//
// Import Format
//

typedef struct _IMAGE_IMPORT_BY_NAME {
    USHORT      Hint;
    CHAR        Name[];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG   ForwarderString;            // PUCHAR
        ULONGLONG   Function;                   // PULONG
        ULONGLONG   Ordinal;
        ULONGLONG   AddressOfData;              // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA64, *PIMAGE_THUNK_DATA64;

typedef struct _IMAGE_THUNK_DATA32 {
  union {
        ULONG   ForwarderString;                // PUCHAR
        ULONG   Function;                       // PULONG
        ULONG   Ordinal;
        ULONG   AddressOfData;                  // PIMAGE_IMPORT_BY_NAME
  } u1;
} IMAGE_THUNK_DATA32, *PIMAGE_THUNK_DATA32;

#define IMAGE_ORDINAL_FLAG64                    0x8000000000000000
#define IMAGE_ORDINAL_FLAG32                    0x80000000

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        ULONG   Characteristics;                // 0 for terminating null import descriptor
        ULONG   OriginalFirstThunk;             // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    };
    ULONG       TimeDateStamp;                  // 0 if not bound,
                                                // -1 if bound, and real date/time stamp
                                                //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                                // O.W. date/time stamp of DLL bound to (Old BIND)

    ULONG       ForwarderChain;                 // -1 if no forwarders
    ULONG       Name;
    ULONG       FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

//
// Thread Local Storage
//

typedef struct _IMAGE_TLS_DIRECTORY64 {
    ULONGLONG   StartAddressOfRawData;
    ULONGLONG   EndAddressOfRawData;
    ULONGLONG   AddressOfIndex;                 // PULONG
    ULONGLONG   AddressOfCallBacks;             // PIMAGE_TLS_CALLBACK *;
    ULONG       SizeOfZeroFill;
    union {
        ULONG   Characteristics;
        struct {
            ULONG   Reserved0 : 20;
            ULONG   Alignment : 4;
            ULONG   Reserved1 : 8;
        };
    };
} IMAGE_TLS_DIRECTORY64, *PIMAGE_TLS_DIRECTORY64;

typedef struct _IMAGE_TLS_DIRECTORY32 {
    ULONG       StartAddressOfRawData;
    ULONG       EndAddressOfRawData;
    ULONG       AddressOfIndex;                 // PULONG
    ULONG       AddressOfCallBacks;             // PIMAGE_TLS_CALLBACK *
    ULONG       SizeOfZeroFill;
    union {
        ULONG   Characteristics;
        struct {
            ULONG   Reserved0 : 20;
            ULONG   Alignment : 4;
            ULONG   Reserved1 : 8;
        };
    };
} IMAGE_TLS_DIRECTORY32, *PIMAGE_TLS_DIRECTORY32;

//
// New format import descriptors pointed to by DataDirectory[ IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT ]
//

typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
    ULONG       TimeDateStamp;
    USHORT      OffsetModuleName;
    USHORT      NumberOfModuleForwarderRefs;
// Array of zero or more IMAGE_BOUND_FORWARDER_REF follows
} IMAGE_BOUND_IMPORT_DESCRIPTOR, *PIMAGE_BOUND_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_BOUND_FORWARDER_REF {
    ULONG       TimeDateStamp;
    USHORT      OffsetModuleName;
    USHORT      Reserved;
} IMAGE_BOUND_FORWARDER_REF, *PIMAGE_BOUND_FORWARDER_REF;

typedef struct _IMAGE_DELAYLOAD_DESCRIPTOR {
    union {
        ULONG   AllAttributes;
        struct {
            ULONG   RvaBased : 1;               // Delay load version 2
            ULONG   ReservedAttributes : 31;
        };
    } Attributes;

    ULONG       DllNameRVA;                     // RVA to the name of the target library (NULL-terminate ASCII string)
    ULONG       ModuleHandleRVA;                // RVA to the HMODULE caching location (PHMODULE)
    ULONG       ImportAddressTableRVA;          // RVA to the start of the IAT (PIMAGE_THUNK_DATA)
    ULONG       ImportNameTableRVA;             // RVA to the start of the name table (PIMAGE_THUNK_DATA::AddressOfData)
    ULONG       BoundImportAddressTableRVA;     // RVA to an optional bound IAT
    ULONG       UnloadInformationTableRVA;      // RVA to an optional unload info table
    ULONG       TimeDateStamp;                  // 0 if not bound,
                                                // Otherwise, date/time of the target DLL
} IMAGE_DELAYLOAD_DESCRIPTOR, *PIMAGE_DELAYLOAD_DESCRIPTOR;

//
// Resource Format.
//

enum RT {
    CURSOR                      = 1,
    BITMAP                      = 2,
    ICON                        = 3,
    MENU                        = 4,
    DIALOG                      = 5,
    STRING                      = 6,
    FONTDIR                     = 7,
    FONT                        = 8,
    ACCELERATOR                 = 9,
    RCDATA                      = 10,
    MESSAGETABLE                = 11,
    GROUP_CURSOR                = 12,
    GROUP_ICON                  = 14,
    VERSION                     = 16,
    DLGINCLUDE                  = 17,
    PLUGPLAY                    = 19,
    VXD                         = 20,
    ANICURSOR                   = 21,
    ANIICON                     = 22,
    HTML                        = 23,
    MANIFEST                    = 24,
};

//
// Resource directory consists of two counts, following by a variable length
// array of directory entries.  The first count is the number of entries at
// beginning of the array that have actual names associated with each entry.
// The entries are in ascending order, case insensitive strings.  The second
// count is the number of entries that immediately follow the named entries.
// This second count identifies the number of entries that have 16-bit integer
// Ids as their name.  These entries are also sorted in ascending order.
//
// This structure allows fast lookup by either name or number, but for any
// given resource entry only one form of lookup is supported, not both.
// This is consistant with the syntax of the .RC file and the .RES file.
//

typedef struct _IMAGE_RESOURCE_DIRECTORY {
    ULONG       Characteristics;
    ULONG       TimeDateStamp;
    USHORT      MajorVersion;
    USHORT      MinorVersion;
    USHORT      NumberOfNamedEntries;
    USHORT      NumberOfIdEntries;
    /*  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[]; */
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

//
// Each directory contains the 32-bit Name of the entry and an offset,
// relative to the beginning of the resource directory of the data associated
// with this directory entry.  If the name of the entry is an actual text
// string instead of an integer Id, then the high order bit of the name field
// is set to one and the low order 31-bits are an offset, relative to the
// beginning of the resource directory of the string, which is of type
// IMAGE_RESOURCE_DIRECTORY_STRING.  Otherwise the high bit is clear and the
// low-order 16-bits are the integer Id that identify this resource directory
// entry. If the directory entry is yet another resource directory (i.e. a
// subdirectory), then the high order bit of the offset field will be
// set to indicate this.  Otherwise the high bit is clear and the offset
// field points to a resource data entry.
//

typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union {
        struct {
            ULONG   NameOffset:31;
            ULONG   NameIsString:1;
        };
        ULONG       Name;
        USHORT      Id;
    };
    union {
        ULONG OffsetToData;
        struct {
            ULONG   OffsetToDirectory:31;
            ULONG   DataIsDirectory:1;
        };
    };
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

//
// For resource directory entries that have actual string names, the Name
// field of the directory entry points to an object of the following type.
// All of these string objects are stored together after the last resource
// directory entry and before the first resource data object.  This minimizes
// the impact of these variable length objects on the alignment of the fixed
// size directory entry objects.
//

typedef struct _IMAGE_RESOURCE_DIRECTORY_STRING {
    USHORT      Length;
    CHAR        NameString[Length];
} IMAGE_RESOURCE_DIRECTORY_STRING, *PIMAGE_RESOURCE_DIRECTORY_STRING;

typedef struct _IMAGE_RESOURCE_DIR_STRING_U {
    USHORT      Length;
    WCHAR       NameString[Length];
} IMAGE_RESOURCE_DIR_STRING_U, *PIMAGE_RESOURCE_DIR_STRING_U;

//
// Each resource data entry describes a leaf node in the resource directory
// tree.  It contains an offset, relative to the beginning of the resource
// directory of the data for the resource, a size field that gives the number
// of bytes of data at that offset, a CodePage that should be used when
// decoding code point values within the resource data.  Typically for new
// applications the code page would be the unicode code page.
//

typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
    ULONG       OffsetToData;
    ULONG       Size;
    ULONG       CodePage;
    ULONG       Reserved;
} IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

typedef struct _VS_FIXEDFILEINFO {
    DWORD       dwSignature;
    DWORD       dwStrucVersion;
    DWORD       dwFileVersionMS;
    DWORD       dwFileVersionLS;
    DWORD       dwProductVersionMS;
    DWORD       dwProductVersionLS;
    DWORD       dwFileFlagsMask;
    DWORD       dwFileFlags;
    DWORD       dwFileOS;
    DWORD       dwFileType;
    DWORD       dwFileSubtype;
    DWORD       dwFileDateMS;
    DWORD       dwFileDateLS;
} VS_FIXEDFILEINFO, *PVS_FIXEDFILEINFO;

flag VS_FF {
    DEBUG                       = 0x00000001,   // The file contains debugging information or is compiled with debugging features enabled.
    PRERELEASE                  = 0x00000002,   // The file is a development version, not a commercially released product.
    PATCHED                     = 0x00000004,   // The file has been modified and is not identical to the original shipping file of the same version number.
    PRIVATEBUILD                = 0x00000008,   // The file was not built using standard release procedures. If this flag is set, the StringFileInfo structure should contain a PrivateBuild entry.
    INFOINFERRED                = 0x00000010,   // The file's version structure was created dynamically; therefore, some of the members in this structure may be empty or incorrect. This flag should never be set in a file's VS_VERSIONINFO data.
    SPECIALBUILD                = 0x00000020,   // The file was built by the original company using standard release procedures but is a variation of the normal file of the same version number. If this flag is set, the StringFileInfo structure should contain a SpecialBuild entry.
};

enum VOS {
    UNKNOWN                     = 0x00000000,   // The operating system for which the file was designed is unknown to the system.
    WINDOWS16                   = 0x00000001,   // The file was designed for 16-bit Windows.
    PM16                        = 0x00000002,   // The file was designed for 16-bit Presentation Manager.
    PM32                        = 0x00000003,   // The file was designed for 32-bit Presentation Manager.
    WINDOWS32                   = 0x00000004,   // The file was designed for 32-bit Windows.
    DOS                         = 0x00010000,   // The file was designed for MS-DOS.
    OS216                       = 0x00020000,   // The file was designed for 16-bit OS/2.
    OS232                       = 0x00030000,   // The file was designed for 32-bit OS/2.
    NT                          = 0x00040000,   // The file was designed for Windows NT.
};

enum VFT {
    UNKNOWN                     = 0x00000000,   // The file type is unknown to the system.
    APP                         = 0x00000001,   // The file contains an application.
    DLL                         = 0x00000002,   // The file contains a DLL.
    DRV                         = 0x00000003,   // The file contains a device driver. If dwFileType is VFT_DRV, dwFileSubtype contains a more specific description of the driver.
    FONT                        = 0x00000004,   // The file contains a font. If dwFileType is VFT_FONT, dwFileSubtype contains a more specific description of the font file.
    VXD                         = 0x00000005,   // The file contains a virtual device.
    STATIC_LIBRARY              = 0x00000007,   // The file contains a static-link library.
};

enum VFT2_DRV {
    UNKNOWN                     = 0x00000000,   // The driver type is unknown by the system.
    PRINTER                     = 0x00000001,   // The file contains a printer driver.
    KEYBOARD                    = 0x00000002,   // The file contains a keyboard driver.
    LANGUAGE                    = 0x00000003,   // The file contains a language driver.
    DISPLAY                     = 0x00000004,   // The file contains a display driver.
    MOUSE                       = 0x00000005,   // The file contains a mouse driver.
    NETWORK                     = 0x00000006,   // The file contains a network driver.
    SYSTEM                      = 0x00000007,   // The file contains a system driver.
    INSTALLABLE                 = 0x00000008,   // The file contains an installable driver.
    SOUND                       = 0x00000009,   // The file contains a sound driver.
    COMM                        = 0x0000000A,   // The file contains a communications driver.
    INPUTMETHOD                 = 0x0000000B,
    VERSIONED_PRINTER           = 0x0000000C,   // The file contains a versioned printer driver.
};

enum VFT2_FONT {
    UNKNOWN                     = 0x00000000,   // The font type is unknown by the system.
    RASTER                      = 0x00000001,   // The file contains a raster font.
    VECTOR                      = 0x00000002,   // The file contains a vector font.
    TRUETYPE                    = 0x00000003,   // The file contains a TrueType font.
};

/*
 * Virtual Keys, Standard Set
 */
enum VK {
    LBUTTON                     = 0x01,
    RBUTTON                     = 0x02,
    CANCEL                      = 0x03,
    MBUTTON                     = 0x04,         /* NOT contiguous with L & RBUTTON */
    XBUTTON1                    = 0x05,         /* NOT contiguous with L & RBUTTON */
    XBUTTON2                    = 0x06,         /* NOT contiguous with L & RBUTTON */

/*
 * 0x07 : reserved
 */

    BACK                        = 0x08,
    TAB                         = 0x09,

/*
 * 0x0A - 0x0B : reserved
 */

    CLEAR                       = 0x0C,
    RETURN                      = 0x0D,

/*
 * 0x0E - 0x0F : unassigned
 */

    SHIFT                       = 0x10,
    CONTROL                     = 0x11,
    MENU                        = 0x12,
    PAUSE                       = 0x13,
    CAPITAL                     = 0x14,

    KANA                        = 0x15,
    HANGEUL                     = 0x15,         /* old name - should be here for compatibility */
    HANGUL                      = 0x15,
    IME_ON                      = 0x16,
    JUNJA                       = 0x17,
    FINAL                       = 0x18,
    HANJA                       = 0x19,
    KANJI                       = 0x19,
    IME_OFF                     = 0x1A,

    ESCAPE                      = 0x1B,

    CONVERT                     = 0x1C,
    NONCONVERT                  = 0x1D,
    ACCEPT                      = 0x1E,
    MODECHANGE                  = 0x1F,

    SPACE                       = 0x20,
    PRIOR                       = 0x21,
    NEXT                        = 0x22,
    END                         = 0x23,
    HOME                        = 0x24,
    LEFT                        = 0x25,
    UP                          = 0x26,
    RIGHT                       = 0x27,
    DOWN                        = 0x28,
    SELECT                      = 0x29,
    PRINT                       = 0x2A,
    EXECUTE                     = 0x2B,
    SNAPSHOT                    = 0x2C,
    INSERT                      = 0x2D,
    DELETE                      = 0x2E,
    HELP                        = 0x2F,

/*
 * VK_0 - VK_9 are the same as ASCII '0' - '9' (0x30 - 0x39)
 * 0x3A - 0x40 : unassigned
 * VK_A - VK_Z are the same as ASCII 'A' - 'Z' (0x41 - 0x5A)
 */

    0                           = 0x30,
    1                           = 0x31,
    2                           = 0x32,
    3                           = 0x33,
    4                           = 0x34,
    5                           = 0x35,
    6                           = 0x36,
    7                           = 0x37,
    8                           = 0x38,
    9                           = 0x39,
    A                           = 0x41,
    B                           = 0x42,
    C                           = 0x43,
    D                           = 0x44,
    E                           = 0x45,
    F                           = 0x46,
    G                           = 0x47,
    H                           = 0x48,
    I                           = 0x49,
    J                           = 0x4A,
    K                           = 0x4B,
    L                           = 0x4C,
    M                           = 0x4D,
    N                           = 0x4E,
    O                           = 0x4F,
    P                           = 0x50,
    Q                           = 0x51,
    R                           = 0x52,
    S                           = 0x53,
    T                           = 0x54,
    U                           = 0x55,
    V                           = 0x56,
    W                           = 0x57,
    X                           = 0x58,
    Y                           = 0x59,
    Z                           = 0x5A,
    LWIN                        = 0x5B,
    RWIN                        = 0x5C,
    APPS                        = 0x5D,

/*
 * 0x5E : reserved
 */

    SLEEP                       = 0x5F,

    NUMPAD0                     = 0x60,
    NUMPAD1                     = 0x61,
    NUMPAD2                     = 0x62,
    NUMPAD3                     = 0x63,
    NUMPAD4                     = 0x64,
    NUMPAD5                     = 0x65,
    NUMPAD6                     = 0x66,
    NUMPAD7                     = 0x67,
    NUMPAD8                     = 0x68,
    NUMPAD9                     = 0x69,
    MULTIPLY                    = 0x6A,
    ADD                         = 0x6B,
    SEPARATOR                   = 0x6C,
    SUBTRACT                    = 0x6D,
    DECIMAL                     = 0x6E,
    DIVIDE                      = 0x6F,
    F1                          = 0x70,
    F2                          = 0x71,
    F3                          = 0x72,
    F4                          = 0x73,
    F5                          = 0x74,
    F6                          = 0x75,
    F7                          = 0x76,
    F8                          = 0x77,
    F9                          = 0x78,
    F10                         = 0x79,
    F11                         = 0x7A,
    F12                         = 0x7B,
    F13                         = 0x7C,
    F14                         = 0x7D,
    F15                         = 0x7E,
    F16                         = 0x7F,
    F17                         = 0x80,
    F18                         = 0x81,
    F19                         = 0x82,
    F20                         = 0x83,
    F21                         = 0x84,
    F22                         = 0x85,
    F23                         = 0x86,
    F24                         = 0x87,

/*
 * 0x88 - 0x8F : UI navigation
 */

    NAVIGATION_VIEW             = 0x88,         // reserved
    NAVIGATION_MENU             = 0x89,         // reserved
    NAVIGATION_UP               = 0x8A,         // reserved
    NAVIGATION_DOWN             = 0x8B,         // reserved
    NAVIGATION_LEFT             = 0x8C,         // reserved
    NAVIGATION_RIGHT            = 0x8D,         // reserved
    NAVIGATION_ACCEPT           = 0x8E,         // reserved
    NAVIGATION_CANCEL           = 0x8F,         // reserved

    NUMLOCK                     = 0x90,
    SCROLL                      = 0x91,

/*
 * NEC PC-9800 kbd definitions
 */
    OEM_NEC_EQUAL               = 0x92,         // '=' key on numpad

/*
 * Fujitsu/OASYS kbd definitions
 */
    OEM_FJ_JISHO                = 0x92,         // 'Dictionary' key
    OEM_FJ_MASSHOU              = 0x93,         // 'Unregister word' key
    OEM_FJ_TOUROKU              = 0x94,         // 'Register word' key
    OEM_FJ_LOYA                 = 0x95,         // 'Left OYAYUBI' key
    OEM_FJ_ROYA                 = 0x96,         // 'Right OYAYUBI' key

/*
 * 0x97 - 0x9F : unassigned
 */

/*
 * VK_L* & VK_R* - left and right Alt, Ctrl and Shift virtual keys.
 * Used only as parameters to GetAsyncKeyState() and GetKeyState().
 * No other API or message will distinguish left and right keys in this way.
 */
    LSHIFT                      = 0xA0,
    RSHIFT                      = 0xA1,
    LCONTROL                    = 0xA2,
    RCONTROL                    = 0xA3,
    LMENU                       = 0xA4,
    RMENU                       = 0xA5,

    BROWSER_BACK                = 0xA6,
    BROWSER_FORWARD             = 0xA7,
    BROWSER_REFRESH             = 0xA8,
    BROWSER_STOP                = 0xA9,
    BROWSER_SEARCH              = 0xAA,
    BROWSER_FAVORITES           = 0xAB,
    BROWSER_HOME                = 0xAC,

    VOLUME_MUTE                 = 0xAD,
    VOLUME_DOWN                 = 0xAE,
    VOLUME_UP                   = 0xAF,
    MEDIA_NEXT_TRACK            = 0xB0,
    MEDIA_PREV_TRACK            = 0xB1,
    MEDIA_STOP                  = 0xB2,
    MEDIA_PLAY_PAUSE            = 0xB3,
    LAUNCH_MAIL                 = 0xB4,
    LAUNCH_MEDIA_SELECT         = 0xB5,
    LAUNCH_APP1                 = 0xB6,
    LAUNCH_APP2                 = 0xB7,

/*
 * 0xB8 - 0xB9 : reserved
 */

    OEM_1                       = 0xBA,         // ';:' for US
    OEM_PLUS                    = 0xBB,         // '+' any country
    OEM_COMMA                   = 0xBC,         // ',' any country
    OEM_MINUS                   = 0xBD,         // '-' any country
    OEM_PERIOD                  = 0xBE,         // '.' any country
    OEM_2                       = 0xBF,         // '/?' for US
    OEM_3                       = 0xC0,         // '`~' for US

/*
 * 0xC1 - 0xC2 : reserved
 */

 /*
 * 0xC3 - 0xDA : Gamepad input
 */

    GAMEPAD_A                   = 0xC3,         // reserved
    GAMEPAD_B                   = 0xC4,         // reserved
    GAMEPAD_X                   = 0xC5,         // reserved
    GAMEPAD_Y                   = 0xC6,         // reserved
    GAMEPAD_RIGHT_SHOULDER      = 0xC7,         // reserved
    GAMEPAD_LEFT_SHOULDER       = 0xC8,         // reserved
    GAMEPAD_LEFT_TRIGGER        = 0xC9,         // reserved
    GAMEPAD_RIGHT_TRIGGER       = 0xCA,         // reserved
    GAMEPAD_DPAD_UP             = 0xCB,         // reserved
    GAMEPAD_DPAD_DOWN           = 0xCC,         // reserved
    GAMEPAD_DPAD_LEFT           = 0xCD,         // reserved
    GAMEPAD_DPAD_RIGHT          = 0xCE,         // reserved
    GAMEPAD_MENU                = 0xCF,         // reserved
    GAMEPAD_VIEW                = 0xD0,         // reserved
    GAMEPAD_LEFT_THUMBSTICK_BUTTON  = 0xD1,     // reserved
    GAMEPAD_RIGHT_THUMBSTICK_BUTTON = 0xD2,     // reserved
    GAMEPAD_LEFT_THUMBSTICK_UP      = 0xD3,     // reserved
    GAMEPAD_LEFT_THUMBSTICK_DOWN    = 0xD4,     // reserved
    GAMEPAD_LEFT_THUMBSTICK_RIGHT   = 0xD5,     // reserved
    GAMEPAD_LEFT_THUMBSTICK_LEFT    = 0xD6,     // reserved
    GAMEPAD_RIGHT_THUMBSTICK_UP     = 0xD7,     // reserved
    GAMEPAD_RIGHT_THUMBSTICK_DOWN   = 0xD8,     // reserved
    GAMEPAD_RIGHT_THUMBSTICK_RIGHT  = 0xD9,     // reserved
    GAMEPAD_RIGHT_THUMBSTICK_LEFT   = 0xDA,     // reserved

    OEM_4                       = 0xDB,         //  '[{' for US
    OEM_5                       = 0xDC,         //  '|' for US
    OEM_6                       = 0xDD,         //  ']}' for US
    OEM_7                       = 0xDE,         //  ''"' for US
    OEM_8                       = 0xDF,

/*
 * 0xE0 : reserved
 */

/*
 * Various extended or enhanced keyboards
 */
    OEM_AX                      = 0xE1,         //  'AX' key on Japanese AX kbd
    OEM_102                     = 0xE2,         //  "<>" or "|" on RT 102-key kbd.
    ICO_HELP                    = 0xE3,         //  Help key on ICO
    ICO_00                      = 0xE4,         //  00 key on ICO

    PROCESSKEY                  = 0xE5,

    ICO_CLEAR                   = 0xE6,

    PACKET                      = 0xE7,

/*
 * 0xE8 : unassigned
 */

/*
 * Nokia/Ericsson definitions
 */
    OEM_RESET                   = 0xE9,
    OEM_JUMP                    = 0xEA,
    OEM_PA1                     = 0xEB,
    OEM_PA2                     = 0xEC,
    OEM_PA3                     = 0xED,
    OEM_WSCTRL                  = 0xEE,
    OEM_CUSEL                   = 0xEF,
    OEM_ATTN                    = 0xF0,
    OEM_FINISH                  = 0xF1,
    OEM_COPY                    = 0xF2,
    OEM_AUTO                    = 0xF3,
    OEM_ENLW                    = 0xF4,
    OEM_BACKTAB                 = 0xF5,

    ATTN                        = 0xF6,
    CRSEL                       = 0xF7,
    EXSEL                       = 0xF8,
    EREOF                       = 0xF9,
    PLAY                        = 0xFA,
    ZOOM                        = 0xFB,
    NONAME                      = 0xFC,
    PA1                         = 0xFD,
    OEM_CLEAR                   = 0xFE,

/*
 * 0xFF : reserved
 */
};

flag ACCEL_F {
    VIRTKEY                     = 0x01,         // Assumed to be == TRUE
    LASTKEY                     = 0x80,         // Indicates last key in the table
    NOINVERT                    = 0x02,
    SHIFT                       = 0x04,
    CONTROL                     = 0x08,
    ALT                         = 0x10,
};

//
// Code Integrity in loadconfig (CI)
//

typedef struct _IMAGE_LOAD_CONFIG_CODE_INTEGRITY {
    USHORT      Flags;                          // Flags to indicate if CI information is available, etc.
    USHORT      Catalog;                        // 0xFFFF means not available
    ULONG       CatalogOffset;
    ULONG       Reserved;                       // Additional bitmask to be defined later
} IMAGE_LOAD_CONFIG_CODE_INTEGRITY, *PIMAGE_LOAD_CONFIG_CODE_INTEGRITY;

//
// Dynamic value relocation table in loadconfig
//

typedef struct _IMAGE_DYNAMIC_RELOCATION_TABLE {
    ULONG       Version;
    ULONG       Size;
//  IMAGE_DYNAMIC_RELOCATION    DynamicRelocations[0];
} IMAGE_DYNAMIC_RELOCATION_TABLE, *PIMAGE_DYNAMIC_RELOCATION_TABLE;

//
// Dynamic value relocation entries following IMAGE_DYNAMIC_RELOCATION_TABLE
//

typedef struct _IMAGE_DYNAMIC_RELOCATION32 {
    ULONG       Symbol;
    ULONG       BaseRelocSize;
//  IMAGE_BASE_RELOCATION       BaseRelocations[0];
} IMAGE_DYNAMIC_RELOCATION32, *PIMAGE_DYNAMIC_RELOCATION32;

typedef struct _IMAGE_DYNAMIC_RELOCATION64 {
    ULONGLONG   Symbol;
    ULONG       BaseRelocSize;
//  IMAGE_BASE_RELOCATION       BaseRelocations[0];
} IMAGE_DYNAMIC_RELOCATION64, *PIMAGE_DYNAMIC_RELOCATION64;

typedef struct _IMAGE_DYNAMIC_RELOCATION32_V2 {
    ULONG       HeaderSize;
    ULONG       FixupInfoSize;
    ULONG       Symbol;
    ULONG       SymbolGroup;
    ULONG       Flags;
    // ...      variable length header fields
    // UCHAR       FixupInfo[FixupInfoSize];
} IMAGE_DYNAMIC_RELOCATION32_V2, *PIMAGE_DYNAMIC_RELOCATION32_V2;

typedef struct _IMAGE_DYNAMIC_RELOCATION64_V2 {
    ULONG       HeaderSize;
    ULONG       FixupInfoSize;
    ULONGLONG   Symbol;
    ULONG       SymbolGroup;
    ULONG       Flags;
    // ...      variable length header fields
    // UCHAR    FixupInfo[FixupInfoSize]
} IMAGE_DYNAMIC_RELOCATION64_V2, *PIMAGE_DYNAMIC_RELOCATION64_V2;

//
// Defined symbolic dynamic relocation entries.
//

#define IMAGE_DYNAMIC_RELOCATION_GUARD_RF_PROLOGUE   0x00000001
#define IMAGE_DYNAMIC_RELOCATION_GUARD_RF_EPILOGUE   0x00000002
#define IMAGE_DYNAMIC_RELOCATION_GUARD_IMPORT_CONTROL_TRANSFER  0x00000003
#define IMAGE_DYNAMIC_RELOCATION_GUARD_INDIR_CONTROL_TRANSFER   0x00000004
#define IMAGE_DYNAMIC_RELOCATION_GUARD_SWITCHTABLE_BRANCH       0x00000005
#define IMAGE_DYNAMIC_RELOCATION_ARM64X                         0x00000006
#define IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE              0x00000007
#define IMAGE_DYNAMIC_RELOCATION_ARM64_KERNEL_IMPORT_CALL_TRANSFER  0x00000008
#define IMAGE_DYNAMIC_RELOCATION_MM_SHARED_USER_DATA_VA         0x7FFE0000
#define IMAGE_DYNAMIC_RELOCATION_KI_USER_SHARED_DATA64          0xFFFFF78000000000

typedef struct _IMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER {
    UCHAR       PrologueByteCount;
    // UCHAR    PrologueBytes[PrologueByteCount];
} IMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER, *PIMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER;

typedef struct _IMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER {
    ULONG       EpilogueCount;
    UCHAR       EpilogueByteCount;
    UCHAR       BranchDescriptorElementSize;
    USHORT      BranchDescriptorCount;
    // UCHAR    BranchDescriptors[...];
    // UCHAR    BranchDescriptorBitMap[...];
} IMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER, *PIMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER;

typedef struct _IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION {
    ULONG       PageRelativeOffset : 12;
    ULONG       IndirectCall       : 1;
    ULONG       IATIndex           : 19;
} IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION, *PIMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION;

//
// On ARM64, an optimized imported function uses the following data structure
// insted of a _IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION.
//

typedef struct _IMAGE_IMPORT_CONTROL_TRANSFER_ARM64_RELOCATION {
    ULONG       PageRelativeOffset : 10;                    // Offset to the call instruction shifted right by 2 (4-byte aligned instruction)
    ULONG       IndirectCall       :  1;                    // 0 if target instruction is a BR, 1 if BLR.
    ULONG       RegisterIndex      :  5;                    // Register index used for the indirect call/jump.
    ULONG       ImportType         :  1;                    // 0 if this refers to a static import, 1 for delayload import
    ULONG       IATIndex           : 15;                    // IAT index of the corresponding import.
                                                            // 0x7FFF is a special value indicating no index.
} IMAGE_IMPORT_CONTROL_TRANSFER_ARM64_RELOCATION, *PIMAGE_IMPORT_CONTROL_TRANSFER_ARM64_RELOCATION;

typedef struct _IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION {
    USHORT      PageRelativeOffset : 12;
    USHORT      IndirectCall       : 1;
    USHORT      RexWPrefix         : 1;
    USHORT      CfgCheck           : 1;
    USHORT      Reserved           : 1;
} IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION, *PIMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION;

typedef struct _IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION {
    USHORT      PageRelativeOffset : 12;
    USHORT      RegisterNumber     : 4;
} IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION, *PIMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION;

typedef struct _IMAGE_FUNCTION_OVERRIDE_HEADER {
    ULONG       FuncOverrideSize;
 // IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION  FuncOverrideInfo[ANYSIZE_ARRAY];    // FuncOverrideSize bytes in size
 // IMAGE_BDD_INFO BDDInfo;                                 // BDD region, size in bytes: DVRTEntrySize - sizeof(IMAGE_FUNCTION_OVERRIDE_HEADER) - FuncOverrideSize
} IMAGE_FUNCTION_OVERRIDE_HEADER, *PIMAGE_FUNCTION_OVERRIDE_HEADER;

typedef struct _IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION {
    ULONG       OriginalRva;                                // RVA of original function
    ULONG       BDDOffset;                                  // Offset into the BDD region
    ULONG       RvaSize;                                    // Size in bytes taken by RVAs. Must be multiple of sizeof(ULONG).
    ULONG       BaseRelocSize;                              // Size in bytes taken by BaseRelocs

//  ULONG       RVAs[RvaSize / sizeof(ULONG)];              // Array containing overriding func RVAs.

//  IMAGE_BASE_RELOCATION  BaseRelocs[ANYSIZE_ARRAY];       // Base relocations (RVA + Size + TO)
                                                            //  Padded with extra TOs for 4B alignment
                                                            // BaseRelocSize size in bytes
} IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION, *PIMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION;

typedef struct _IMAGE_BDD_INFO {
    ULONG       Version;                                    // decides the semantics of serialized BDD
    ULONG       BDDSize;
//  IMAGE_BDD_DYNAMIC_RELOCATION BDDNodes[ANYSIZE_ARRAY];   // BDDSize size in bytes.
} IMAGE_BDD_INFO, *PIMAGE_BDD_INFO;

typedef struct _IMAGE_BDD_DYNAMIC_RELOCATION {
    USHORT      Left;                                       // Index of FALSE edge in BDD array
    USHORT      Right;                                      // Index of TRUE edge in BDD array
    ULONG       Value;                                      // Either FeatureNumber or Index into RVAs array
} IMAGE_BDD_DYNAMIC_RELOCATION, *PIMAGE_BDD_DYNAMIC_RELOCATION;

// Function override relocation types in DVRT records.

#define IMAGE_FUNCTION_OVERRIDE_INVALID                     0
#define IMAGE_FUNCTION_OVERRIDE_X64_REL32                   1   // 32-bit relative address from byte following reloc
#define IMAGE_FUNCTION_OVERRIDE_ARM64_BRANCH26              2   // 26 bit offset << 2 & sign ext. for B & BL
#define IMAGE_FUNCTION_OVERRIDE_ARM64_THUNK                 3

//
// Load Configuration Directory Entry
//

flag IMAGE_GUARD : ULONG {
    CF_INSTRUMENTED                     = 0x00000100,       // Module performs control flow integrity checks using system-supplied support
    CFW_INSTRUMENTED                    = 0x00000200,       // Module performs control flow and write integrity checks
    CF_FUNCTION_TABLE_PRESENT           = 0x00000400,       // Module contains valid control flow target metadata
    SECURITY_COOKIE_UNUSED              = 0x00000800,       // Module does not make use of the /GS security cookie
    PROTECT_DELAYLOAD_IAT               = 0x00001000,       // Module supports read only delay load IAT
    DELAYLOAD_IAT_IN_ITS_OWN_SECTION    = 0x00002000,       // Delayload import table in its own .didat section (with nothing else in it) that can be freely reprotected
    CF_EXPORT_SUPPRESSION_INFO_PRESENT  = 0x00004000,       // Module contains suppressed export information. This also infers that the address taken
                                                            // taken IAT table is also present in the load config.
    CF_ENABLE_EXPORT_SUPPRESSION        = 0x00008000,       // Module enables suppression of exports
    CF_LONGJUMP_TABLE_PRESENT           = 0x00010000,       // Module contains longjmp target information
    RF_INSTRUMENTED                     = 0x00020000,       // Module contains return flow instrumentation and metadata
    RF_ENABLE                           = 0x00040000,       // Module requests that the OS enable return flow protection
    RF_STRICT                           = 0x00080000,       // Module requests that the OS enable return flow protection in strict mode
    RETPOLINE_PRESENT                   = 0x00100000,       // Module was built with retpoline support
//  DO_NOT_USE                          = 0x00200000,       // Was EHCont flag on VB (20H1)
    EH_CONTINUATION_TABLE_PRESENT       = 0x00400000,       // Module contains EH continuation target information
    XFG_ENABLED                         = 0x00800000,       // Module was built with xfg
    CASTGUARD_PRESENT                   = 0x01000000,       // Module has CastGuard instrumentation present
    MEMCPY_PRESENT                      = 0x02000000,       // Module has Guarded Memcpy instrumentation present
};

#define IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK  0xF0000000 // Stride of Guard CF function table encoded in these bits (additional count of bytes per element)
#define IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT 28         // Shift to right-justify Guard CF function table stride

typedef struct _IMAGE_LOAD_CONFIG_DIRECTORY32 {
    ULONG       Size;
    ULONG       TimeDateStamp;
    USHORT      MajorVersion;
    USHORT      MinorVersion;
    ULONG       GlobalFlagsClear;
    ULONG       GlobalFlagsSet;
    ULONG       CriticalSectionDefaultTimeout;
    ULONG       DeCommitFreeBlockThreshold;
    ULONG       DeCommitTotalFreeThreshold;
    ULONG       LockPrefixTable;                            // VA
    ULONG       MaximumAllocationSize;
    ULONG       VirtualMemoryThreshold;
    ULONG       ProcessHeapFlags;
    ULONG       ProcessAffinityMask;
    USHORT      CSDVersion;
    USHORT      DependentLoadFlags;
    ULONG       EditList;                                   // VA
    ULONG       SecurityCookie;                             // VA
    ULONG       SEHandlerTable;                             // VA
    ULONG       SEHandlerCount;
    ULONG       GuardCFCheckFunctionPointer;                // VA
    ULONG       GuardCFDispatchFunctionPointer;             // VA
    ULONG       GuardCFFunctionTable;                       // VA
    ULONG       GuardCFFunctionCount;
    IMAGE_GUARD GuardFlags;
    IMAGE_LOAD_CONFIG_CODE_INTEGRITY    CodeIntegrity;
    ULONG       GuardAddressTakenIatEntryTable;             // VA
    ULONG       GuardAddressTakenIatEntryCount;
    ULONG       GuardLongJumpTargetTable;                   // VA
    ULONG       GuardLongJumpTargetCount;
    ULONG       DynamicValueRelocTable;                     // VA
    ULONG       CHPEMetadataPointer;
    ULONG       GuardRFFailureRoutine;                      // VA
    ULONG       GuardRFFailureRoutineFunctionPointer;       // VA
    ULONG       DynamicValueRelocTableOffset;
    USHORT      DynamicValueRelocTableSection;
    USHORT      Reserved2;
    ULONG       GuardRFVerifyStackPointerFunctionPointer;   // VA
    ULONG       HotPatchTableOffset;
    ULONG       Reserved3;
    ULONG       EnclaveConfigurationPointer;                // VA
    ULONG       VolatileMetadataPointer;                    // VA
    ULONG       GuardEHContinuationTable;                   // VA
    ULONG       GuardEHContinuationCount;
    ULONG       GuardXFGCheckFunctionPointer;               // VA
    ULONG       GuardXFGDispatchFunctionPointer;            // VA
    ULONG       GuardXFGTableDispatchFunctionPointer;       // VA
    ULONG       CastGuardOsDeterminedFailureMode;           // VA
    ULONG       GuardMemcpyFunctionPointer;                 // VA
    ULONG       UmaFunctionPointers;                        // VA
} IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;

typedef struct _IMAGE_LOAD_CONFIG_DIRECTORY64 {
    ULONG       Size;
    ULONG       TimeDateStamp;
    USHORT      MajorVersion;
    USHORT      MinorVersion;
    ULONG       GlobalFlagsClear;
    ULONG       GlobalFlagsSet;
    ULONG       CriticalSectionDefaultTimeout;
    ULONGLONG   DeCommitFreeBlockThreshold;
    ULONGLONG   DeCommitTotalFreeThreshold;
    ULONGLONG   LockPrefixTable;                            // VA
    ULONGLONG   MaximumAllocationSize;
    ULONGLONG   VirtualMemoryThreshold;
    ULONGLONG   ProcessAffinityMask;
    ULONG       ProcessHeapFlags;
    USHORT      CSDVersion;
    USHORT      DependentLoadFlags;
    ULONGLONG   EditList;                                   // VA
    ULONGLONG   SecurityCookie;                             // VA
    ULONGLONG   SEHandlerTable;                             // VA
    ULONGLONG   SEHandlerCount;
    ULONGLONG   GuardCFCheckFunctionPointer;                // VA
    ULONGLONG   GuardCFDispatchFunctionPointer;             // VA
    ULONGLONG   GuardCFFunctionTable;                       // VA
    ULONGLONG   GuardCFFunctionCount;
    IMAGE_GUARD GuardFlags;
    IMAGE_LOAD_CONFIG_CODE_INTEGRITY    CodeIntegrity;
    ULONGLONG   GuardAddressTakenIatEntryTable;             // VA
    ULONGLONG   GuardAddressTakenIatEntryCount;
    ULONGLONG   GuardLongJumpTargetTable;                   // VA
    ULONGLONG   GuardLongJumpTargetCount;
    ULONGLONG   DynamicValueRelocTable;                     // VA
    ULONGLONG   CHPEMetadataPointer;                        // VA
    ULONGLONG   GuardRFFailureRoutine;                      // VA
    ULONGLONG   GuardRFFailureRoutineFunctionPointer;       // VA
    ULONG       DynamicValueRelocTableOffset;
    USHORT      DynamicValueRelocTableSection;
    USHORT      Reserved2;
    ULONGLONG   GuardRFVerifyStackPointerFunctionPointer;   // VA
    ULONG       HotPatchTableOffset;
    ULONG       Reserved3;
    ULONGLONG   EnclaveConfigurationPointer;                // VA
    ULONGLONG   VolatileMetadataPointer;                    // VA
    ULONGLONG   GuardEHContinuationTable;                   // VA
    ULONGLONG   GuardEHContinuationCount;
    ULONGLONG   GuardXFGCheckFunctionPointer;               // VA
    ULONGLONG   GuardXFGDispatchFunctionPointer;            // VA
    ULONGLONG   GuardXFGTableDispatchFunctionPointer;       // VA
    ULONGLONG   CastGuardOsDeterminedFailureMode;           // VA
    ULONGLONG   GuardMemcpyFunctionPointer;                 // VA
    ULONGLONG   UmaFunctionPointers;                        // VA
} IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;

typedef struct _IMAGE_CHPE_METADATA_X86 {
    ULONG       Version;
    ULONG       CHPECodeAddressRangeOffset;
    ULONG       CHPECodeAddressRangeCount;
    ULONG       WowA64ExceptionHandlerFunctionPointer;
    ULONG       WowA64DispatchCallFunctionPointer;
    ULONG       WowA64DispatchIndirectCallFunctionPointer;
    ULONG       WowA64DispatchIndirectCallCfgFunctionPointer;
    ULONG       WowA64DispatchRetFunctionPointer;
    ULONG       WowA64DispatchRetLeafFunctionPointer;
    ULONG       WowA64DispatchJumpFunctionPointer;
    ULONG       CompilerIATPointer;                         // Present if Version >= 2
    ULONG       WowA64RdtscFunctionPointer;                 // Present if Version >= 3
} IMAGE_CHPE_METADATA_X86, *PIMAGE_CHPE_METADATA_X86;

typedef struct _IMAGE_CHPE_RANGE_ENTRY {
    union {
        ULONG   StartOffset;
        struct {
            ULONG   NativeCode : 1;
            ULONG   AddressBits : 31;
        };
    };
    ULONG Length;
} IMAGE_CHPE_RANGE_ENTRY, *PIMAGE_CHPE_RANGE_ENTRY;

typedef struct _IMAGE_ARM64EC_METADATA {
    ULONG       Version;
    ULONG       CodeMap;
    ULONG       CodeMapCount;
    ULONG       CodeRangesToEntryPoints;
    ULONG       RedirectionMetadata;
    ULONG       tbd__os_arm64x_dispatch_call_no_redirect;
    ULONG       tbd__os_arm64x_dispatch_ret;
    ULONG       tbd__os_arm64x_dispatch_call;
    ULONG       tbd__os_arm64x_dispatch_icall;
    ULONG       tbd__os_arm64x_dispatch_icall_cfg;
    ULONG       AlternateEntryPoint;
    ULONG       AuxiliaryIAT;
    ULONG       CodeRangesToEntryPointsCount;
    ULONG       RedirectionMetadataCount;
    ULONG       GetX64InformationFunctionPointer;
    ULONG       SetX64InformationFunctionPointer;
    ULONG       ExtraRFETable;
    ULONG       ExtraRFETableSize;
    ULONG       __os_arm64x_dispatch_fptr;
    ULONG       AuxiliaryIATCopy;
} IMAGE_ARM64EC_METADATA, *PIMAGE_ARM64EC_METADATA;

typedef struct _IMAGE_ARM64EC_METADATA_V2 {
    ULONG       Version;
    ULONG       CodeMap;
    ULONG       CodeMapCount;
    ULONG       CodeRangesToEntryPoints;
    ULONG       RedirectionMetadata;
    ULONG       tbd__os_arm64x_dispatch_call_no_redirect;
    ULONG       tbd__os_arm64x_dispatch_ret;
    ULONG       tbd__os_arm64x_dispatch_call;
    ULONG       tbd__os_arm64x_dispatch_icall;
    ULONG       tbd__os_arm64x_dispatch_icall_cfg;
    ULONG       AlternateEntryPoint;
    ULONG       AuxiliaryIAT;
    ULONG       CodeRangesToEntryPointsCount;
    ULONG       RedirectionMetadataCount;
    ULONG       GetX64InformationFunctionPointer;
    ULONG       SetX64InformationFunctionPointer;
    ULONG       ExtraRFETable;
    ULONG       ExtraRFETableSize;
    ULONG       __os_arm64x_dispatch_fptr;
    ULONG       AuxiliaryIATCopy;

    //
    // Below are V2-specific
    //
    ULONG       AuxDelayloadIAT;
    ULONG       AuxDelayloadIATCopy;
    ULONG       ReservedBitField;                           // reserved and unused by the linker
} IMAGE_ARM64EC_METADATA_V2, *PIMAGE_ARM64EC_METADATA_V2;

typedef struct _IMAGE_ARM64EC_REDIRECTION_ENTRY {
    ULONG       Source;
    ULONG       Destination;
} IMAGE_ARM64EC_REDIRECTION_ENTRY, *PIMAGE_ARM64EC_REDIRECTION_ENTRY;

typedef struct _IMAGE_ARM64EC_CODE_RANGE_ENTRY_POINT {
    ULONG       StartRva;
    ULONG       EndRva;
    ULONG       EntryPoint;
} IMAGE_ARM64EC_CODE_RANGE_ENTRY_POINT, *PIMAGE_ARM64EC_CODE_RANGE_ENTRY_POINT;

#define IMAGE_DVRT_ARM64X_FIXUP_TYPE_ZEROFILL   0
#define IMAGE_DVRT_ARM64X_FIXUP_TYPE_VALUE      1
#define IMAGE_DVRT_ARM64X_FIXUP_TYPE_DELTA      2

#define IMAGE_DVRT_ARM64X_FIXUP_SIZE_2BYTES     1
#define IMAGE_DVRT_ARM64X_FIXUP_SIZE_4BYTES     2
#define IMAGE_DVRT_ARM64X_FIXUP_SIZE_8BYTES     3

typedef struct _IMAGE_DVRT_ARM64X_FIXUP_RECORD {
    USHORT      Offset  : 12;
    USHORT      Type    :  2;
    USHORT      Size    :  2;
} IMAGE_DVRT_ARM64X_FIXUP_RECORD, *PIMAGE_DVRT_ARM64X_FIXUP_RECORD;

typedef struct _IMAGE_DVRT_ARM64X_DELTA_FIXUP_RECORD {
    USHORT      Offset  : 12;
    USHORT      Type    :  2;
    USHORT      Sign    :  1;
    USHORT      Scale   :  1;
} IMAGE_DVRT_ARM64X_DELTA_FIXUP_RECORD, *PIMAGE_DVRT_ARM64X_DELTA_FIXUP_RECORD;

typedef struct _IMAGE_HOT_PATCH_INFO {
    ULONG       Version;
    ULONG       Size;
    ULONG       SequenceNumber;
    ULONG       BaseImageList;
    ULONG       BaseImageCount;
    ULONG       BufferOffset;                               // Version 2 and later
    ULONG       ExtraPatchSize;                             // Version 3 and later
    ULONG       MinSequenceNumber;                          // Version 4 and later
    ULONG       Flags;                                      // Version 4 and later
} IMAGE_HOT_PATCH_INFO, *PIMAGE_HOT_PATCH_INFO;

typedef struct _IMAGE_HOT_PATCH_BASE {
    ULONG       SequenceNumber;
    ULONG       Flags;
    ULONG       OriginalTimeDateStamp;
    ULONG       OriginalCheckSum;
    ULONG       CodeIntegrityInfo;
    ULONG       CodeIntegritySize;
    ULONG       PatchTable;
    ULONG       BufferOffset;                               // V2 and later
} IMAGE_HOT_PATCH_BASE, *PIMAGE_HOT_PATCH_BASE;

typedef struct _IMAGE_HOT_PATCH_MACHINE {
    struct {
        ULONG   _x86     :  1;
        ULONG   Amd64    :  1;
        ULONG   Arm64    :  1;
        ULONG   Amd64EC  :  1;
    };
} IMAGE_HOT_PATCH_MACHINE, *PIMAGE_HOT_PATCH_MACHINE;

typedef struct _IMAGE_HOT_PATCH_HASHES {
    UCHAR       SHA256[32];
    UCHAR       SHA1[20];
} IMAGE_HOT_PATCH_HASHES, *PIMAGE_HOT_PATCH_HASHES;

#define IMAGE_HOT_PATCH_BASE_OBLIGATORY         0x00000001
#define IMAGE_HOT_PATCH_BASE_CAN_ROLL_BACK      0x00000002

#define IMAGE_HOT_PATCH_BASE_MACHINE_I386       0x00000004
#define IMAGE_HOT_PATCH_BASE_MACHINE_ARM64      0x00000008
#define IMAGE_HOT_PATCH_BASE_MACHINE_AMD64      0x00000010

#define IMAGE_HOT_PATCH_CHUNK_INVERSE           0x80000000
#define IMAGE_HOT_PATCH_CHUNK_OBLIGATORY        0x40000000
#define IMAGE_HOT_PATCH_CHUNK_RESERVED          0x3FF03000
#define IMAGE_HOT_PATCH_CHUNK_TYPE              0x000FC000
#define IMAGE_HOT_PATCH_CHUNK_SOURCE_RVA        0x00008000
#define IMAGE_HOT_PATCH_CHUNK_TARGET_RVA        0x00004000
#define IMAGE_HOT_PATCH_CHUNK_SIZE              0x00000FFF

enum IMAGE_HOT_PATCH {
    NONE                        = 0x00000000,
    FUNCTION                    = 0x0001C000,
    ABSOLUTE                    = 0x0002C000,
    REL32                       = 0x0003C000,
    CALL_TARGET                 = 0x00044000,
    INDIRECT                    = 0x0005C000,
    NO_CALL_TARGET              = 0x00064000,
    DYNAMIC_VALUE               = 0x00078000,
};

//
// GFIDS table entry flags.
//

#define IMAGE_GUARD_FLAG_FID_SUPPRESSED         0x01        // The containing GFID entry is suppressed
#define IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED      0x02        // The containing GFID entry is export suppressed
#define IMAGE_GUARD_FLAG_FID_LANGEXCPTHANDLER   0x04
#define IMAGE_GUARD_FLAG_FID_XFG                0x08

//
// WIN CE Exception table format
//

//
// Function table entry format.  Function table is pointed to by the
// IMAGE_DIRECTORY_ENTRY_EXCEPTION directory entry.
//

typedef struct _IMAGE_CE_RUNTIME_FUNCTION_ENTRY {
    ULONG       FuncStart;
    ULONG       PrologLen : 8;
    ULONG       FuncLen : 22;
    ULONG       ThirtyTwoBit : 1;
    ULONG       ExceptionFlag : 1;
} IMAGE_CE_RUNTIME_FUNCTION_ENTRY, *PIMAGE_CE_RUNTIME_FUNCTION_ENTRY;

typedef struct _IMAGE_ARM_RUNTIME_FUNCTION_ENTRY {
    ULONG       BeginAddress;
    union {
        ULONG   UnwindData;
        struct {
            ULONG   Flag : 2;
            ULONG   FunctionLength : 11;
            ULONG   Ret : 2;
            ULONG   H : 1;
            ULONG   Reg : 3;
            ULONG   R : 1;
            ULONG   L : 1;
            ULONG   C : 1;
            ULONG   StackAdjust : 10;
        };
    };
} IMAGE_ARM_RUNTIME_FUNCTION_ENTRY, *PIMAGE_ARM_RUNTIME_FUNCTION_ENTRY;

enum ARM64_FNPDATA_FLAGS {
    PdataRefToFullXdata         = 0,
    PdataPackedUnwindFunction   = 1,
    PdataPackedUnwindFragment   = 2,
};

enum ARM64_FNPDATA_CR {
    PdataCrUnchained            = 0,
    PdataCrUnchainedSavedLr     = 1,
    PdataCrChainedWithPac       = 2,
    PdataCrChained              = 3,
};

typedef struct _IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY {
    ULONG       BeginAddress;
    union {
        ULONG   UnwindData;
        struct {
            ULONG   Flag : 2;
            ULONG   FunctionLength : 11;
            ULONG   RegF : 3;
            ULONG   RegI : 4;
            ULONG   H : 1;
            ULONG   CR : 2;
            ULONG   FrameSize : 9;
        };
    };
} IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY, *PIMAGE_ARM64_RUNTIME_FUNCTION_ENTRY;

typedef union _IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA {
    ULONG       HeaderData;
    struct {
        ULONG       FunctionLength : 18;        // in words (2 bytes)
        ULONG       Version : 2;
        ULONG       ExceptionDataPresent : 1;
        ULONG       EpilogInHeader : 1;
        ULONG       EpilogCount : 5;            // number of epilogs or byte index of the first unwind code for the one only epilog
        ULONG       CodeWords : 5;              // number of dwords with unwind codes
    };
} IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA, *PIMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA;

typedef union IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA_EXTENDED {
    ULONG       ExtendedHeaderData;
    struct {
        ULONG       ExtendedEpilogCount : 16;
        ULONG       ExtendedCodeWords : 8;
    };
} IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA_EXTENDED, *PIMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA_EXTENDED;

typedef union IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA_EPILOG_SCOPE {
    ULONG       EpilogScopeData;
    struct {
        ULONG       EpilogStartOffset : 18;     // offset in bytes, divided by 4, of the epilog relative to the start of the function.
        ULONG       Res0: 4;
        ULONG       EpilogStartIndex : 10;      // byte index of the first unwind code that describes this epilog.
    };
} IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA_EPILOG_SCOPE, *PIMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA_EPILOG_SCOPE;

typedef struct _IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY {
    ULONGLONG   BeginAddress;
    ULONGLONG   EndAddress;
    ULONGLONG   ExceptionHandler;
    ULONGLONG   HandlerData;
    ULONGLONG   PrologEndAddress;
} IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY, *PIMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY;

typedef struct _IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY {
    ULONG       BeginAddress;
    ULONG       EndAddress;
    ULONG       ExceptionHandler;
    ULONG       HandlerData;
    ULONG       PrologEndAddress;
} IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY, *PIMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY;

typedef struct _IMAGE_MIPS_RUNTIME_FUNCTION_ENTRY {
    ULONG       BeginAddress;
    ULONG       EndAddress;
    ULONG       ExceptionHandler;
    ULONG       HandlerData;
    ULONG       PrologEndAddress;
} IMAGE_MIPS_RUNTIME_FUNCTION_ENTRY, *PIMAGE_MIPS_RUNTIME_FUNCTION_ENTRY;

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
    ULONG       BeginAddress;
    ULONG       EndAddress;
    union {
        ULONG   UnwindInfoAddress;
        ULONG   UnwindData;
    };
} IMAGE_RUNTIME_FUNCTION_ENTRY, *PIMAGE_RUNTIME_FUNCTION_ENTRY;

//
// Sofware enclave information
//

#define IMAGE_ENCLAVE_LONG_ID_LENGTH            ENCLAVE_LONG_ID_LENGTH
#define IMAGE_ENCLAVE_SHORT_ID_LENGTH           ENCLAVE_SHORT_ID_LENGTH

typedef struct _IMAGE_ENCLAVE_CONFIG32 {
    ULONG       Size;
    ULONG       MinimumRequiredConfigSize;
    ULONG       PolicyFlags;
    ULONG       NumberOfImports;
    ULONG       ImportList;
    ULONG       ImportEntrySize;
    UCHAR       FamilyID[IMAGE_ENCLAVE_SHORT_ID_LENGTH];
    UCHAR       ImageID[IMAGE_ENCLAVE_SHORT_ID_LENGTH];
    ULONG       ImageVersion;
    ULONG       SecurityVersion;
    ULONG       EnclaveSize;
    ULONG       NumberOfThreads;
    ULONG       EnclaveFlags;
} IMAGE_ENCLAVE_CONFIG32, *PIMAGE_ENCLAVE_CONFIG32;

typedef struct _IMAGE_ENCLAVE_CONFIG64 {
    ULONG       Size;
    ULONG       MinimumRequiredConfigSize;
    ULONG       PolicyFlags;
    ULONG       NumberOfImports;
    ULONG       ImportList;
    ULONG       ImportEntrySize;
    UCHAR       FamilyID[IMAGE_ENCLAVE_SHORT_ID_LENGTH];
    UCHAR       ImageID[IMAGE_ENCLAVE_SHORT_ID_LENGTH];
    ULONG       ImageVersion;
    ULONG       SecurityVersion;
    ULONGLONG   EnclaveSize;
    ULONG       NumberOfThreads;
    ULONG       EnclaveFlags;
} IMAGE_ENCLAVE_CONFIG64, *PIMAGE_ENCLAVE_CONFIG64;

#define IMAGE_ENCLAVE_POLICY_DEBUGGABLE         0x00000001
#define IMAGE_ENCLAVE_POLICY_STRICT_MEMORY      0x00000002

#define IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE        0x00000001

typedef struct _IMAGE_ENCLAVE_IMPORT {
    ULONG       MatchType;
    ULONG       MinimumSecurityVersion;
    UCHAR       UniqueOrAuthorID[IMAGE_ENCLAVE_LONG_ID_LENGTH];
    UCHAR       FamilyID[IMAGE_ENCLAVE_SHORT_ID_LENGTH];
    UCHAR       ImageID[IMAGE_ENCLAVE_SHORT_ID_LENGTH];
    ULONG       ImportName;
    ULONG       Reserved;
} IMAGE_ENCLAVE_IMPORT, *PIMAGE_ENCLAVE_IMPORT;

#define IMAGE_ENCLAVE_IMPORT_MATCH_NONE         0x00000000
#define IMAGE_ENCLAVE_IMPORT_MATCH_UNIQUE_ID    0x00000001
#define IMAGE_ENCLAVE_IMPORT_MATCH_AUTHOR_ID    0x00000002
#define IMAGE_ENCLAVE_IMPORT_MATCH_FAMILY_ID    0x00000003
#define IMAGE_ENCLAVE_IMPORT_MATCH_IMAGE_ID     0x00000004

//
// Security Format
//

#define WIN_CERT_REVISION_1_0                   0x0100
#define WIN_CERT_REVISION_2_0                   0x0200

enum WIN_CERT_TYPE : USHORT {
    X509                        = 0x0001,       // bCertificate contains an X.509 Certificate
    PKCS_SIGNED_DATA            = 0x0002,       // bCertificate contains a PKCS SignedData structure
    RESERVED_1                  = 0x0003,       // Reserved
    TS_STACK_SIGNED             = 0x0004,       // Terminal Server Protocol Stack Certificate signing
};

typedef struct _WIN_CERTIFICATE {
    ULONG       dwLength;
    USHORT      wRevision;
    WIN_CERT_TYPE   wCertificateType;
    CHAR        bCertificate[dwLength - 8];
} WIN_CERTIFICATE, *PWIN_CERTIFICATE;

//
// Debug Format
//

enum IMAGE_DEBUG_TYPE : ULONG {
    UNKNOWN                     = 0,            // An unknown value that is ignored by all tools.
    COFF                        = 1,            // The COFF debug information (line numbers, symbol table, and string table). This type of debug information is also pointed to by fields in the file headers.
    CODEVIEW                    = 2,            // The Visual C++ debug information.
    FPO                         = 3,            // The frame pointer omission (FPO) information. This information tells the debugger how to interpret nonstandard stack frames, which use the EBP register for a purpose other than as a frame pointer.
    MISC                        = 4,            // The location of DBG file.
    EXCEPTION                   = 5,            // A copy of .pdata section.
    FIXUP                       = 6,            // Reserved.
    OMAP_TO_SRC                 = 7,            // The mapping from an RVA in image to an RVA in source image.
    OMAP_FROM_SRC               = 8,            // The mapping from an RVA in source image to an RVA in image.
    BORLAND                     = 9,            // Reserved for Borland.
    RESERVED10                  = 10,           // Reserved.
    BBT                         = 10,
    CLSID                       = 11,           // Reserved.
    VC_FEATURE                  = 12,
    POGO                        = 13,
    ILTCG                       = 14,
    MPX                         = 15,
    REPRO                       = 16,           // PE determinism or reproducibility.
    EMBEDDED_PORTABLE_PDB       = 17,           // Debugging information is embedded in the PE file at location specified by PointerToRawData.
    SPGO                        = 18,
    PDBCHECKSUM                 = 19,           // Stores crypto hash for the content of the symbol file used to build the PE/COFF file.
    EX_DLLCHARACTERISTICS       = 20,           // Extended DLL characteristics bits.
    PERFMAP                     = 21,
};

flag IMAGE_DLLCHARACTERISTICS_EX {
    CET_COMPAT                  = 0x01,
    CET_COMPAT_STRICT_MODE      = 0x02,
    CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE  = 0x04,
    CET_DYNAMIC_APIS_ALLOW_IN_PROC  = 0x08,
    CET_RESERVED_1              = 0x10,
    CET_RESERVED_2              = 0x20,
    FORWARD_CFI_COMPAT          = 0x40,
    HOTPATCH_COMPATIBLE         = 0x80,
};

typedef struct _IMAGE_DEBUG_DIRECTORY {
    ULONG       Characteristics;
    ULONG       TimeDateStamp;
    USHORT      MajorVersion;
    USHORT      MinorVersion;
    IMAGE_DEBUG_TYPE    Type;
    ULONG       SizeOfData;
    ULONG       AddressOfRawData;
    ULONG       PointerToRawData;
} IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

typedef struct _IMAGE_COFF_SYMBOLS_HEADER {
    ULONG       NumberOfSymbols;
    ULONG       LvaToFirstSymbol;
    ULONG       NumberOfLinenumbers;
    ULONG       LvaToFirstLinenumber;
    ULONG       RvaToFirstByteOfCode;
    ULONG       RvaToLastByteOfCode;
    ULONG       RvaToFirstByteOfData;
    ULONG       RvaToLastByteOfData;
} IMAGE_COFF_SYMBOLS_HEADER, *PIMAGE_COFF_SYMBOLS_HEADER;

#define CVINFO_PDB70_CVSIGNATURE                0x53445352  // "RSDS"
#define CVINFO_PDB20_CVSIGNATURE                0x3031424e  // "NB10"
#define CVINFO_CV50_CVSIGNATURE                 0x3131424e  // "NB11"
#define CVINFO_CV41_CVSIGNATURE                 0x3930424e  // "NB09"
#define CVINFO_MTOC_CVSIGNATURE                 0x434f544d  // "MTOC"

typedef struct _CV_HEADER {
    ULONG       Signature;
    ULONG       Offset;
} CV_HEADER, *PCV_HEADER;

typedef struct _CV_INFO_PDB20 {
    CV_HEADER   CvHeader;
    ULONG       Signature;
    ULONG       Age;
    CHAR        PdbFileName[];
} CV_INFO_PDB20, *PCV_INFO_PDB20;

typedef struct _CV_INFO_PDB70 {
    ULONG       CvSignature;
    CHAR        Signature[16];
    ULONG       Age;
    CHAR        PdbFileName[];
} CV_INFO_PDB70, *PCV_INFO_PDB70;

typedef struct _CV_INFO_MTOC {
  ULONG         CvSignature;
  BYTE          Signature[16];
  BYTE          PdbFileName[1];
} CV_INFO_MTOC, *PCV_INFO_MTOC;

#define FRAME_FPO       0
#define FRAME_TRAP      1
#define FRAME_TSS       2
#define FRAME_NONFPO    3

typedef struct _FPO_DATA {
    ULONG       ulOffStart;                     // offset 1st byte of function code
    ULONG       cbProcSize;                     // # bytes in function
    ULONG       cdwLocals;                      // # bytes in locals/4
    USHORT      cdwParams;                      // # bytes in params/4
    USHORT      cbProlog : 8;                   // # bytes in prolog
    USHORT      cbRegs   : 3;                   // # regs saved
    USHORT      fHasSEH  : 1;                   // TRUE if SEH in func
    USHORT      fUseBP   : 1;                   // TRUE if EBP has been allocated
    USHORT      reserved : 1;                   // reserved for future use
    USHORT      cbFrame  : 2;                   // frame type
} FPO_DATA, *PFPO_DATA;

#define IMAGE_DEBUG_MISC_EXENAME                1

typedef struct _IMAGE_DEBUG_MISC {
    ULONG       DataType;                       // type of misc data, see defines
    ULONG       Length;                         // total length of record, rounded to four
                                                // byte multiple.
    BOOLEAN     Unicode;                        // TRUE if data is unicode string
    UCHAR       Reserved[ 3 ];
//  UCHAR       Data[ 1 ];                      // Actual data
} IMAGE_DEBUG_MISC, *PIMAGE_DEBUG_MISC;

#define IMAGE_DEBUG_POGO_SIGNATURE_ZERO         0x00000000
#define IMAGE_DEBUG_POGO_SIGNATURE_LTCG         0x4C544347
#define IMAGE_DEBUG_POGO_SIGNATURE_PGU          0x50475500

typedef struct _VC_FEATURE {
    ULONG       PreVC11;
    ULONG       CCpp;
    ULONG       Gs;
    ULONG       Sdl;
    ULONG       GuardN;
} VC_FEATURE, *PVC_FEATURE;

//
// Function table extracted from MIPS/ALPHA/IA64 images.  Does not contain
// information needed only for runtime support.  Just those fields for
// each entry needed by a debugger.
//

typedef struct _IMAGE_FUNCTION_ENTRY {
    ULONG       StartingAddress;
    ULONG       EndingAddress;
    ULONG       EndOfPrologue;
} IMAGE_FUNCTION_ENTRY, *PIMAGE_FUNCTION_ENTRY;

typedef struct _IMAGE_FUNCTION_ENTRY64 {
    ULONGLONG   StartingAddress;
    ULONGLONG   EndingAddress;
    union {
        ULONGLONG   EndOfPrologue;
        ULONGLONG   UnwindInfoAddress;
    };
} IMAGE_FUNCTION_ENTRY64, *PIMAGE_FUNCTION_ENTRY64;

//
// Debugging information can be stripped from an image file and placed
// in a separate .DBG file, whose file name part is the same as the
// image file name part (e.g. symbols for CMD.EXE could be stripped
// and placed in CMD.DBG).  This is indicated by the IMAGE_FILE_DEBUG_STRIPPED
// flag in the Characteristics field of the file header.  The beginning of
// the .DBG file contains the following structure which captures certain
// information from the image file.  This allows a debug to proceed even if
// the original image file is not accessable.  This header is followed by
// zero of more IMAGE_SECTION_HEADER structures, followed by zero or more
// IMAGE_DEBUG_DIRECTORY structures.  The latter structures and those in
// the image file contain file offsets relative to the beginning of the
// .DBG file.
//
// If symbols have been stripped from an image, the IMAGE_DEBUG_MISC structure
// is left in the image file, but not mapped.  This allows a debugger to
// compute the name of the .DBG file, from the name of the image in the
// IMAGE_DEBUG_MISC structure.
//

typedef struct _IMAGE_SEPARATE_DEBUG_HEADER {
    USHORT      Signature;
    USHORT      Flags;
    USHORT      Machine;
    USHORT      Characteristics;
    ULONG       TimeDateStamp;
    ULONG       CheckSum;
    ULONG       ImageBase;
    ULONG       SizeOfImage;
    ULONG       NumberOfSections;
    ULONG       ExportedNamesSize;
    ULONG       DebugDirectorySize;
    ULONG       SectionAlignment;
    ULONG       Reserved[2];
} IMAGE_SEPARATE_DEBUG_HEADER, *PIMAGE_SEPARATE_DEBUG_HEADER;

typedef struct _NON_PAGED_DEBUG_INFO {
    USHORT      Signature;
    USHORT      Flags;
    ULONG       Size;
    USHORT      Machine;
    USHORT      Characteristics;
    ULONG       TimeDateStamp;
    ULONG       CheckSum;
    ULONG       SizeOfImage;
    ULONGLONG   ImageBase;
    //DebugDirectorySize
    //IMAGE_DEBUG_DIRECTORY
} NON_PAGED_DEBUG_INFO, *PNON_PAGED_DEBUG_INFO;

#define IMAGE_SEPARATE_DEBUG_SIGNATURE          0x4449      // DI
#define NON_PAGED_DEBUG_SIGNATURE               0x4E49      // NI

#define IMAGE_SEPARATE_DEBUG_FLAGS_MASK         0x8000
#define IMAGE_SEPARATE_DEBUG_MISMATCH           0x8000      // when DBG was updated, the
                                                            // old checksum didn't match.

//
//  The .arch section is made up of headers, each describing an amask position/value
//  pointing to an array of IMAGE_ARCHITECTURE_ENTRY's.  Each "array" (both the header
//  and entry arrays) are terminiated by a quadword of 0xffffffffL.
//
//  NOTE: There may be quadwords of 0 sprinkled around and must be skipped.
//

typedef struct _ImageArchitectureHeader {
    unsigned int    AmaskValue: 1;              // 1 -> code section depends on mask bit
                                                // 0 -> new instruction depends on mask bit
    int _:7;                                    // MBZ
    unsigned int    AmaskShift: 8;              // Amask bit in question for this fixup
    int _:16;                                   // MBZ
    ULONG           FirstEntryRVA;              // RVA into .arch section to array of ARCHITECTURE_ENTRY's
} IMAGE_ARCHITECTURE_HEADER, *PIMAGE_ARCHITECTURE_HEADER;

typedef struct _ImageArchitectureEntry {
    ULONG       FixupInstRVA;                   // RVA of instruction to fixup
    ULONG       NewInst;                        // fixup instruction (see alphaops.h)
} IMAGE_ARCHITECTURE_ENTRY, *PIMAGE_ARCHITECTURE_ENTRY;

// The following structure defines the new import object.  Note the values of the first two fields,
// which must be set as stated in order to differentiate old and new import members.
// Following this structure, the linker emits two null-terminated strings used to recreate the
// import at the time of use.  The first string is the import's name, the second is the dll's name.

#define IMPORT_OBJECT_HDR_SIG2                  0xffff

enum IMPORT_OBJECT_TYPE {
    IMPORT_OBJECT_CODE          = 0,
    IMPORT_OBJECT_DATA          = 1,
    IMPORT_OBJECT_CONST         = 2,
};

enum IMPORT_OBJECT_NAME_TYPE {
    IMPORT_OBJECT_ORDINAL       = 0,            // Import by ordinal
    IMPORT_OBJECT_NAME          = 1,            // Import name == public symbol name.
    IMPORT_OBJECT_NAME_NO_PREFIX    = 2,        // Import name == public symbol name skipping leading ?, @, or optionally _.
    IMPORT_OBJECT_NAME_UNDECORATE   = 3,        // Import name == public symbol name skipping leading ?, @, or optionally _
                                                //  and truncating at first @.
    IMPORT_OBJECT_NAME_EXPORTAS     = 4,        // Import name == a name is explicitly provided after the DLL name.
};

typedef struct IMPORT_OBJECT_HEADER {
    USHORT      Sig1;                           // Must be IMAGE_FILE_MACHINE_UNKNOWN
    USHORT      Sig2;                           // Must be IMPORT_OBJECT_HDR_SIG2.
    USHORT      Version;
    USHORT      Machine;
    ULONG       TimeDateStamp;                  // Time/date stamp
    ULONG       SizeOfData;                     // particularly useful for incremental links

    union {
        USHORT  Ordinal;                        // if grf & IMPORT_OBJECT_ORDINAL
        USHORT  Hint;
    };

    IMPORT_OBJECT_TYPE  Type : 2;               // IMPORT_TYPE
    IMPORT_OBJECT_NAME_TYPE NameType : 3;       // IMPORT_NAME_TYPE
    USHORT      Reserved : 11;                  // Reserved. Must be zero.
} IMPORT_OBJECT_HEADER, *PIMPORT_OBJECT_HEADER;

//
// COM Format.
//

// COM+ Header entry point flags.
flag COMIMAGE_FLAGS : ULONG {
    ILONLY                      = 0x00000001,
    32BITREQUIRED               = 0x00000002,
    IL_LIBRARY                  = 0x00000004,
    STRONGNAMESIGNED            = 0x00000008,
    NATIVE_ENTRYPOINT           = 0x00000010,
    TRACKDEBUGDATA              = 0x00010000,
    32BITPREFERRED              = 0x00020000
};

// Version flags for image.
#define COR_VERSION_MAJOR_V2                    2
#define COR_VERSION_MAJOR                       COR_VERSION_MAJOR_V2
#define COR_VERSION_MINOR                       5
#define COR_DELETED_NAME_LENGTH                 8
#define COR_VTABLEGAP_NAME_LENGTH               8

// Maximum size of a NativeType descriptor.
#define NATIVE_TYPE_MAX_CB                      1
#define COR_ILMETHOD_SECT_SMALL_MAX_DATASIZE    0xFF

// #defines for the MIH FLAGS
#define IMAGE_COR_MIH_METHODRVA                 0x01
#define IMAGE_COR_MIH_EHRVA                     0x02
#define IMAGE_COR_MIH_BASICBLOCK                0x08

// V-table constants
#define COR_VTABLE_32BIT                        0x01        // V-table slots are 32-bits in size.
#define COR_VTABLE_64BIT                        0x02        // V-table slots are 64-bits in size.
#define COR_VTABLE_FROM_UNMANAGED               0x04        // If set, transition from unmanaged.
#define COR_VTABLE_FROM_UNMANAGED_RETAIN_APPDOMAIN  0x08    // If set, transition from unmanaged with keeping the current appdomain.
#define COR_VTABLE_CALL_MOST_DERIVED            0x10        // Call most derived method described by

// EATJ constants
#define IMAGE_COR_EATJ_THUNK_SIZE               32          // Size of a jump thunk reserved range.

// Max name lengths
#define MAX_CLASS_NAME                          1024
#define MAX_PACKAGE_NAME                        1024

// CLR 2.0 header structure.
typedef struct _IMAGE_COR20_HEADER {
    // Header versioning
    ULONG                   cb;
    USHORT                  MajorRuntimeVersion;
    USHORT                  MinorRuntimeVersion;

    // Symbol table and startup information
    IMAGE_DATA_DIRECTORY    MetaData;
    ULONG                   Flags;

    // If COMIMAGE_FLAGS_NATIVE_ENTRYPOINT is not set, EntryPointToken represents a managed entrypoint.
    // If COMIMAGE_FLAGS_NATIVE_ENTRYPOINT is set, EntryPointRVA represents an RVA to a native entrypoint.
    union {
        ULONG               EntryPointToken;
        ULONG               EntryPointRVA;
    };

    // Binding information
    IMAGE_DATA_DIRECTORY    Resources;
    IMAGE_DATA_DIRECTORY    StrongNameSignature;

    // Regular fixup and binding information
    IMAGE_DATA_DIRECTORY    CodeManagerTable;
    IMAGE_DATA_DIRECTORY    VTableFixups;
    IMAGE_DATA_DIRECTORY    ExportAddressTableJumps;

    // Precompiled image info (internal use only - set to zero)
    IMAGE_DATA_DIRECTORY    ManagedNativeHeader;
} IMAGE_COR20_HEADER, *PIMAGE_COR20_HEADER;

typedef struct _IMAGE_COR20_METADATA {
    ULONG       Magic;
    USHORT      MajorVersion;
    USHORT      MinorVersion;
    ULONG       Reserved;
    ULONG       Length;
    CHAR        Version[Length];
    USHORT      Flags;
    USHORT      NumberOfStreams;
} IMAGE_COR20_METADATA, *PIMAGE_COR20_METADATA;

typedef struct _IMAGE_COR20_STREAM_HEADER {
    ULONG       Offset;
    ULONG       Size;
    CHAR        Name[];
} IMAGE_COR20_STREAM_HEADER, *PIMAGE_COR20_STREAM_HEADER;
"""  # noqa: E501

c_pe = cstruct().load(c_pe_def)
