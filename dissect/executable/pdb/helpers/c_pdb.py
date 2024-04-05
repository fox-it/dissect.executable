from dissect.cstruct import cstruct

pdb_def = """
/////////////////////////////////////////////////////////////////////////
// PDB generic definitions
/////////////////////////////////////////////////////////////////////////
typedef uint32 OFF;
typedef uint32 CB;
typedef uint16 SN;

typedef uint32 CV_typ_t;
typedef CV_typ_t TI;
typedef ushort CV_typ16_t;

struct OffCb {              // offset, cb pair
    OFF off;
    CB  cb;
};

struct CV_funcattr_t {
    uint8  cxxreturnudt :1;  // true if C++ style ReturnUDT
    uint8  ctor         :1;  // true if func is an instance constructor
    uint8  ctorvbase    :1;  // true if func is an instance constructor of a class with virtual bases
    uint8  unused       :5;  // unused
};

struct DATA_STREAM_V7 {
    uint32 stream_size;
};

struct ROOT_STREAM_V7 {
    uint32 dStreams;
    DATA_STREAM_V7 streamLengths[dStreams];
};

struct PDB7_HEADER {
    char signature[32];
    uint32 page_size;
    uint32 alloc_table_ptr;
    uint32 num_file_pages;
    uint32 root_size;
    uint32 reserved;
    uint32 root_page_index;
};

struct DATA_STREAM_V2 {
    uint32 stream_size;
    uint32 reserved;
};

struct ROOT_STREAM_V2 {
  uint16 dStreams;
  uint16 reserved;
  DATA_STREAM_V2 streamLengths[dStreams]; // array of page numbers
};

struct PDB2_HEADER {
    char signature[44];
    uint32 page_size;
    uint16 start_page;
    uint16 num_file_pages;
    uint32 root_size;
    uint32 reserved;
};

struct PORTABLE_PDB_HEADER {
    char signature[4];
    uint16 majorVersion;
    uint16 minorVersion;
    uint32 reserved;
    uint32 versionLength;
    char version[versionLength];
};

/////////////////////////////////////////////////////////////////////////
// TPI specific definitions
//
// General overview: https://github.com/microsoft/microsoft-pdb/blob/master/PDB/dbi/tpi.h
/////////////////////////////////////////////////////////////////////////

enum TPIIMPV {
    impv40 = 19950410,
    impv41 = 19951122,
    impv50Interim = 19960307,
    impv50 = 19961031,
    impv70 = 19990903,
    impv80 = 20040203,
};

struct TpiHash {
    SN      sn;             // main hash stream
    SN      snPad;          // auxilliary hash data if necessary
    CB      cbHashKey;      // size of hash key
    uint32  cHashBuckets;   // how many buckets we have
    OffCb   offcbHashVals;  // offcb of hashvals
    OffCb   offcbTiOff;     // offcb of (TI,OFF) pairs
    OffCb   offcbHashAdj;   // offcb of hash head list, maps (hashval,ti), where ti is the head of the hashval chain.
};

struct TpiHeader {          // type database header:
    TPIIMPV vers;           // version which created this TypeServer
    CB      cbHdr;          // size of the header, allows easier upgrading and backwards compatibility
    TI      tiMin;          // lowest TI
    TI      tiMax;          // highest TI + 1
    CB      cbGprec;        // count of bytes used by the gprec which follows.
    TpiHash tpihash;        // hash stream schema
};

struct TpiType {
    uint16 length;
    char type_data[length];
};

// Typing
// https://github.com/microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/include/cvinfo.h
//

enum LEAF_ENUM_e : uint16 {
    // leaf indices starting records but referenced from symbol records

    LF_MODIFIER_16t     = 0x01,
    LF_POINTER_16t      = 0x02,
    LF_ARRAY_16t        = 0x03,
    LF_CLASS_16t        = 0x04,
    LF_STRUCTURE_16t    = 0x05,
    LF_UNION_16t        = 0x06,
    LF_ENUM_16t         = 0x07,
    LF_PROCEDURE_16t    = 0x08,
    LF_MFUNCTION_16t    = 0x09,
    LF_VTSHAPE          = 0x0a,
    LF_COBOL0_16t       = 0x0b,
    LF_COBOL1           = 0x0c,
    LF_BARRAY_16t       = 0x0d,
    LF_LABEL            = 0x0e,
    LF_NULL             = 0x0f,
    LF_NOTTRAN          = 0x10,
    LF_DIMARRAY_16t     = 0x11,
    LF_VFTPATH_16t      = 0x12,
    LF_PRECOMP_16t      = 0x13,       // not referenced from symbol
    LF_ENDPRECOMP       = 0x14,       // not referenced from symbol
    LF_OEM_16t          = 0x15,       // oem definable type string
    LF_TYPESERVER_ST    = 0x16,       // not referenced from symbol

    // leaf indices starting records but referenced only from type records

    LF_SKIP_16t         = 0x0200,
    LF_ARGLIST_16t      = 0x0201,
    LF_DEFARG_16t       = 0x0202,
    LF_LIST             = 0x0203,
    LF_FIELDLIST_16t    = 0x0204,
    LF_DERIVED_16t      = 0x0205,
    LF_BITFIELD_16t     = 0x0206,
    LF_METHODLIST_16t   = 0x0207,
    LF_DIMCONU_16t      = 0x0208,
    LF_DIMCONLU_16t     = 0x0209,
    LF_DIMVARU_16t      = 0x020a,
    LF_DIMVARLU_16t     = 0x020b,
    LF_REFSYM           = 0x020c,

    LF_BCLASS_16t       = 0x0400,
    LF_VBCLASS_16t      = 0x0401,
    LF_IVBCLASS_16t     = 0x0402,
    LF_ENUMERATE_ST     = 0x0403,
    LF_FRIENDFCN_16t    = 0x0404,
    LF_INDEX_16t        = 0x0405,
    LF_MEMBER_16t       = 0x0406,
    LF_STMEMBER_16t     = 0x0407,
    LF_METHOD_16t       = 0x0408,
    LF_NESTTYPE_16t     = 0x0409,
    LF_VFUNCTAB_16t     = 0x040a,
    LF_FRIENDCLS_16t    = 0x040b,
    LF_ONEMETHOD_16t    = 0x040c,
    LF_VFUNCOFF_16t     = 0x040d,

// 32-bit type index versions of leaves, all have the 0x1000 bit set

    LF_TI16_MAX         = 0x1000,
    LF_MODIFIER         = 0x1001,
    LF_POINTER          = 0x1002,
    LF_ARRAY_ST         = 0x1003,
    LF_CLASS_ST         = 0x1004,
    LF_STRUCTURE_ST     = 0x1005,
    LF_UNION_ST         = 0x1006,
    LF_ENUM_ST          = 0x1007,
    LF_PROCEDURE        = 0x1008,
    LF_MFUNCTION        = 0x1009,
    LF_COBOL0           = 0x100a,
    LF_BARRAY           = 0x100b,
    LF_DIMARRAY_ST      = 0x100c,
    LF_VFTPATH          = 0x100d,
    LF_PRECOMP_ST       = 0x100e,       // not referenced from symbol
    LF_OEM              = 0x100f,       // oem definable type string
    LF_ALIAS_ST         = 0x1010,       // alias (typedef) type
    LF_OEM2             = 0x1011,       // oem definable type string

    // leaf indices starting records but referenced only from type records

    LF_SKIP             = 0x1200,
    LF_ARGLIST          = 0x1201,
    LF_DEFARG_ST        = 0x1202,
    LF_FIELDLIST        = 0x1203,
    LF_DERIVED          = 0x1204,
    LF_BITFIELD         = 0x1205,
    LF_METHODLIST       = 0x1206,
    LF_DIMCONU          = 0x1207,
    LF_DIMCONLU         = 0x1208,
    LF_DIMVARU          = 0x1209,
    LF_DIMVARLU         = 0x120a,

    LF_BCLASS           = 0x1400,
    LF_VBCLASS          = 0x1401,
    LF_IVBCLASS         = 0x1402,
    LF_FRIENDFCN_ST     = 0x1403,
    LF_INDEX            = 0x1404,
    LF_MEMBER_ST        = 0x1405,
    LF_STMEMBER_ST      = 0x1406,
    LF_METHOD_ST        = 0x1407,
    LF_NESTTYPE_ST      = 0x1408,
    LF_VFUNCTAB         = 0x1409,
    LF_FRIENDCLS        = 0x140a,
    LF_ONEMETHOD_ST     = 0x140b,
    LF_VFUNCOFF         = 0x140c,
    LF_NESTTYPEEX_ST    = 0x140d,
    LF_MEMBERMODIFY_ST  = 0x140e,
    LF_MANAGED_ST       = 0x140f,

    // Types w/ SZ names

    LF_ST_MAX           = 0x1500,
    LF_TYPESERVER       = 0x1501,       // not referenced from symbol
    LF_ENUMERATE        = 0x1502,
    LF_ARRAY            = 0x1503,
    LF_CLASS            = 0x1504,
    LF_STRUCTURE        = 0x1505,
    LF_UNION            = 0x1506,
    LF_ENUM             = 0x1507,
    LF_DIMARRAY         = 0x1508,
    LF_PRECOMP          = 0x1509,       // not referenced from symbol
    LF_ALIAS            = 0x150a,       // alias (typedef) type
    LF_DEFARG           = 0x150b,
    LF_FRIENDFCN        = 0x150c,
    LF_MEMBER           = 0x150d,
    LF_STMEMBER         = 0x150e,
    LF_METHOD           = 0x150f,
    LF_NESTTYPE         = 0x1510,
    LF_ONEMETHOD        = 0x1511,
    LF_NESTTYPEEX       = 0x1512,
    LF_MEMBERMODIFY     = 0x1513,
    LF_MANAGED          = 0x1514,
    LF_TYPESERVER2      = 0x1515,

    LF_STRIDED_ARRAY    = 0x1516,    // same as LF_ARRAY, but with stride between adjacent elements
    LF_HLSL             = 0x1517,
    LF_MODIFIER_EX      = 0x1518,
    LF_INTERFACE        = 0x1519,
    LF_BINTERFACE       = 0x151a,
    LF_VECTOR           = 0x151b,
    LF_MATRIX           = 0x151c,

    LF_VFTABLE          = 0x151d,      // a virtual function table
    // LF_ENDOFLEAFRECORD  = LF_VFTABLE,

    // LF_TYPE_LAST,                    // one greater than the last type record
    // LF_TYPE_MAX         = LF_TYPE_LAST - 1,

    LF_FUNC_ID          = 0x1601,    // global func ID
    LF_MFUNC_ID         = 0x1602,    // member func ID
    LF_BUILDINFO        = 0x1603,    // build info: tool, version, command line, src/pdb file
    LF_SUBSTR_LIST      = 0x1604,    // similar to LF_ARGLIST, for list of sub strings
    LF_STRING_ID        = 0x1605,    // string ID

    LF_UDT_SRC_LINE     = 0x1606,    // source and line on where an UDT is defined
                                     // only generated by compiler

    LF_UDT_MOD_SRC_LINE = 0x1607,    // module, source and line on where an UDT is defined
                                     // only generated by linker

    // LF_ID_LAST,                      // one greater than the last ID record
    // LF_ID_MAX           = LF_ID_LAST - 1,

    LF_NUMERIC          = 0x8000,
    LF_CHAR             = 0x8000,
    LF_SHORT            = 0x8001,
    LF_USHORT           = 0x8002,
    LF_LONG             = 0x8003,
    LF_ULONG            = 0x8004,
    LF_REAL32           = 0x8005,
    LF_REAL64           = 0x8006,
    LF_REAL80           = 0x8007,
    LF_REAL128          = 0x8008,
    LF_QUADWORD         = 0x8009,
    LF_UQUADWORD        = 0x800a,
    LF_REAL48           = 0x800b,
    LF_COMPLEX32        = 0x800c,
    LF_COMPLEX64        = 0x800d,
    LF_COMPLEX80        = 0x800e,
    LF_COMPLEX128       = 0x800f,
    LF_VARSTRING        = 0x8010,

    LF_OCTWORD          = 0x8017,
    LF_UOCTWORD         = 0x8018,

    LF_DECIMAL          = 0x8019,
    LF_DATE             = 0x801a,
    LF_UTF8STRING       = 0x801b,

    LF_REAL16           = 0x801c,

    LF_PAD0             = 0xf0,
    LF_PAD1             = 0xf1,
    LF_PAD2             = 0xf2,
    LF_PAD3             = 0xf3,
    LF_PAD4             = 0xf4,
    LF_PAD5             = 0xf5,
    LF_PAD6             = 0xf6,
    LF_PAD7             = 0xf7,
    LF_PAD8             = 0xf8,
    LF_PAD9             = 0xf9,
    LF_PAD10            = 0xfa,
    LF_PAD11            = 0xfb,
    LF_PAD12            = 0xfc,
    LF_PAD13            = 0xfd,
    LF_PAD14            = 0xfe,
    LF_PAD15            = 0xff,
};

struct CV_prop_t {
    USHORT  packed      :1;     // true if structure is packed
    USHORT  ctor        :1;     // true if constructors or destructors present
    USHORT  ovlops      :1;     // true if overloaded operators present
    USHORT  isnested    :1;     // true if this is a nested class
    USHORT  cnested     :1;     // true if this class contains nested types
    USHORT  opassign    :1;     // true if overloaded assignment (=)
    USHORT  opcast      :1;     // true if casting methods
    USHORT  fwdref      :1;     // true if forward reference (incomplete defn)
    USHORT  scoped      :1;     // scoped definition
    USHORT  hasuniquename :1;   // true if there is a decorated name following the regular name
    USHORT  sealed      :1;     // true if class cannot be used as a base class
    USHORT  hfa         :2;     // CV_HFA_e
    USHORT  intrinsic   :1;     // true if class is an intrinsic type (e.g. __m128d)
    USHORT  mocom       :2;     // CV_MOCOM_UDT_e
};

//      LF_MODIFIER

struct CV_modifier_t {
    unsigned short  MOD_const       :1;
    unsigned short  MOD_volatile    :1;
    unsigned short  MOD_unaligned   :1;
    unsigned short  MOD_unused      :13;
};

struct LF_MODIFIER {
    CV_typ_t        type;           // modified type
    CV_modifier_t   attr;           // modifier attribute modifier_t
};

//      LF_POINTER

enum CV_ptrmode_e {
    CV_PTR_MODE_PTR         = 0x00, // "normal" pointer
    CV_PTR_MODE_REF         = 0x01, // "old" reference
    CV_PTR_MODE_LVREF       = 0x01, // l-value reference
    CV_PTR_MODE_PMEM        = 0x02, // pointer to data member
    CV_PTR_MODE_PMFUNC      = 0x03, // pointer to member function
    CV_PTR_MODE_RVREF       = 0x04, // r-value reference
    CV_PTR_MODE_RESERVED    = 0x05  // first unused pointer mode
};

enum CV_ptrtype_e {
    CV_PTR_NEAR         = 0x00, // 16 bit pointer
    CV_PTR_FAR          = 0x01, // 16:16 far pointer
    CV_PTR_HUGE         = 0x02, // 16:16 huge pointer
    CV_PTR_BASE_SEG     = 0x03, // based on segment
    CV_PTR_BASE_VAL     = 0x04, // based on value of base
    CV_PTR_BASE_SEGVAL  = 0x05, // based on segment value of base
    CV_PTR_BASE_ADDR    = 0x06, // based on address of base
    CV_PTR_BASE_SEGADDR = 0x07, // based on segment address of base
    CV_PTR_BASE_TYPE    = 0x08, // based on type
    CV_PTR_BASE_SELF    = 0x09, // based on self
    CV_PTR_NEAR32       = 0x0a, // 32 bit pointer
    CV_PTR_FAR32        = 0x0b, // 16:32 pointer
    CV_PTR_64           = 0x0c, // 64 bit pointer
    CV_PTR_UNUSEDPTR    = 0x0d  // first unused pointer type
};

struct lfPointerAttr {
    CV_ptrtype_e    ptrtype     :5;     // ordinal specifying pointer type (CV_ptrtype_e)
    CV_ptrmode_e    ptrmode     :3;     // ordinal specifying pointer mode (CV_ptrmode_e)
    unsigned long   isflat32    :1;     // true if 0:32 pointer
    unsigned long   isvolatile  :1;     // TRUE if volatile pointer
    unsigned long   isconst     :1;     // TRUE if const pointer
    unsigned long   isunaligned :1;     // TRUE if unaligned pointer
    unsigned long   isrestrict  :1;     // TRUE if restricted pointer (allow agressive opts)
    unsigned long   size        :6;     // size of pointer (in bytes)
    unsigned long   ismocom     :1;     // TRUE if it is a MoCOM pointer (^ or %)
    unsigned long   islref      :1;     // TRUE if it is this pointer of member function with & ref-qualifier
    unsigned long   isrref      :1;     // TRUE if it is this pointer of member function with && ref-qualifier
    unsigned long   unused      :10;    // pad out to 32-bits for following cv_typ_t's
};

struct LF_POINTER {
    CV_typ_t        utype;          // type index of the underlying type
    lfPointerAttr   attr;
};

//      LF_ARGLIST
struct LF_ARGLIST_16t {
    unsigned short  count;          // number of arguments
    CV_typ16_t      arg[count];      // number of arguments
};

struct LF_ARGLIST {
    unsigned long   count;          // number of arguments
    CV_typ_t        arg[count];      // number of arguments
};

//      LF_ARRAY

struct LF_ARRAY {
    CV_typ_t        elemtype;       // type index of element type
    CV_typ_t        idxtype;        // type index of indexing type
    uint16          size;
    unsigned char   name[];         // variable length data specifying size in bytes and name
};

//      LF_STRUCTURE

struct LF_STRUCTURE {
    uint16 count;
    CV_prop_t       property;       // property attribute field (prop_t)
    CV_typ_t        field;          // type index of LF_FIELD descriptor list
    CV_typ_t        derived;        // type index of derived from list if not zero
    CV_typ_t        vshape;         // type index of vshape table for this class
};

struct LF_STRUCTURE_ST {
    uint16 count;
    CV_prop_t       property;       // property attribute field (prop_t)
    CV_typ_t        field;          // type index of LF_FIELD descriptor list
    CV_typ_t        derived;        // type index of derived from list if not zero
    CV_typ_t        vshape;         // type index of vshape table for this class
    uint16          size;
};

//      LF_UNION

struct LF_UNION {
    unsigned short  count;          // count of number of elements in class
    CV_prop_t       property;       // property attribute field
    CV_typ_t        field;          // type index of LF_FIELD descriptor list
    uint16          size;
    unsigned char   name[];         // variable length data describing length of structure and name
};

//      LF_FIELDLIST STRUCTS

enum CV_methodprop_e : uint8 {
    CV_MTvanilla        = 0x00,
    CV_MTvirtual        = 0x01,
    CV_MTstatic         = 0x02,
    CV_MTfriend         = 0x03,
    CV_MTintro          = 0x04,
    CV_MTpurevirt       = 0x05,
    CV_MTpureintro      = 0x06,
};

typedef struct CV_fldattr_t {
    unsigned short  access      :2;     // access protection CV_access_t
    unsigned short  mprop       :3;     // method properties CV_methodprop_t
    unsigned short  pseudo      :1;     // compiler generated fcn and does not exist
    unsigned short  noinherit   :1;     // true if class cannot be inherited
    unsigned short  noconstruct :1;     // true if class cannot be constructed
    unsigned short  compgenx    :1;     // compiler generated fcn and does exist
    unsigned short  sealed      :1;     // true if method cannot be overridden
    unsigned short  unused      :6;     // unused
};

struct LF_MEMBER {
    CV_fldattr_t    attr;         // attribute mask
    CV_typ_t        index;        // index of type record for field
    uint16          offset;
    unsigned char   name[];       // variable length offset of field followed by length prefixed name of field
};

struct LF_STMEMBER {
    CV_fldattr_t    attr;         // attribute mask
    CV_typ_t        index;        // index of type record for field
    unsigned char   name[];       // variable length offset of field followed by length prefixed name of field
};

// LF_ONEMETHOD

struct LF_ONEMETHOD_HEADER {
    CV_fldattr_t    attr;         // attribute mask
    CV_typ_t        index;        // index of type record for field
}

struct LF_ONEMETHOD {
    CV_fldattr_t    attr;         // attribute mask
    CV_typ_t        index;        // index of type record for field
    uint32          offset;       // vtable offset
    char            name[];
}

// LF_ENUMERATE

struct LF_ENUMERATE {
    CV_fldattr_t    attr;       // access
    uint16          value;   // Leaf index used to check how many bytes to skip before the name
    unsigned char   name[];    // variable length value field followed by length prefixed name
};

//      LF_ENUM

struct LF_ENUM {
    unsigned short  count;          // count of number of elements in class
    CV_prop_t       property;       // property attribute field
    CV_typ_t        utype;          // underlying type of the enum
    CV_typ_t        field;          // type index of LF_FIELD descriptor list
    unsigned char   name[];         // length prefixed name of enum
};

//      LF_PROCEDURE
struct LF_PROCEDURE_16t {
    CV_typ16_t      rvtype;         // type index of return value
    unsigned char   calltype;       // calling convention (CV_call_t)
    CV_funcattr_t   funcattr;       // attributes
    unsigned short  parmcount;      // number of parameters
    CV_typ16_t      arglist;        // type index of argument list
};

struct LF_PROCEDURE {
    CV_typ_t        rvtype;         // type index of return value
    unsigned char   calltype;       // calling convention (CV_call_t)
    CV_funcattr_t   funcattr;       // attributes
    unsigned short  parmcount;      // number of parameters
    CV_typ_t        arglist;        // type index of argument list
};

//      LF_MFUNCTION

struct LF_MFUNCTION_16t {
    CV_typ16_t      rvtype;         // type index of return value
    CV_typ16_t      classtype;      // type index of containing class
    CV_typ16_t      thistype;       // type index of this pointer (model specific)
    unsigned char   calltype;       // calling convention (call_t)
    CV_funcattr_t   funcattr;       // attributes
    unsigned short  parmcount;      // number of parameters
    CV_typ16_t      arglist;        // type index of argument list
    long            thisadjust;     // this adjuster (long because pad required anyway)
};

struct LF_MFUNCTION {
    CV_typ_t        rvtype;         // type index of return value
    CV_typ_t        classtype;      // type index of containing class
    CV_typ_t        thistype;       // type index of this pointer (model specific)
    unsigned char   calltype;       // calling convention (call_t)
    CV_funcattr_t   funcattr;       // attributes
    unsigned short  parmcount;      // number of parameters
    CV_typ_t        arglist;        // type index of argument list
    long            thisadjust;     // this adjuster (long because pad required anyway)
};

//      LF_CLASS

struct LF_CLASS_16t {
    unsigned short  count;          // count of number of elements in class
    CV_typ16_t      field;          // type index of LF_FIELD descriptor list
    CV_prop_t       property;       // property attribute field (prop_t)
    CV_typ16_t      derived;        // type index of derived from list if not zero
    CV_typ16_t      vshape;         // type index of vshape table for this class
    unsigned char   data[];         // data describing length of structure in
                                    // bytes and name
};

// typedef LF_CLASS_16t lfStructure_16t;

struct LF_CLASS {
    unsigned short  count;          // count of number of elements in class
    CV_prop_t       property;       // property attribute field (prop_t)
    CV_typ_t        field;          // type index of LF_FIELD descriptor list
    CV_typ_t        derived;        // type index of derived from list if not zero
    CV_typ_t        vshape;         // type index of vshape table for this class
    unsigned char   data[];         // data describing length of structure in
                                    // bytes and name
};

// typedef LF_CLASS LF_STRUCTURE;
// typedef LF_CLASS lfInterface;

//      LF_METHODLIST

struct LF_METHOD_16t {
    unsigned short  count;          // number of occurrences of function
    CV_typ16_t      mList;          // index to LF_METHODLIST record
    unsigned char   Name[];        // length prefixed name of method
};

struct LF_METHOD {
    unsigned short  count;          // number of occurrences of function
    CV_typ_t        mList;          // index to LF_METHODLIST record
    unsigned char   Name[];        // length prefixed name of method
};

//      LF_VTABLE

struct LF_VTABLE {
    unsigned short  count;      // number of entries in vfunctable
    unsigned char   desc[count];     // 4 bit (CV_VTS_desc) descriptors
};

//     type record for a virtual function table
struct LF_VFTABLE {
    CV_typ_t        type;             // class/structure that owns the vftable
    CV_typ_t        baseVftable;      // vftable from which this vftable is derived
    unsigned long   offsetInObjectLayout; // offset of the vfptr to this table, relative to the start of the object layout.
    unsigned long   len;              // length of the Names array below in bytes.
    unsigned char   Names[1];         // array of names.
                                      // The first is the name of the vtable.
                                      // The others are the names of the methods.
                                      // TS-TODO: replace a name with a NamedCodeItem once Weiping is done, to
                                      //    avoid duplication of method names.
};

// LF_VFUNCTAB

struct LF_VFUNCTAB {
    uint16  unk1;
    uint32   table;
};

// LF_BCLAS, LF_BINTERFACE

struct LF_BCLASS {
    CV_fldattr_t attr;
    uint32 base_class;
    uint32 offset;
};

// LF_NESTTYPE

struct LF_NESTTYPE {
    CV_fldattr_t attr;
    uint32 nested_type;
    char name[];
};

// LF_VBCLASS

struct LF_VBCLASS {
    CV_fldattr_t attr;
    uint32 base_class;
    uint32 base_pointer;
    uint16 base_pointer_offset;
    uint16 virtual_base_offset;
};

struct dynamic_type {
    LEAF_ENUM_e type_info;
};

enum SYM_ENUM_e : uint16 {
    S_COMPILE       =  0x0001,  // Compile flags symbol
    S_REGISTER_16t  =  0x0002,  // Register variable
    S_CONSTANT_16t  =  0x0003,  // constant symbol
    S_UDT_16t       =  0x0004,  // User defined type
    S_SSEARCH       =  0x0005,  // Start Search
    S_END           =  0x0006,  // Block, procedure, "with" or thunk end
    S_SKIP          =  0x0007,  // Reserve symbol space in $$Symbols table
    S_CVRESERVE     =  0x0008,  // Reserved symbol for CV internal use
    S_OBJNAME_ST    =  0x0009,  // path to object file name
    S_ENDARG        =  0x000a,  // end of argument/return list
    S_COBOLUDT_16t  =  0x000b,  // special UDT for cobol that does not symbol pack
    S_MANYREG_16t   =  0x000c,  // multiple register variable
    S_RETURN        =  0x000d,  // return description symbol
    S_ENTRYTHIS     =  0x000e,  // description of this pointer on entry

    S_BPREL16       =  0x0100,  // BP-relative
    S_LDATA16       =  0x0101,  // Module-local symbol
    S_GDATA16       =  0x0102,  // Global data symbol
    S_PUB16         =  0x0103,  // a public symbol
    S_LPROC16       =  0x0104,  // Local procedure start
    S_GPROC16       =  0x0105,  // Global procedure start
    S_THUNK16       =  0x0106,  // Thunk Start
    S_BLOCK16       =  0x0107,  // block start
    S_WITH16        =  0x0108,  // with start
    S_LABEL16       =  0x0109,  // code label
    S_CEXMODEL16    =  0x010a,  // change execution model
    S_VFTABLE16     =  0x010b,  // address of virtual function table
    S_REGREL16      =  0x010c,  // register relative address

    S_BPREL32_16t   =  0x0200,  // BP-relative
    S_LDATA32_16t   =  0x0201,  // Module-local symbol
    S_GDATA32_16t   =  0x0202,  // Global data symbol
    S_PUB32_16t     =  0x0203,  // a public symbol (CV internal reserved)
    S_LPROC32_16t   =  0x0204,  // Local procedure start
    S_GPROC32_16t   =  0x0205,  // Global procedure start
    S_THUNK32_ST    =  0x0206,  // Thunk Start
    S_BLOCK32_ST    =  0x0207,  // block start
    S_WITH32_ST     =  0x0208,  // with start
    S_LABEL32_ST    =  0x0209,  // code label
    S_CEXMODEL32    =  0x020a,  // change execution model
    S_VFTABLE32_16t =  0x020b,  // address of virtual function table
    S_REGREL32_16t  =  0x020c,  // register relative address
    S_LTHREAD32_16t =  0x020d,  // local thread storage
    S_GTHREAD32_16t =  0x020e,  // global thread storage
    S_SLINK32       =  0x020f,  // static link for MIPS EH implementation

    S_LPROCMIPS_16t =  0x0300,  // Local procedure start
    S_GPROCMIPS_16t =  0x0301,  // Global procedure start

    // if these ref symbols have names following then the names are in ST format
    S_PROCREF_ST    =  0x0400,  // Reference to a procedure
    S_DATAREF_ST    =  0x0401,  // Reference to data
    S_ALIGN         =  0x0402,  // Used for page alignment of symbols

    S_LPROCREF_ST   =  0x0403,  // Local Reference to a procedure
    S_OEM           =  0x0404,  // OEM defined symbol

    // sym records with 32-bit types embedded instead of 16-bit
    // all have 0x1000 bit set for easy identification
    // only do the 32-bit target versions since we don't really
    // care about 16-bit ones anymore.
    S_TI16_MAX          =  0x1000,

    S_REGISTER_ST   =  0x1001,  // Register variable
    S_CONSTANT_ST   =  0x1002,  // constant symbol
    S_UDT_ST        =  0x1003,  // User defined type
    S_COBOLUDT_ST   =  0x1004,  // special UDT for cobol that does not symbol pack
    S_MANYREG_ST    =  0x1005,  // multiple register variable
    S_BPREL32_ST    =  0x1006,  // BP-relative
    S_LDATA32_ST    =  0x1007,  // Module-local symbol
    S_GDATA32_ST    =  0x1008,  // Global data symbol
    S_PUB32_ST      =  0x1009,  // a public symbol (CV internal reserved)
    S_LPROC32_ST    =  0x100a,  // Local procedure start
    S_GPROC32_ST    =  0x100b,  // Global procedure start
    S_VFTABLE32     =  0x100c,  // address of virtual function table
    S_REGREL32_ST   =  0x100d,  // register relative address
    S_LTHREAD32_ST  =  0x100e,  // local thread storage
    S_GTHREAD32_ST  =  0x100f,  // global thread storage

    S_LPROCMIPS_ST  =  0x1010,  // Local procedure start
    S_GPROCMIPS_ST  =  0x1011,  // Global procedure start

    S_FRAMEPROC     =  0x1012,  // extra frame and proc information
    S_COMPILE2_ST   =  0x1013,  // extended compile flags and info

    // new symbols necessary for 16-bit enumerates of IA64 registers
    // and IA64 specific symbols

    S_MANYREG2_ST   =  0x1014,  // multiple register variable
    S_LPROCIA64_ST  =  0x1015,  // Local procedure start (IA64)
    S_GPROCIA64_ST  =  0x1016,  // Global procedure start (IA64)

    // Local symbols for IL
    S_LOCALSLOT_ST  =  0x1017,  // local IL sym with field for local slot index
    S_PARAMSLOT_ST  =  0x1018,  // local IL sym with field for parameter slot index

    S_ANNOTATION    =  0x1019,  // Annotation string literals

    // symbols to support managed code debugging
    S_GMANPROC_ST   =  0x101a,  // Global proc
    S_LMANPROC_ST   =  0x101b,  // Local proc
    S_RESERVED1     =  0x101c,  // reserved
    S_RESERVED2     =  0x101d,  // reserved
    S_RESERVED3     =  0x101e,  // reserved
    S_RESERVED4     =  0x101f,  // reserved
    S_LMANDATA_ST   =  0x1020,
    S_GMANDATA_ST   =  0x1021,
    S_MANFRAMEREL_ST=  0x1022,
    S_MANREGISTER_ST=  0x1023,
    S_MANSLOT_ST    =  0x1024,
    S_MANMANYREG_ST =  0x1025,
    S_MANREGREL_ST  =  0x1026,
    S_MANMANYREG2_ST=  0x1027,
    S_MANTYPREF     =  0x1028,  // Index for type referenced by name from metadata
    S_UNAMESPACE_ST =  0x1029,  // Using namespace

    // Symbols w/ SZ name fields. All name fields contain utf8 encoded strings.
    S_ST_MAX        =  0x1100,  // starting point for SZ name symbols

    S_OBJNAME       =  0x1101,  // path to object file name
    S_THUNK32       =  0x1102,  // Thunk Start
    S_BLOCK32       =  0x1103,  // block start
    S_WITH32        =  0x1104,  // with start
    S_LABEL32       =  0x1105,  // code label
    S_REGISTER      =  0x1106,  // Register variable
    S_CONSTANT      =  0x1107,  // constant symbol
    S_UDT           =  0x1108,  // User defined type
    S_COBOLUDT      =  0x1109,  // special UDT for cobol that does not symbol pack
    S_MANYREG       =  0x110a,  // multiple register variable
    S_BPREL32       =  0x110b,  // BP-relative
    S_LDATA32       =  0x110c,  // Module-local symbol
    S_GDATA32       =  0x110d,  // Global data symbol
    S_PUB32         =  0x110e,  // a public symbol (CV internal reserved)
    S_LPROC32       =  0x110f,  // Local procedure start
    S_GPROC32       =  0x1110,  // Global procedure start
    S_REGREL32      =  0x1111,  // register relative address
    S_LTHREAD32     =  0x1112,  // local thread storage
    S_GTHREAD32     =  0x1113,  // global thread storage

    S_LPROCMIPS     =  0x1114,  // Local procedure start
    S_GPROCMIPS     =  0x1115,  // Global procedure start
    S_COMPILE2      =  0x1116,  // extended compile flags and info
    S_MANYREG2      =  0x1117,  // multiple register variable
    S_LPROCIA64     =  0x1118,  // Local procedure start (IA64)
    S_GPROCIA64     =  0x1119,  // Global procedure start (IA64)
    S_LOCALSLOT     =  0x111a,  // local IL sym with field for local slot index
    S_PARAMSLOT     =  0x111b,  // local IL sym with field for parameter slot index

    // symbols to support managed code debugging
    S_LMANDATA      =  0x111c,
    S_GMANDATA      =  0x111d,
    S_MANFRAMEREL   =  0x111e,
    S_MANREGISTER   =  0x111f,
    S_MANSLOT       =  0x1120,
    S_MANMANYREG    =  0x1121,
    S_MANREGREL     =  0x1122,
    S_MANMANYREG2   =  0x1123,
    S_UNAMESPACE    =  0x1124,  // Using namespace

    // ref symbols with name fields
    S_PROCREF       =  0x1125,  // Reference to a procedure
    S_DATAREF       =  0x1126,  // Reference to data
    S_LPROCREF      =  0x1127,  // Local Reference to a procedure
    S_ANNOTATIONREF =  0x1128,  // Reference to an S_ANNOTATION symbol
    S_TOKENREF      =  0x1129,  // Reference to one of the many MANPROCSYM's

    // continuation of managed symbols
    S_GMANPROC      =  0x112a,  // Global proc
    S_LMANPROC      =  0x112b,  // Local proc

    // short, light-weight thunks
    S_TRAMPOLINE    =  0x112c,  // trampoline thunks
    S_MANCONSTANT   =  0x112d,  // constants with metadata type info

    // native attributed local/parms
    S_ATTR_FRAMEREL =  0x112e,  // relative to virtual frame ptr
    S_ATTR_REGISTER =  0x112f,  // stored in a register
    S_ATTR_REGREL   =  0x1130,  // relative to register (alternate frame ptr)
    S_ATTR_MANYREG  =  0x1131,  // stored in >1 register

    // Separated code (from the compiler) support
    S_SEPCODE       =  0x1132,

    S_LOCAL_2005    =  0x1133,  // defines a local symbol in optimized code
    S_DEFRANGE_2005 =  0x1134,  // defines a single range of addresses in which symbol can be evaluated
    S_DEFRANGE2_2005 =  0x1135,  // defines ranges of addresses in which symbol can be evaluated

    S_SECTION       =  0x1136,  // A COFF section in a PE executable
    S_COFFGROUP     =  0x1137,  // A COFF group
    S_EXPORT        =  0x1138,  // A export

    S_CALLSITEINFO  =  0x1139,  // Indirect call site information
    S_FRAMECOOKIE   =  0x113a,  // Security cookie information

    S_DISCARDED     =  0x113b,  // Discarded by LINK /OPT:REF (experimental, see richards)

    S_COMPILE3      =  0x113c,  // Replacement for S_COMPILE2
    S_ENVBLOCK      =  0x113d,  // Environment block split off from S_COMPILE2

    S_LOCAL         =  0x113e,  // defines a local symbol in optimized code
    S_DEFRANGE      =  0x113f,  // defines a single range of addresses in which symbol can be evaluated
    S_DEFRANGE_SUBFIELD =  0x1140,           // ranges for a subfield

    S_DEFRANGE_REGISTER =  0x1141,           // ranges for en-registered symbol
    S_DEFRANGE_FRAMEPOINTER_REL =  0x1142,   // range for stack symbol.
    S_DEFRANGE_SUBFIELD_REGISTER =  0x1143,  // ranges for en-registered field of symbol
    S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE =  0x1144, // range for stack symbol span valid full scope of function body, gap might apply.
    S_DEFRANGE_REGISTER_REL =  0x1145, // range for symbol address as register + offset.

    // S_PROC symbols that reference ID instead of type
    S_LPROC32_ID     =  0x1146,
    S_GPROC32_ID     =  0x1147,
    S_LPROCMIPS_ID   =  0x1148,
    S_GPROCMIPS_ID   =  0x1149,
    S_LPROCIA64_ID   =  0x114a,
    S_GPROCIA64_ID   =  0x114b,

    S_BUILDINFO      = 0x114c, // build information.
    S_INLINESITE     = 0x114d, // inlined function callsite.
    S_INLINESITE_END = 0x114e,
    S_PROC_ID_END    = 0x114f,

    S_DEFRANGE_HLSL  = 0x1150,
    S_GDATA_HLSL     = 0x1151,
    S_LDATA_HLSL     = 0x1152,

    S_FILESTATIC     = 0x1153,

    S_LOCAL_DPC_GROUPSHARED = 0x1154, // DPC groupshared variable
    S_LPROC32_DPC = 0x1155, // DPC local procedure start
    S_LPROC32_DPC_ID =  0x1156,
    S_DEFRANGE_DPC_PTR_TAG =  0x1157, // DPC pointer tag definition range
    S_DPC_SYM_TAG_MAP = 0x1158, // DPC pointer tag value to symbol record map
    
    S_ARMSWITCHTABLE  = 0x1159,
    S_CALLEES = 0x115a,
    S_CALLERS = 0x115b,
    S_POGODATA = 0x115c,
    S_INLINESITE2 = 0x115d,      // extended inline site information

    S_HEAPALLOCSITE = 0x115e,    // heap allocation site

    S_MOD_TYPEREF = 0x115f,      // only generated at link time

    S_REF_MINIPDB = 0x1160,      // only generated at link time for mini PDB
    S_PDBMAP      = 0x1161,      // only generated at link time for mini PDB

    S_GDATA_HLSL32 = 0x1162,
    S_LDATA_HLSL32 = 0x1163,

    S_GDATA_HLSL32_EX = 0x1164,
    S_LDATA_HLSL32_EX = 0x1165,

    S_RECTYPE_MAX = 0x1166,               // one greater than last -> manually set for dissect.cstruct
    S_RECTYPE_LAST  = 0x1166 - 1,
    S_RECTYPE_PAD   = 0x1166 + 0x100 // Used *only* to verify symbol record types so that current PDB code can potentially read
                                // future PDBs (assuming no format change, etc).
};

/////////////////////////////////////////////////////////////////////////
// DBI specific definitions
// https://github.com/microsoft/microsoft-pdb/blob/master/PDB/dbi/dbi.h
// https://github.com/ungoogled-software/syzygy/blob/master/syzygy/pdb/pdb_data.h
/////////////////////////////////////////////////////////////////////////
struct DbiSectionContrib {
    int16_t section;
    int16_t pad1;
    int32_t offset;
    int32_t size;
    uint32_t flags;
    int16_t module;
    int16_t pad2;
    uint32_t data_crc;
    uint32_t reloc_crc;
};

struct DbiModuleInfoBase {
    uint32_t opened;
    DbiSectionContrib section;
    uint16_t flags;
    int16_t stream;
    uint32_t symbol_bytes;
    uint32_t old_lines_bytes;
    uint32_t lines_bytes;
    int16_t num_files;
    uint16_t padding;
    uint32_t offsets;
    uint32_t num_source;
    uint32_t num_compiler;
    char module_name[];
    char object_name[];
    // There are two trailing null-terminated 8-bit strings, the first being the
    // module_name and the second being the object_name. Then this structure is
    // padded with zeros to have a length that is a multiple of 4.
};

struct DbiSectionMapItem {
    uint8_t flags;
    uint8_t section_type;
    // This field hasn't been deciphered but it is always 0x00000000 or 0xFFFFFFFF
    // and modifying it doesn't seem to invalidate the PDB.
    uint16_t unknown_data_1[2];
    uint16_t section_number;
    // Same thing as for unknown_data_1.
    uint16_t unknown_data_2[2];
    // Value added to the address offset when calculating the RVA.
    uint32_t rva_offset;
    uint32_t section_length;
};

enum header_signature {
    hdrSignature = -1,
};

struct DbiHeader {
    ULONG       verSignature;
    ULONG       verHdr;
    ULONG       age;

    SN          snGSSyms;

    union {
        struct {
            USHORT      usVerPdbDllMin : 8;     // minor version
            USHORT      usVerPdbDllMaj : 7;     // major version
            USHORT      fNewVerFmt     : 1;     // flag telling us we have rbld stored elsewhere (high bit of original major version)  # noqa: E501
        } vernew;                               // that built this pdb last.
        struct {
            USHORT      usVerPdbDllRBld: 4;
            USHORT      usVerPdbDllMin : 7;
            USHORT      usVerPdbDllMaj : 5;
        } verold;
        USHORT          usVerAll;
    };

    SN          snPSSyms;
    USHORT      usVerPdbDllBuild;   // build version of the pdb dll that built this pdb last.
    SN          snSymRecs;
    USHORT      usVerPdbDllRBld;    // rbld version of the pdb dll that built this pdb last.
    CB          cbGpModi;           // size of rgmodi substream
    CB          cbSC;               // size of Section Contribution substream
    CB          cbSecMap;
    CB          cbFileInfo;

    CB          cbTSMap;            // size of the Type Server Map substream
    ULONG       iMFC;               // index of MFC type server
    CB          cbDbgHdr;           // size of optional DbgHdr info appended to the end of the stream
    CB          cbECInfo;           // number of bytes in EC substream, or 0 if EC no EC enabled Mods
    struct _flags {
        USHORT  fIncLink:1;         // true if linked incrmentally (really just if ilink thunks are present)
        USHORT  fStripped:1;        // true if PDB::CopyTo stripped the private data out
        USHORT  fCTypes:1;          // true if linked with /debug:ctypes
        USHORT  unused:13;          // reserved, must be 0.
    } flags;
    USHORT      wMachine;           // machine type
    ULONG       rgulReserved[1];    // pad out to 64 bytes for future growth.
};

struct SymbolRecordHeader {
    // Length of the symbol record in bytes, without this field. The length
    // including this field is always a multiple of 4.
    uint16_t length;

    // Type of the symbol record. If must be a value from Microsoft_Cci_Pdb::SYM.
    SYM_ENUM_e type;
};


enum CVPSF : uint32 {
    CVPSF_CODE = 0x1,
    CVPSF_FUNCTION = 0x2,
    CVPSF_MANAGED = 0x4,
    CVPSF_MSIL = 0x8,
};

enum Variant : uint16 {
    uint8 = 0,
    uint16 = 1,
    uint32 = 2,
    uint64 = 3,
    int8 = 4,
    int16 = 5,
    int32 = 6,
    int64 = 7,
};

// SYMBOL STRUCTURES

struct GlobalSymbol {
    CVPSF cvpsf_type;
    uint32 offset;  // The memory offset relative from the start of the section's memory.
    uint16 section; // The index of the section in the PDB's section headers list, incremented by `1`.
    char name[];
};

struct PublicSymbol {
    CVPSF cvpsf_type;
    uint32 offset;
    uint16 section;
    char name[];
};

struct PublicSymbol_ST {
    CVPSF cvpsf_type;
    uint32 offset;
    uint16 section;
    uint8 name_length;
    char name[name_length];
};


// ConstantSymbol
struct ConstantSymbolHeader {
    uint32 type_index;
    uint16 value;
};

struct ConstantSymbol {
    uint32 type_index;
    char value[];
    char name[];
};


struct RegisterSymbol {
    uint32 type_index;
    uint16 register;
    char name[];
};

struct GlobalDataSymbol {
    uint32 type_index;
    uint32 offset;
    uint16 section;
    char name[];
};

struct ManagedDataSymbol {
    uint32 type_index;
    uint32 offset;
    uint16 section;
    char name[];
}

struct ProcedureReferenceSymbol{
    uint32 sum_name;
    uint32 symbol_index;
    uint16 module_index;    // Index of the module containing the symbol
    char name[];
};

struct DataReferenceSymbol {
    uint32 sum_name;
    uint32 symbol_index;
    uint32 module;
    char name[];
};

struct AnnotationReferenceSymbol {
    uint32 sum_name;
    uint32 symbol_index;
    uint16 module;
    char name[];
};

typedef enum TrampolineType : uint16 {
    Incremental = 0x0,
    BranchIsland = 0x1,
    Unknown = 0x2,
};

struct TrampolineSymbol {
    TrampolineType trampoline_type;
    uint16 size;
    uint32 thunk_offset;  // The memory offset relative from the start of the section's memory.
    uint16 thunk_section; // The index of the section in the PDB's section headers list, incremented by `1`.
    uint32 target_offset;  // The target memory offset relative from the start of the section's memory.
    uint16 target_section; // The target index of the section in the PDB's section headers list, incremented by `1`.
};

struct UserDefinedSymbol {
    uint32 type_index;
    char name[];
};

struct ThreadStorageSymbol {
    uint32 type_index;
    uint32 offset;
    uint16 section;
    char name[];
};

struct TokenReferenceSymbol {
    uint32 unk1;
    uint32 symbol_index;
    uint16 module_index;
    char name[];    // The token ID
};

typedef enum CV_PROCFLAGS : uint8 {
    CV_PFLAG_NOFPO = 0x01,
    CV_PFLAG_INT = 0x02,
    CV_PFLAG_FAR = 0x04,
    CV_PFLAG_NEVER = 0x08,
    CV_PFLAG_NOTREACHED = 0x10,
    CV_PFLAG_CUST_CALL = 0x20,
    CV_PFLAG_NOINLINE = 0x40,
    CV_PFLAG_OPTDBGINFO = 0x80,
};

struct ProcedureSymbol {
    uint32 parent;
    uint32 end;
    uint32 next;
    uint32 length;
    uint32 debug_start_offset;
    uint32 debug_end_offset;
    uint32 type_index;
    uint32 offset;
    uint16 section;
    CV_PROCFLAGS flags;
    char name[];
};
"""


c_pdb = cstruct()
c_pdb.load(pdb_def)


cv_info_def = """
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


cv_info_struct = cstruct()
cv_info_struct.load(cv_info_def)


# Types that were gathered from creating some PDB's using Visual Studio
COMPILER_TYPES = {
    0x8: c_pdb.uint32,  # HRESULT
    0x10: c_pdb.char,  # __int8 / signed char
    0x11: c_pdb.short,
    0x12: c_pdb.int32,  # LONG
    0x13: c_pdb.int64,  # LONGLONG
    0x14: c_pdb.int128,
    0x20: c_pdb.uchar,  # byte
    0x21: c_pdb.WORD,  # WORD
    0x22: c_pdb.uint32,  # ULONG
    0x23: c_pdb.uint64,  # ULONGLONG / QWORD
    0x24: c_pdb.uint128,
    0x30: c_pdb.uint32,  # unsigned long long
    0x40: c_pdb.float,
    0x41: c_pdb.double,
    0x42: c_pdb.char[10],  # dt type (float64 10 bytes)
    0x45: c_pdb.float,  # float32pp
    0x46: c_pdb.float16,
    0x68: c_pdb.int8,
    0x69: c_pdb.uint8,
    0x70: c_pdb.char,  # CHAR
    0x71: c_pdb.wchar,
    0x72: c_pdb.int16,
    0x73: c_pdb.uint16,
    0x74: c_pdb.int,  # INT
    0x75: c_pdb.uint32,  # DWORD32 / unsigned int
    0x76: c_pdb.int64,  # LONGLONG
    0x77: c_pdb.uint64,  # ULONGLONG
    0x78: c_pdb.int128,
    0x79: c_pdb.uint128,
    0x7A: c_pdb.uint64,  # ???
    0x7B: c_pdb.uint64,  # ???
    0x48CA: c_pdb.uint64,  #
    0x1B1511: c_pdb.uint64,  # ???
}

# Specific pointer types
# 0x47b
POINTER_TYPES = {
    0x410: c_pdb.int8,  # PINT8
    0x411: c_pdb.short,  # piVal
    0x412: c_pdb.long,  # plVal
    0x413: c_pdb.LONGLONG,  # pllVal
    0x420: c_pdb.char,  # char*
    0x421: c_pdb.ushort,  # puiVal
    0x422: c_pdb.ULONG,  # pulVal
    0x423: c_pdb.uint64,  # pUint64
    0x440: c_pdb.float,  # pfltVal
    0x441: c_pdb.double,  # pdblVal
    0x470: c_pdb.char,  # char*
    0x471: c_pdb.char,  # LPSTR
    0x474: c_pdb.uint32,
    0x475: c_pdb.UINT,  # puintVal
    0x610: c_pdb.int8,
    0x611: c_pdb.short,  # piVal
    0x612: c_pdb.LONG,  # long*
    0x613: c_pdb.QWORD,  # quad*
    0x620: c_pdb.uchar,  # uchar*
    0x621: c_pdb.ushort,  # ushort*
    0x622: c_pdb.ULONG,  # ulong*
    0x623: c_pdb.uint64,  # uquad*
    0x630: c_pdb.uint64,
    0x640: c_pdb.float,  # pfltVal
    0x641: c_pdb.double,  # pdblVal
    0x670: c_pdb.char,  # rchar*
    0x671: c_pdb.LONG,  # LONG pointer
    0x674: c_pdb.int,  # pIntVal
    0x675: c_pdb.DWORD,  # PDWORD32 / PUHALF_PTR / PUINT / PUINT32 / PULONG32
    0x67A: c_pdb.char[2],  # _Ptr <Union std::_String_val<std::_Simple_types<char16_t> >::_Bxty>
    0x67B: c_pdb.char[4],  # _Ptr <Union std::_String_val<std::_Simple_types<char32_t> >::_Bxty>
}

# Either unsupported by cstruct at the time of writing or architecture specific
ARCH_POINTERS = [
    0x3,  # VOID
    0x103,  # std::nullptr_t
    0x403,  # PVOID
    0x47A,  # _Ptr
    0x47B,  # _Ptr
    0x603,  # VOID
]

# This translation is used to translate the leaf data type for constant symbols
# These relate to integer values, but we're reading the amount of bytes in our case
leaf_translation = {
    0x8000: c_pdb.char,
    0x8001: c_pdb.char[2],
    0x8002: c_pdb.char[2],
    0x8003: c_pdb.char[4],
    0x8004: c_pdb.char[4],
    0x8005: c_pdb.char[4],
    0x8006: c_pdb.char[8],
    0x8007: c_pdb.char[10],
    0x8008: c_pdb.char[16],
    0x8009: c_pdb.char[8],
    0x800A: c_pdb.char[8],
    0x800B: c_pdb.char[6],
    0x800C: c_pdb.char[8],
    0x800D: c_pdb.char[16],
    0x800E: c_pdb.char[20],
    0x800F: c_pdb.char[32],
    0x8010: c_pdb.char,
    0x8017: c_pdb.char[16],
    0x8018: c_pdb.char[16],
    0x8019: c_pdb.char[14],
    0x801A: c_pdb.char[8],
    0x801B: c_pdb.char[None],
    0x801C: c_pdb.char[2],
}


PDB2_SIGNATURE = b"Microsoft C/C++ program database 2.00\r\n\x1aJG\x00\x00"
PDB7_SIGNATURE = b"Microsoft C/C++ MSF 7.00\r\n\x1ADS\x00\x00\x00"
