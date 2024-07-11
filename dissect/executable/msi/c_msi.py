from dissect import cstruct

msi_def = """
#define MSI_DATASIZEMASK    0x00ff
#define MSITYPE_VALID       0x0100
#define MSITYPE_LOCALIZABLE 0x0200
#define MSITYPE_STRING      0x0800
#define MSITYPE_NULLABLE    0x1000
#define MSITYPE_KEY         0x2000
#define MSITYPE_TEMPORARY   0x4000
#define MSITYPE_UNKNOWN     0x8000

#define TABLENAME_COLUMNS "_Columns"
#define TABLENAME_TABLE "_Tables"
#define TABLENAME_STRINGPOOL "_StringPool"
#define TABLENAME_STRINGDATA "_StringData"

#define CP_ACP				0x0
"""

c_msi = cstruct.cstruct()
c_msi.load(msi_def)
