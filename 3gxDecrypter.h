#include <stddef.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

enum FileState {
  NEED_DECRYPT,
  NOT_3GX_FILE,
  UNSUPPORTED_3GX_VERSION,
  NOT_ENCRYPTED
};


// by https://github.com/Nanquitas/Luma3DS/blob/v10.2.1/sysmodules/rosalina/include/plugin/3gx.h

#define _3GX_MAGIC (0x3230303024584733) /* "3GX$0002" */
#define PACKED     __attribute__((packed))

typedef struct PACKED
{
    u32             authorLen;
    u32             authorMsg;
    u32             titleLen;
    u32             titleMsg;
    u32             summaryLen;
    u32             summaryMsg;
    u32             descriptionLen;
    u32             descriptionMsg;
    union {
        u32         flags;
        struct {
            u32     embeddedExeDecryptFunc : 1;
            u32     embeddedSwapEncDecFunc : 1;
            u32     unused : 30;
        };
    };
    u32             exeDecChecksum;
    u32             builtInDecExeArgs[4];
    u32             builtInSwapEncDecArgs[4];
} _3gx_Infos;

typedef struct PACKED
{
    u32             count;
    u32             titles;
}   _3gx_Targets;

typedef struct PACKED
{
    u32             nbSymbols;
    u32             symbolsOffset;
    u32             nameTableOffset;
}   _3gx_Symtable;

typedef struct PACKED
{
    u32             codeOffset;
    u32             rodataOffset;
    u32             dataOffset;
    u32             codeSize;
    u32             rodataSize;
    u32             dataSize;
    u32             bssSize;
    u32             exeDecOffset; // NOP terminated
    u32             swapEncOffset; // NOP terminated
    u32             swapDecOffset; // NOP terminated
} _3gx_Executable;

typedef struct PACKED
{
    u64             magic;
    u32             version;
    u32             reserved;
    _3gx_Infos      infos;
    _3gx_Executable executable;
    _3gx_Targets    targets;
    _3gx_Symtable   symtable;
} _3gx_Header;