#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "3gxDecrypter.h"

u32 exeDecProcess[] = {
  0xE52DE004, // push {lr}
  0xE3A00000, // mov r0, #0
  0xE49DF004, // pop {pc}
  0xE320F000, // NOP
};

const char *const FileErrMsg[] = {
  "%s is not 3gx file.\n",
  "%s is not supported version.\n",
  "%s is not encrypted.\n"
};

void Decrypt(u32 *code, u32 size, u32 *args)
{
  u32 arg1 = args[0];
  u32 arg2 = args[1];
  size /= sizeof(u32);
  for(u32 i = 0; i < size; i++)
  {
    code[i] ^= arg1;
    code[i] += arg2;
    arg1 += arg1;
    arg2 += code[i];
  }
}

void SetExeDecProcess(_3gx_Header *header, u8 *buffer)
{
  header->infos.exeDecChecksum = 0;
  memcpy(buffer + header->executable.exeDecOffset, exeDecProcess, sizeof(exeDecProcess));
}

int CheckFile(_3gx_Header *header)
{
  // Check magic
  if((u32)header->magic != (u32)_3GX_MAGIC)
    return NOT_3GX_FILE;

  // Check version
  if((u64)header->magic != (u64)_3GX_MAGIC)
    return UNSUPPORTED_3GX_VERSION;

  // Is file encrypted
  if(header->infos.builtInDecExeArgs[0] == 0 && header->infos.builtInDecExeArgs[1] == 0)
    return NOT_ENCRYPTED;

  return NEED_DECRYPT;
}

int main(int argc, char **argv)
{
  FILE *input;
  FILE *output;
  u32 fileSize;
  u32 codeSize;
  _3gx_Header *header;
  u8 *buffer;

  if(argc != 3)
  {
    printf("3gxDecrypter <input.3gx> <output.3gx>\n");
    exit(-1);
  }

  // Open input file
  input = fopen(argv[1], "rb");
  if(!input)
  {
    printf("Failed to open %s!\n", argv[1]);
    exit(-1);
  }

  // Get file size
  fseek(input, 0, SEEK_END);
  fileSize = ftell(input);
  fseek(input, 0, SEEK_SET);

  // Read the file
  buffer = malloc(fileSize);
  if(!buffer)
  {
    printf("Failed to allocate memory.\n");
    fclose(input);
    exit(-1);
  }
  fread(buffer, 1, fileSize, input);
  fclose(input);

  // Check the file
  header = (_3gx_Header *)buffer;
  int fileState = CheckFile(header);
  if(fileState != NEED_DECRYPT)
  {
    printf(FileErrMsg[fileState - 1], argv[1]);
    free(buffer);
    exit(-1);
  }

  // Get code size
  codeSize = header->executable.codeSize;
  codeSize += header->executable.rodataSize;
  codeSize += header->executable.dataSize;

  // Decryption
  Decrypt((u32 *)(buffer + header->executable.codeOffset), codeSize, (u32 *)header->infos.builtInDecExeArgs);
  SetExeDecProcess(header, buffer);

  // Write the decrypted data
  output = fopen(argv[2], "wb");
  if(!output)
  {
    printf("Failed to open %s!\n", argv[2]);
    free(buffer);
    exit(-1);
  }
  fwrite(buffer, 1, fileSize, output);
  fclose(output);

  free(buffer);
  printf("Done\n");
  return 0;
}
