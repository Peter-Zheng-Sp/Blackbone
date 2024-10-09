#pragma once
#include <ntifs.h>

void pretenseProcessImageName(IN PEPROCESS sourceProcess, IN PEPROCESS targetProcess);
void pretenseProcessFullName(IN PEPROCESS sourceProcess, IN PEPROCESS targetProcess);
void pretenseProcessFileObjectName(IN PEPROCESS sourceProcess, IN PEPROCESS targetProcess);
void pretenseProcessTokenGroup(IN PEPROCESS sourceProcess, IN PEPROCESS targetProcess);
void pretenseProcessPeb64Param(IN PEPROCESS sourceProcess, IN PEPROCESS targetProcess);
void pretenseProcessPeb64Moudle(IN PEPROCESS sourceProcess, IN PEPROCESS targetProcess);
void pretenseProcessPeb32Param(IN PEPROCESS sourceProcess, IN PEPROCESS targetProcess);
void pretenseProcessPeb32Moudle(IN PEPROCESS sourceProcess, IN PEPROCESS targetProcess);
