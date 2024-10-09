#include "PretenseHelpers.h"

#include "private.h"

extern DYNAMIC_DATA dynData;

void pretenseProcessImageName(IN PEPROCESS sourceProcess, IN PEPROCESS targetProcess)
{
    ULONG imgNameOffset = dynData.ImageFileName;

    PUCHAR imageName = ((PUCHAR)((PUCHAR)sourceProcess + imgNameOffset));

    PUCHAR targetName = ((PUCHAR)((PUCHAR)targetProcess + imgNameOffset));

    memcpy(imageName, targetName, 15);
}

//修改全路径
void pretenseProcessFullName(IN PEPROCESS sourceProcess, IN PEPROCESS targetProcess)
{
    PUNICODE_STRING pTargetFullName = NULL;

    NTSTATUS status = SeLocateProcessImageName(targetProcess, &pTargetFullName);

    if (!NT_SUCCESS(status))
    {
        return;
    }

    ULONG seOffset = dynData.SeAuditImageName;
    POBJECT_NAME_INFORMATION pSeInfo = (POBJECT_NAME_INFORMATION) * ((PULONG64)((PUCHAR)sourceProcess + seOffset));

    if (pSeInfo->Name.Length >= pTargetFullName->Length)
    {
        memset(pSeInfo->Name.Buffer, 0, pSeInfo->Name.MaximumLength);

        memcpy(pSeInfo->Name.Buffer, pTargetFullName->Buffer, pTargetFullName->Length);
    }
    else
    {
        //申请一块内存
        SIZE_T size = pTargetFullName->MaximumLength + sizeof(UNICODE_STRING);

        PUNICODE_STRING uname = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, size, 'fIeS');
        if (!uname)
        {
            return;
        }

        uname->MaximumLength = pTargetFullName->MaximumLength;

        uname->Length = pTargetFullName->Length;

        uname->Buffer = (PWCH)((PUCHAR)uname + sizeof(UNICODE_STRING));

        memcpy(uname->Buffer, pTargetFullName->Buffer, pTargetFullName->Length);

        ExFreePool(pSeInfo);

        *((PULONG64)((PUCHAR)sourceProcess + seOffset)) = (ULONG64)uname;
    }

    ExFreePool(pTargetFullName);
}

void pretenseProcessFileObjectName(IN PEPROCESS sourceProcess, IN PEPROCESS targetProcess)
{
    PFILE_OBJECT fakeFileObj = NULL;

    PFILE_OBJECT srcFileObj = NULL;

    OBJECT_NAME_INFORMATION srcFileName = {0};

    UNICODE_STRING ustrAPI = {0};
    RtlInitUnicodeString(&ustrAPI, L"PsReferenceProcessFilePointer");
    typedef_PsReferenceProcessFilePointer myPsReferenceProcessFilePointer =
        (typedef_PsReferenceProcessFilePointer)MmGetSystemRoutineAddress(&ustrAPI);

    NTSTATUS status = myPsReferenceProcessFilePointer(targetProcess, &srcFileObj);

    if (!NT_SUCCESS(status))
    {
        return;
    }

    status = myPsReferenceProcessFilePointer(sourceProcess, &fakeFileObj);

    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(srcFileObj);
        return;
    }

    PUNICODE_STRING usrcName = &srcFileObj->FileName;

    PUNICODE_STRING ufakeName = &fakeFileObj->FileName;

    PWCH fakeName = NULL;

    if (ufakeName->Length >= usrcName->Length)
    {
        memset(ufakeName->Buffer, 0, usrcName->MaximumLength);

        memcpy(ufakeName->Buffer, usrcName->Buffer, usrcName->Length);

        fakeName = ufakeName->Buffer;
    }
    else
    {
        //申请一块内存
        SIZE_T size = usrcName->MaximumLength;

        fakeName = (PWCH)ExAllocatePool(NonPagedPool, size);
        if (!fakeName)
        {
            ObDereferenceObject(srcFileObj);
            return;
        }

        memset(fakeName, 0, size);

        memcpy(fakeName, usrcName->Buffer, usrcName->Length);

        ufakeName->Buffer = fakeName;
    }

    ufakeName->MaximumLength = usrcName->MaximumLength;

    ufakeName->Length = usrcName->Length;

    ULONG64 fsContext2 = *(PULONG64)((PUCHAR)fakeFileObj + 0x20);

    if (MmIsAddressValid((PUCHAR)fsContext2))
    {
        PUNICODE_STRING unfsContextName = (PUNICODE_STRING)(fsContext2 + 0x10);

        if (unfsContextName->Length && unfsContextName->MaximumLength)
        {
            unfsContextName->Buffer = fakeName;
            unfsContextName->Length = ufakeName->Length;
            unfsContextName->MaximumLength = ufakeName->MaximumLength;
        }
    }

    fakeFileObj->DeviceObject = srcFileObj->DeviceObject;
    fakeFileObj->Vpb = srcFileObj->Vpb;

    ObDereferenceObject(srcFileObj);
    ObDereferenceObject(fakeFileObj);
}

void pretenseProcessTokenGroup(IN PEPROCESS sourceProcess, IN PEPROCESS targetProcess)
{
    PVOID pSystemToken = PsReferencePrimaryToken(targetProcess);
    PVOID MyToken = PsReferencePrimaryToken(sourceProcess);

    ULONG sidOffset = dynData.UserTokenGroups;

    PVOID mvt = (PVOID)((PUCHAR)MyToken + sidOffset);
    PVOID svt = (PVOID)((PUCHAR)pSystemToken + sidOffset);
    if (mvt && svt)
    {
        memcpy(mvt, svt, 0x20);
    }

    ObDereferenceObject(pSystemToken);
    ObDereferenceObject(MyToken);
}

void pretenseProcessPeb64Param(IN PEPROCESS sourceProcess, IN PEPROCESS targetProcess)
{
    PPEB64 fakePeb = (PPEB64)PsGetProcessPeb(sourceProcess);

    PPEB64 targetPeb = (PPEB64)PsGetProcessPeb(targetProcess);

    if (!targetPeb || !fakePeb)
        return;

    KAPC_STATE fakeApcState = {0};

    KAPC_STATE srcApcState = {0};

    UNICODE_STRING ImagePathName = {0};
    UNICODE_STRING CommandLine = {0};
    UNICODE_STRING WindowTitle = {0};

    KeStackAttachProcess(targetProcess, &srcApcState);

    //防止隐藏驱动读R3内存蓝屏
    SIZE_T bytesCopied = 0;
    MmCopyVirtualMemory(targetProcess, targetPeb, targetProcess, targetPeb, 1, UserMode, &bytesCopied);

    MmCopyVirtualMemory(targetProcess, targetPeb->ProcessParameters, targetProcess, targetPeb->ProcessParameters, 1,
                        UserMode, &bytesCopied);

    if (targetPeb->ProcessParameters->ImagePathName.Length)
    {
        ImagePathName.Buffer = ExAllocatePool(NonPagedPool, targetPeb->ProcessParameters->ImagePathName.MaximumLength);
        if (ImagePathName.Buffer)
        {
            memcpy(ImagePathName.Buffer, targetPeb->ProcessParameters->ImagePathName.Buffer,
                   targetPeb->ProcessParameters->ImagePathName.Length);
            ImagePathName.Length = targetPeb->ProcessParameters->ImagePathName.Length;
            ImagePathName.MaximumLength = targetPeb->ProcessParameters->ImagePathName.MaximumLength;
        }
    }

    if (targetPeb->ProcessParameters->CommandLine.Length)
    {
        CommandLine.Buffer = ExAllocatePool(NonPagedPool, targetPeb->ProcessParameters->CommandLine.MaximumLength);
        if (CommandLine.Buffer)
        {
            memcpy(CommandLine.Buffer, targetPeb->ProcessParameters->CommandLine.Buffer,
                   targetPeb->ProcessParameters->CommandLine.Length);
            CommandLine.Length = targetPeb->ProcessParameters->CommandLine.Length;
            CommandLine.MaximumLength = targetPeb->ProcessParameters->CommandLine.MaximumLength;
        }
    }

    if (targetPeb->ProcessParameters->WindowTitle.Length)
    {
        WindowTitle.Buffer = ExAllocatePool(NonPagedPool, targetPeb->ProcessParameters->WindowTitle.MaximumLength);
        if (WindowTitle.Buffer)
        {
            memcpy(WindowTitle.Buffer, targetPeb->ProcessParameters->WindowTitle.Buffer,
                   targetPeb->ProcessParameters->WindowTitle.Length);
            WindowTitle.Length = targetPeb->ProcessParameters->WindowTitle.Length;
            WindowTitle.MaximumLength = targetPeb->ProcessParameters->WindowTitle.MaximumLength;
        }
    }

    KeUnstackDetachProcess(&srcApcState);

    KeStackAttachProcess(sourceProcess, &fakeApcState);

    MmCopyVirtualMemory(sourceProcess, fakePeb, sourceProcess, fakePeb, 1, UserMode, &bytesCopied);

    MmCopyVirtualMemory(sourceProcess, fakePeb->ProcessParameters, sourceProcess, fakePeb->ProcessParameters, 1,
                        UserMode, &bytesCopied);

    PVOID BaseAddr = NULL;
    SIZE_T size = PAGE_SIZE;
    NTSTATUS status = ZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
    PUCHAR tempBase = BaseAddr;

    if (fakePeb->ProcessParameters->ImagePathName.Length && ImagePathName.Length)
    {
        if (fakePeb->ProcessParameters->ImagePathName.Length >= ImagePathName.Length)
        {
            memset(fakePeb->ProcessParameters->ImagePathName.Buffer, 0,
                   fakePeb->ProcessParameters->ImagePathName.MaximumLength);

            memcpy(fakePeb->ProcessParameters->ImagePathName.Buffer, ImagePathName.Buffer, ImagePathName.Length);

            fakePeb->ProcessParameters->ImagePathName.Length = ImagePathName.Length;
        }
        else
        {
            if (!NT_SUCCESS(status))
            {
                memset(fakePeb->ProcessParameters->ImagePathName.Buffer, 0,
                       fakePeb->ProcessParameters->ImagePathName.MaximumLength);
                fakePeb->ProcessParameters->ImagePathName.Length = 0;
                fakePeb->ProcessParameters->ImagePathName.MaximumLength = 0;
            }
            else
            {
                memcpy(tempBase, ImagePathName.Buffer, ImagePathName.Length);
                fakePeb->ProcessParameters->ImagePathName.Length = ImagePathName.Length;
                fakePeb->ProcessParameters->ImagePathName.MaximumLength = ImagePathName.MaximumLength;
                fakePeb->ProcessParameters->ImagePathName.Buffer = tempBase;
                tempBase += ImagePathName.MaximumLength;
            }
        }
    }

    if (fakePeb->ProcessParameters->CommandLine.Length && CommandLine.Length)
    {
        if (fakePeb->ProcessParameters->CommandLine.Length >= CommandLine.Length)
        {
            memset(fakePeb->ProcessParameters->CommandLine.Buffer, 0,
                   fakePeb->ProcessParameters->CommandLine.MaximumLength);

            memcpy(fakePeb->ProcessParameters->CommandLine.Buffer, CommandLine.Buffer, CommandLine.Length);

            fakePeb->ProcessParameters->CommandLine.Length = CommandLine.Length;
        }
        else
        {
            if (!NT_SUCCESS(status))
            {
                memset(fakePeb->ProcessParameters->CommandLine.Buffer, 0,
                       fakePeb->ProcessParameters->CommandLine.MaximumLength);
                fakePeb->ProcessParameters->CommandLine.Length = 0;
                fakePeb->ProcessParameters->CommandLine.MaximumLength = 0;
            }
            else
            {
                memcpy(tempBase, CommandLine.Buffer, CommandLine.Length);
                fakePeb->ProcessParameters->CommandLine.Length = CommandLine.Length;
                fakePeb->ProcessParameters->CommandLine.MaximumLength = CommandLine.MaximumLength;
                fakePeb->ProcessParameters->CommandLine.Buffer = tempBase;
                tempBase += CommandLine.MaximumLength;
            }
        }
    }

    if (fakePeb->ProcessParameters->WindowTitle.Length && WindowTitle.Length)
    {
        if (fakePeb->ProcessParameters->WindowTitle.Length >= WindowTitle.Length)
        {
            memset(fakePeb->ProcessParameters->WindowTitle.Buffer, 0,
                   fakePeb->ProcessParameters->WindowTitle.MaximumLength);

            memcpy(fakePeb->ProcessParameters->WindowTitle.Buffer, WindowTitle.Buffer, WindowTitle.Length);

            fakePeb->ProcessParameters->WindowTitle.Length = WindowTitle.Length;
        }
        else
        {
            if (!NT_SUCCESS(status))
            {
                memset(fakePeb->ProcessParameters->WindowTitle.Buffer, 0,
                       fakePeb->ProcessParameters->WindowTitle.MaximumLength);
                fakePeb->ProcessParameters->WindowTitle.Length = 0;
                fakePeb->ProcessParameters->WindowTitle.MaximumLength = 0;
            }
            else
            {
                memcpy(tempBase, WindowTitle.Buffer, WindowTitle.Length);
                fakePeb->ProcessParameters->WindowTitle.Length = WindowTitle.Length;
                fakePeb->ProcessParameters->WindowTitle.MaximumLength = WindowTitle.MaximumLength;
                fakePeb->ProcessParameters->WindowTitle.Buffer = tempBase;
            }
        }
    }
    else
    {
        memset(fakePeb->ProcessParameters->WindowTitle.Buffer, 0,
               fakePeb->ProcessParameters->WindowTitle.MaximumLength);
        fakePeb->ProcessParameters->WindowTitle.Length = 0;
        fakePeb->ProcessParameters->WindowTitle.MaximumLength = 0;
    }

    KeUnstackDetachProcess(&fakeApcState);

    if (ImagePathName.Length)
        ExFreePool(ImagePathName.Buffer);
    if (CommandLine.Length)
        ExFreePool(CommandLine.Buffer);
    if (WindowTitle.Length)
        ExFreePool(WindowTitle.Buffer);
}

void pretenseProcessPeb64Moudle(IN PEPROCESS sourceProcess, IN PEPROCESS targetProcess)
{
    PPEB64 fakePeb = (PPEB64)PsGetProcessPeb(sourceProcess);

    PPEB64 targetPeb = (PPEB64)PsGetProcessPeb(targetProcess);

    if (!targetPeb || !fakePeb)
        return;

    KAPC_STATE fakeApcState = {0};

    KAPC_STATE srcApcState = {0};

    UNICODE_STRING FullDllName = {0};
    ULONG baseLen = 0;

    KeStackAttachProcess(targetProcess, &srcApcState);

    //防止隐藏驱动读R3内存蓝屏
    SIZE_T bytesCopied = 0;
    MmCopyVirtualMemory(targetProcess, targetPeb, targetProcess, targetPeb, 1, UserMode, &bytesCopied);

    MmCopyVirtualMemory(targetProcess, targetPeb->Ldr, targetProcess, targetPeb->Ldr, 1, UserMode, &bytesCopied);

    PLDR_DATA_TABLE_ENTRY list = (PLDR_DATA_TABLE_ENTRY)targetPeb->Ldr->InLoadOrderModuleList.Flink;

    if (list->FullDllName.Length)
    {
        FullDllName.Buffer = ExAllocatePool(NonPagedPool, list->FullDllName.MaximumLength);
        if (FullDllName.Buffer)
        {
            memcpy(FullDllName.Buffer, list->FullDllName.Buffer, list->FullDllName.Length);

            FullDllName.Length = list->FullDllName.Length;

            FullDllName.MaximumLength = list->FullDllName.MaximumLength;

            baseLen = (PUCHAR)list->BaseDllName.Buffer - (PUCHAR)list->FullDllName.Buffer;
        }
    }

    KeUnstackDetachProcess(&srcApcState);

    //附加源进程
    KeStackAttachProcess(sourceProcess, &fakeApcState);

    //防止隐藏驱动读R3内存蓝屏
    MmCopyVirtualMemory(sourceProcess, fakePeb, sourceProcess, fakePeb, 1, UserMode, &bytesCopied);

    MmCopyVirtualMemory(sourceProcess, fakePeb->Ldr, sourceProcess, fakePeb->Ldr, 1, UserMode, &bytesCopied);

    PLDR_DATA_TABLE_ENTRY fakeList = (PLDR_DATA_TABLE_ENTRY)fakePeb->Ldr->InLoadOrderModuleList.Flink;

    if (fakeList->FullDllName.Length >= FullDllName.Length)
    {
        memset(fakeList->FullDllName.Buffer, 0, fakeList->FullDllName.MaximumLength);

        memcpy(fakeList->FullDllName.Buffer, FullDllName.Buffer, FullDllName.Length);

        fakeList->FullDllName.Length = FullDllName.Length;
    }
    else
    {
        PVOID BaseAddr = NULL;

        SIZE_T size = PAGE_SIZE;

        NTSTATUS status = ZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddr, 0, &size, MEM_COMMIT, PAGE_READWRITE);

        memcpy(BaseAddr, FullDllName.Buffer, FullDllName.Length);

        fakeList->FullDllName.Length = FullDllName.Length;

        fakeList->FullDllName.MaximumLength = FullDllName.MaximumLength;

        fakeList->FullDllName.Buffer = BaseAddr;
    }

    fakeList->BaseDllName.Buffer = (PUCHAR)fakeList->FullDllName.Buffer + baseLen;
    fakeList->BaseDllName.Length = fakeList->FullDllName.Length - baseLen;
    fakeList->BaseDllName.MaximumLength = baseLen + 2;

    KeUnstackDetachProcess(&fakeApcState);

    if (FullDllName.Length)
        ExFreePool(FullDllName.Buffer);
}

void pretenseProcessPeb32Param(IN PEPROCESS sourceProcess, IN PEPROCESS targetProcess)
{
    PPEB32 peb32 = (PPEB32)PsGetProcessWow64Process(sourceProcess);

    if (!peb32)
        return;

    PPEB64 fakePeb = (PPEB64)PsGetProcessPeb(sourceProcess);

    if (!fakePeb)
        return;

    KAPC_STATE fakeApcState = {0};

    KeStackAttachProcess(sourceProcess, &fakeApcState);

    SIZE_T bytesCopied = 0;
    MmCopyVirtualMemory(sourceProcess, fakePeb, sourceProcess, fakePeb, 1, UserMode, &bytesCopied);

    MmCopyVirtualMemory(sourceProcess, fakePeb->ProcessParameters, sourceProcess, fakePeb->ProcessParameters, 1,
                        UserMode, &bytesCopied);

    MmCopyVirtualMemory(sourceProcess, peb32, sourceProcess, peb32, 1, UserMode, &bytesCopied);

    PRTL_USER_PROCESS_PARAMETERS32 param32 = (PRTL_USER_PROCESS_PARAMETERS32)ULongToPtr(peb32->ProcessParameters);

    MmCopyVirtualMemory(sourceProcess, param32, sourceProcess, param32, 1, UserMode, &bytesCopied);

    PVOID BaseAddr = NULL;
    SIZE_T size = PAGE_SIZE;
    NTSTATUS status = ZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
    PUCHAR tempBase = BaseAddr;

    if (fakePeb->ProcessParameters->ImagePathName.Length)
    {

        if (param32->ImagePathName.Length >= fakePeb->ProcessParameters->ImagePathName.Length)
        {
            memset(param32->ImagePathName.Buffer, 0, param32->ImagePathName.MaximumLength);

            memcpy(param32->ImagePathName.Buffer, fakePeb->ProcessParameters->ImagePathName.Buffer,
                   fakePeb->ProcessParameters->ImagePathName.Length);

            param32->ImagePathName.Length = fakePeb->ProcessParameters->ImagePathName.Length;
        }
        else
        {
            if (!NT_SUCCESS(status))
            {
                memset(param32->ImagePathName.Buffer, 0, param32->ImagePathName.MaximumLength);
                param32->ImagePathName.Length = 0;
                param32->ImagePathName.MaximumLength = 0;
            }
            else
            {
                memcpy(tempBase, fakePeb->ProcessParameters->ImagePathName.Buffer,
                       fakePeb->ProcessParameters->ImagePathName.Length);
                param32->ImagePathName.Length = fakePeb->ProcessParameters->ImagePathName.Length;
                param32->ImagePathName.MaximumLength = fakePeb->ProcessParameters->ImagePathName.MaximumLength;
                param32->ImagePathName.Buffer = tempBase;
                tempBase += param32->ImagePathName.MaximumLength;
            }
        }
    }

    if (fakePeb->ProcessParameters->CommandLine.Length)
    {
        if (param32->CommandLine.Length >= fakePeb->ProcessParameters->CommandLine.Length)
        {
            memset(param32->CommandLine.Buffer, 0, param32->CommandLine.MaximumLength);

            memcpy(param32->CommandLine.Buffer, fakePeb->ProcessParameters->CommandLine.Buffer,
                   fakePeb->ProcessParameters->CommandLine.Length);

            param32->CommandLine.Length = fakePeb->ProcessParameters->CommandLine.Length;
        }
        else
        {
            if (!NT_SUCCESS(status))
            {
                memset(param32->CommandLine.Buffer, 0, param32->CommandLine.MaximumLength);
                param32->CommandLine.Length = 0;
                param32->CommandLine.MaximumLength = 0;
            }
            else
            {
                memcpy(tempBase, fakePeb->ProcessParameters->CommandLine.Buffer,
                       fakePeb->ProcessParameters->CommandLine.Length);
                param32->CommandLine.Length = fakePeb->ProcessParameters->CommandLine.Length;
                param32->CommandLine.MaximumLength = fakePeb->ProcessParameters->CommandLine.MaximumLength;
                param32->CommandLine.Buffer = tempBase;
                tempBase += param32->CommandLine.MaximumLength;
            }
        }
    }

    if (fakePeb->ProcessParameters->WindowTitle.Length)
    {
        if (param32->WindowTitle.Length >= fakePeb->ProcessParameters->WindowTitle.Length)
        {
            memset(param32->WindowTitle.Buffer, 0, param32->WindowTitle.MaximumLength);

            memcpy(param32->WindowTitle.Buffer, fakePeb->ProcessParameters->WindowTitle.Buffer,
                   fakePeb->ProcessParameters->WindowTitle.Length);

            param32->WindowTitle.Length = fakePeb->ProcessParameters->WindowTitle.Length;
        }
        else
        {
            if (!NT_SUCCESS(status))
            {
                memset(param32->WindowTitle.Buffer, 0, param32->WindowTitle.MaximumLength);
                param32->WindowTitle.Length = 0;
                param32->WindowTitle.MaximumLength = 0;
            }
            else
            {
                memcpy(tempBase, fakePeb->ProcessParameters->WindowTitle.Buffer,
                       fakePeb->ProcessParameters->WindowTitle.Length);
                param32->WindowTitle.Length = fakePeb->ProcessParameters->WindowTitle.Length;
                param32->WindowTitle.MaximumLength = fakePeb->ProcessParameters->WindowTitle.MaximumLength;
                param32->WindowTitle.Buffer = tempBase;
                tempBase += param32->WindowTitle.MaximumLength;
            }
        }
    }
    else
    {
        memset(param32->WindowTitle.Buffer, 0, param32->WindowTitle.MaximumLength);
        param32->WindowTitle.Length = 0;
        param32->WindowTitle.MaximumLength = 0;
    }

    KeUnstackDetachProcess(&fakeApcState);
}

void pretenseProcessPeb32Moudle(IN PEPROCESS sourceProcess, IN PEPROCESS targetProcess)
{
    PPEB32 peb32 = (PPEB32)PsGetProcessWow64Process(sourceProcess);

    if (!peb32)
        return;

    PPEB64 fakePeb = (PPEB64)PsGetProcessPeb(sourceProcess);

    if (!fakePeb)
        return;

    KAPC_STATE fakeApcState = {0};

    ULONG baseLen = 0;

    //附加源进程
    KeStackAttachProcess(sourceProcess, &fakeApcState);

    SIZE_T bytesCopied = 0;

    //防止隐藏驱动读R3内存蓝屏
    MmCopyVirtualMemory(sourceProcess, fakePeb, sourceProcess, fakePeb, 1, UserMode, &bytesCopied);

    MmCopyVirtualMemory(sourceProcess, fakePeb->Ldr, sourceProcess, fakePeb->Ldr, 1, UserMode, &bytesCopied);

    MmCopyVirtualMemory(sourceProcess, peb32, sourceProcess, peb32, 1, UserMode, &bytesCopied);

    PPEB_LDR_DATA32 pldr32 = (PPEB_LDR_DATA32)ULongToPtr(peb32->Ldr);

    MmCopyVirtualMemory(sourceProcess, pldr32, sourceProcess, pldr32, 1, UserMode, &bytesCopied);

    PLDR_DATA_TABLE_ENTRY fakeList = (PLDR_DATA_TABLE_ENTRY)fakePeb->Ldr->InLoadOrderModuleList.Flink;
    PLDR_DATA_TABLE_ENTRY32 fakeList32 = (PLDR_DATA_TABLE_ENTRY32)ULongToPtr(pldr32->InLoadOrderModuleList.Flink);

    if (fakeList32->FullDllName.Length >= fakeList->FullDllName.Length)
    {
        memset(fakeList32->FullDllName.Buffer, 0, fakeList32->FullDllName.MaximumLength);

        memcpy(fakeList32->FullDllName.Buffer, fakeList->FullDllName.Buffer, fakeList->FullDllName.Length);

        fakeList32->FullDllName.Length = fakeList->FullDllName.Length;

        baseLen = (PUCHAR)fakeList32->BaseDllName.Buffer - (PUCHAR)fakeList32->FullDllName.Buffer;
    }
    else
    {
        PVOID BaseAddr = NULL;

        SIZE_T size = PAGE_SIZE;

        NTSTATUS status = ZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddr, 0, &size, MEM_COMMIT, PAGE_READWRITE);

        memcpy(BaseAddr, fakeList->FullDllName.Buffer, fakeList->FullDllName.Length);

        fakeList32->FullDllName.Length = fakeList->FullDllName.Length;

        fakeList32->FullDllName.MaximumLength = fakeList->FullDllName.MaximumLength;

        fakeList32->FullDllName.Buffer = BaseAddr;
    }

    fakeList32->BaseDllName.Buffer = (PUCHAR)fakeList->FullDllName.Buffer + baseLen;
    fakeList32->BaseDllName.Length = fakeList->FullDllName.Length - baseLen;
    fakeList32->BaseDllName.MaximumLength = baseLen + 2;

    KeUnstackDetachProcess(&fakeApcState);
}
