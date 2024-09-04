// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "HookInstall.h"

PVOID AllocateNearbyMemory(PVOID TargetAddress)
{
    SYSTEM_INFO SysInfo;
    GetSystemInfo(&SysInfo);

    const DWORD PAGE_SIZE = SysInfo.dwPageSize;

    uintptr_t StartRange = (uintptr_t)TargetAddress - 0x01000000;
    uintptr_t EndRange = (uintptr_t)TargetAddress + 0x01000000;
    uintptr_t Current = StartRange;

    while (Current < EndRange)
    {
        VOID* AllocatedMem = VirtualAlloc((LPVOID)Current, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (AllocatedMem)
        {
            return AllocatedMem;
        }

        Current += PAGE_SIZE;

    }

    return NULL;
}


PVOID CreateMiddleFunction(BYTE* TargetFunction, BYTE* DetourFunction)
{

    PVOID MiddleFunction = AllocateNearbyMemory(TargetFunction);
    if (MiddleFunction == NULL)
    {
        // Failed creating the middle function near to the target function
        printf("Failed creating the middle function near to the target function\n");
        return NULL;
    }

    // Now we have a block size of memory near the target.
    // lets create the the jump to the detour now
    BYTE AbsolutJump[] =
    {
        0x49, 0xBA, /*MOV R10, Address OP*/
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Place holder for 64bit address
        0x41, 0xFF, 0xE2  // JMP R10
    };

    // Insert detour address to the code
    *(uintptr_t*)(AbsolutJump + 2) = (uintptr_t)DetourFunction;

    // Write the AbsolutJump to the middle function memory
    memcpy(MiddleFunction, AbsolutJump, sizeof(AbsolutJump));

    return MiddleFunction;
}

BOOL Hook(BYTE* TargetFunction, BYTE* DetourFunction, int Length)
{
    if (Length < 5)
    {
        return FALSE;
    }

    PVOID MiddleFunction = CreateMiddleFunction(TargetFunction, (BYTE*)DetourFunction);

    if (MiddleFunction == NULL)
    {
        // Failed creating the middle function near to the target function
        printf("Failed creating the middle function near to the target function\n");
        return FALSE;
    }

    DWORD OldProtection;

    if (!VirtualProtect(TargetFunction, Length, PAGE_EXECUTE_READWRITE, &OldProtection))
        return FALSE;

    // Calculate relative address for a 32-bit offset
    uintptr_t relativeAddress = ((uintptr_t)MiddleFunction - (uintptr_t)TargetFunction) - 5;

    // Clean from leftovers after jump
    memset(TargetFunction, 0x90, Length);

    // Insert jump instruction (0xE9) and relative address
    *TargetFunction = 0xE9;
    *(uint32_t*)(TargetFunction + 1) = (uint32_t)relativeAddress;

    // Restore original protection
    VirtualProtect(TargetFunction, Length, OldProtection, &OldProtection);

    return TRUE;
}



// Function to create a trampoline
PVOID CreateTrampoline(BYTE* TargetFunction, BYTE* DetourFunction, int Length)
{

    // Validate that we have enough slots for relative jump instruction
    if (Length < 5)
    {
        return NULL;
    }

    // Allocate memory for the trampoline
    VOID* TrampolineAddress = VirtualAlloc(nullptr, Length + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!TrampolineAddress)
    {
        printf("Memory allocation for trampoline failed\n");
        return nullptr;
    }

    // Copy original code to trampoline
    memcpy(TrampolineAddress, TargetFunction, Length);

    // Calculate the jump back address after execution ended
    uintptr_t AbsoluteJumpBackToTarget = (uintptr_t)(TargetFunction + Length);

    // Insert the jump back instruction at the end of the trampoline
    BYTE AbsolutJump[] =
    {
        0x49, 0xBA, /*MOV R10, Address OP*/
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Place holder for 64bit address
        0x41, 0xFF, 0xE2  // JMP R10
    };

    // Insert Target address to the code
    *(uintptr_t*)(AbsolutJump + 2) = AbsoluteJumpBackToTarget;

    // Write the AbsolutJump to the target into the trampoline after stolen bytes
    memcpy((BYTE*)TrampolineAddress + Length, AbsolutJump, sizeof(AbsolutJump));

    return TrampolineAddress;
}

// Detour function for MessageBoxA
int WINAPI MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    // Call the original function via trampoline
    return trampoline(hWnd, "Hooked Message Box Text!", "(>.<)", uType);
}

// Function to get the address of MessageBoxA from user32.dll
FARPROC GetMessageBoxAAddress() {
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if (!hUser32) {
        printf("Failed to load user32.dll\n");
        return nullptr;
    }
    FARPROC pMessageBoxA = GetProcAddress(hUser32, "MessageBoxA");
    if (!pMessageBoxA) {
        printf("Failed to get address of MessageBoxA\n");
        FreeLibrary(hUser32);
        return nullptr;
    }
    return pMessageBoxA;
}

VOID InstallMessageBoxAHook()
{
    int HookLength = 7;
    auto OriginMessageBoxA = (MessageBoxAPtr)GetMessageBoxAAddress();
    trampoline = (MessageBoxAPtr)CreateTrampoline((BYTE*)GetMessageBoxAAddress(), (BYTE*)OriginMessageBoxA, HookLength);
    Hook((BYTE*)OriginMessageBoxA, (BYTE*)MyMessageBoxA, HookLength);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        InstallMessageBoxAHook();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

