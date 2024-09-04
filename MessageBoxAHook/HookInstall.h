#pragma once
#include <iostream>
#include <Windows.h>

//Function pointer type for MessageBoxW
typedef int (WINAPI* MessageBoxAPtr)(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCSTR lpText,
	_In_opt_ LPCSTR lpCaption,
	_In_ UINT uType);

static MessageBoxAPtr trampoline; // Global variable to hold the trampoline function


// Create function that is relative close to the TargetFunction
// And performs absolute jump to the DetourFunction
PVOID CreateMiddleFunction(BYTE* TargetFunction, BYTE* DetourFunction);

// Allocation page of memory in close to TargetAddress (+/- 2GB)
PVOID AllocateNearbyMemory(PVOID TargetAddress);

// Install to jump to the detour function
// The callee need to create trampoline and
// make sure the detour function calls the trampoline
BOOL Hook(BYTE* TargetFunction, BYTE* DetourFunction, int Length);

// Create trampoline function which steals from the target Length amount of bytes
// And when called, run those instructions and the performe absolute jump to the target
// At the address after the stolen bytes
PVOID CreateTrampoline(BYTE* TargetFunction, BYTE* DetourFunction, int Length);

// Get the address of the win api function MessageBoxA from user32.dll
FARPROC GetMessageBoxAAddress();

int WINAPI MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
