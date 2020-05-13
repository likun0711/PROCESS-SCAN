# PROCESS-SCAN
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <stdio.h>

BOOL GetProcessList();
void printError(TCHAR* msg);
void main()
{ 
	GetProcessList();
}
BOOL GetProcessList()
{ 
	HANDLE hProcessSnap; 
	PROCESSENTRY32 pe32; //用来存放进程信息
	hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 ); 
	if( hProcessSnap == INVALID_HANDLE_VALUE ) 
	{ 
		printError( TEXT("CreateToolhelp32Snapshot (of processes)") ); 
		return( FALSE ); 
	} // 设置结构体
	pe32.dwSize = sizeof( PROCESSENTRY32 ); // 检索有关第一个进程的信息
	// 如果失败则退出
	if( !Process32First( hProcessSnap, &pe32 ) ) 
	{ 
		printError( TEXT("Process32First") ); // 显示失败原因
		CloseHandle( hProcessSnap );
		( FALSE ); 
	} // 遍历进程信息，并依次显示
	do {
		printf( "\n\n=====================================================" ); 
		_tprintf( TEXT("\nPROCESS NAME: %s"), pe32.szExeFile ); 
		printf( "\n-----------------------------------------------------" ); 
		printf( "\n Process ID = 0x%08X", pe32.th32ProcessID ); 
		printf( "\n Thread count = %d", pe32.cntThreads ); 
		printf( "\n Parent process ID = 0x%08X", pe32.th32ParentProcessID ); 
		printf( "\n Priority base = %d", pe32.pcPriClassBase ); 
	} 
	while( Process32Next( hProcessSnap, &pe32 ) );
	CloseHandle( hProcessSnap ); 
	return( TRUE );
}
void printError( TCHAR* msg )
{ 
	DWORD eNum; 
	TCHAR sysMsg[256]; 
	TCHAR* p; 
	eNum = GetLastError( ); 
	FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, eNum, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
		sysMsg,256, NULL ); 
	p = sysMsg;
	while( ( *p > 31 ) || ( *p == 9 ) ) 
		++p; 
	do {
		*p-- = 0;
	} 
	while((p>=sysMsg)&&((*p=='.')||(*p<33))); 
	_tprintf( TEXT("\n WARNING: %s failed with error %d (%s)"), msg, eNum, sysMsg );
} 
