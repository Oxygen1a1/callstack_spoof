#pragma once
#ifdef _KERNEL_MODE
#include <fltKernel.h>
#include <ntifs.h>
#include <ntimage.h>
#pragma warning(disable : 4083)
#pragma warning(disable : 4005)
#include <xtr1common>
#pragma warning(default : 4083)
#pragma warning(default : 4005)
#else
#include <Windows.h>
#include <utility>
#include <TlHelp32.h>
#endif
#include  <Intrin.h> 

//爆栈 调用这个类之后,在析构函数调用之前,栈都无法遍历
#define SPOOF_FUNC CallSpoofer::SpoofFunc spoof(_AddressOfReturnAddress())
//伪装栈调用 调用这个
#define SPOOF_CALL(retType,funcPtr) CallSpoofer::SpoofCall<retType,decltype(funcPtr)>(funcPtr)
//CallSpoofer::SpoofCall<void, decltype(foo2)> a(foo2);
namespace CallSpoofer {
#pragma warning(disable : 4996)
	//from vmprotect src
	typedef enum _SYSTEM_INFORMATION_CLASS {
		SystemModuleInformation = 0xb,
		SystemKernelDebuggerInformation = 0x23,
		SystemFirmwareTableInformation = 0x4c
	} SYSTEM_INFORMATION_CLASS;

	EXTERN_C __kernel_entry NTSTATUS ZwQuerySystemInformation(
	 SYSTEM_INFORMATION_CLASS SystemInformationClass,
	 PVOID                    SystemInformation,
	 ULONG                    SystemInformationLength,
	 PULONG                   ReturnLength
	);

#ifndef _KERNEL_MODE
#pragma comment(lib,"ntdll.lib")
#define PAGE_SIZE 0x1000
	typedef enum _MEMORY_INFORMATION_CLASS {
		MemoryBasicInformation
	} MEMORY_INFORMATION_CLASS;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

	EXTERN_C NTSYSAPI NTSTATUS ZwQueryVirtualMemory(
		HANDLE                   ProcessHandle,
		PVOID                    BaseAddress,
		MEMORY_INFORMATION_CLASS MemoryInformationClass,
		PVOID                    MemoryInformation,
		SIZE_T                   MemoryInformationLength,
		PSIZE_T                  ReturnLength
	);
#else


	const unsigned HistoryTableSize = 0x300;

	typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY RUNTIME_FUNCTION, * PRUNTIME_FUNCTION;
	EXTERN_C NTSYSAPI
		PRUNTIME_FUNCTION
		NTAPI
		RtlLookupFunctionEntry(
			_In_ DWORD64 ControlPc,
			_Out_ PDWORD64 ImageBase,
			_Inout_opt_ PCHAR HistoryTable
		);
#endif // 

	typedef struct _SYSTEM_MODULE_ENTRY
	{
#ifdef _WIN64
		ULONGLONG Unknown1;
		ULONGLONG Unknown2;
#else
		ULONG Unknown1;
		ULONG Unknown2;
#endif
		PVOID BaseAddress;
		ULONG Size;
		ULONG Flags;
		ULONG EntryIndex;
		USHORT NameLength;  // Length of module name not including the path, this field contains valid value only for NTOSKRNL module
		USHORT PathLength;  // Length of 'directory path' part of modulename
#ifdef _KERNEL_MODE
		CHAR Name[MAXIMUM_FILENAME_LENGTH];
#else
		CHAR Name[256];
#endif
	} SYSTEM_MODULE_ENTRY;

	typedef struct _SYSTEM_MODULE_INFORMATION
	{
		ULONG Count;
#ifdef _WIN64
		ULONG Unknown1;
#endif
		SYSTEM_MODULE_ENTRY Module[1];
	} SYSTEM_MODULE_INFORMATION;

	const auto MAX_SHELLCODE_COUNT = 0x100;
	const auto POOL_TAG = 'cssf';
	//加密堆栈的密钥
	const auto xor_key = 0xff00ff00ff00ff00;
	//函数最大不超过一个页 超过肯定也找不到这么大的空白地址
	const auto MAX_FUNC_SIZE = PAGE_SIZE;
	//Spoof当前函数 只留一个retAddr
	//原理是动态修改返回地址,析构函数再变回来
	class SpoofFunc {

	public:
		SpoofFunc(void* retAddrInStack) :_retAddrInStack(retAddrInStack){

			tmp = *reinterpret_cast<UINT_PTR*>(retAddrInStack) ^ xor_key;
			*reinterpret_cast<UINT_PTR*>(retAddrInStack) = 0;
		}
		~SpoofFunc() {
			*reinterpret_cast<UINT_PTR*>(_retAddrInStack) = tmp ^ xor_key;
		}
	private:
		void* _retAddrInStack;
		UINT_PTR encodeAddrValue;
		ULONG_PTR tmp;

	};


	ULONG getFuncSize(void* addr) {
		//用异常表找是最准确的 内核的话考虑map加载的驱动,所以可能不用这玩意
		//可能会有错误
		DWORD64 base = 0;
#ifdef _KERNEL_MODE
		CHAR table[HistoryTableSize]{0};
		auto rtFuncTbl = RtlLookupFunctionEntry((DWORD64)addr, &base, table);
#else
		UNWIND_HISTORY_TABLE table{ 0 };
		auto rtFuncTbl = RtlLookupFunctionEntry((DWORD64)addr, &base, &table);
#endif
		
		if (rtFuncTbl != nullptr) {

			return rtFuncTbl->EndAddress - rtFuncTbl->BeginAddress;
		}
		//实在找不到 用这个方法找

		//这样不准确,如果是代码段出现cc 不一定是函数结束
		//往上遍历 往下遍历 找到int3(函数之间对齐),可能会不准确 但是一定会偏大 不会小 所以没问题
		unsigned i = 0;
		for (;i<MAX_FUNC_SIZE; i++) {
			if (reinterpret_cast<unsigned char*>(addr)[i] == 0xcc) {
				//find
				return i;
			}

		}
		i = 0;
		return i;
	}
	
	
	//from cow inject master
	//查找一块空闲的地址
	//不确定是不是可以用于
	void* getFreeSpaceR3(void* start,ULONG size,ULONG needSize) {

		size_t return_length;

		for (uintptr_t address = (uintptr_t)start; address <= (uintptr_t)start + size; address += sizeof(uintptr_t)) {
			__try
			{

				//ProbeForRead((void*)address, needSize, 0x1);
				if (*(uintptr_t*)address == 0x00 || *(uintptr_t*)address == 0x90)
				{
					MEMORY_BASIC_INFORMATION memory_information = { 0 };
					NTSTATUS status = ZwQueryVirtualMemory((HANDLE)-1, (PVOID)address, MemoryBasicInformation, &memory_information, needSize, &return_length);
					if (NT_SUCCESS(status)) {
						if ((memory_information.Protect == PAGE_EXECUTE || memory_information.Protect == PAGE_EXECUTE_READ || memory_information.Protect == PAGE_EXECUTE_READWRITE || memory_information.Protect == PAGE_EXECUTE_WRITECOPY) == false) {
							continue;
						}
					}
					uintptr_t count = 0;
					bool is_good = true;
					uintptr_t max_count = 0;
					for (; count < needSize && is_good; count += sizeof(uintptr_t))
					{
						max_count++;
						auto check_ptr = (uintptr_t*)((PUCHAR)address + count);
						if (*check_ptr != 0x0 && *check_ptr != 0x90)
						{
							is_good = false;
							break;
						}
					}
					if (is_good) {
						return (void*)address;
					}
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				continue;
			}
		}

		return NULL;

	}

#ifdef _KERNEL_MODE
	//必须提供内核的模块基质
	//获取text节区的空闲地址
	void* getFreeSpaceR0(void* start, ULONG size, ULONG needSize) {
		if (start == nullptr || size == 0 || needSize == 0) return NULL;

		auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(start);
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			return nullptr;
		}
		auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>
			((UINT_PTR)start + dosHeader->e_lfanew);
		auto secCount = ntHeaders->FileHeader.NumberOfSections;

		auto sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(
			(UINT_PTR)ntHeaders +
			sizeof ntHeaders->Signature +
			sizeof ntHeaders->FileHeader +
			ntHeaders->FileHeader.SizeOfOptionalHeader);

		for (unsigned i = 0; i < secCount; i++) {
			if (strcmp((PCCHAR)sections[i].Name, ".text") == 0) {
				//find
				auto secSize = sections[i].Misc.VirtualSize;
				auto rva = sections[i].VirtualAddress;
				for (unsigned j = 0; j < secSize; j++) {
					auto comMem = ExAllocatePoolWithTag(NonPagedPool, needSize, POOL_TAG);
					if (comMem == nullptr) break;
					memset(comMem, 0, needSize);
					bool isFind = false;
					if (RtlCompareMemory((PCCHAR)start + rva + j, comMem, needSize) == needSize) {
						isFind = true;

					}
					ExFreePool(comMem);
					if (isFind) {
						return (PCCHAR)start + rva + j;
					}
				}
			}

		}

		return nullptr;

	}


	void* getEmptySpaceForR0(ULONG needSize) {
		//通过NtQueryInfo遍历
		SYSTEM_MODULE_INFORMATION* infoBuf=nullptr;
		ULONG bufSize = 0;
		auto status = ZwQuerySystemInformation(SystemModuleInformation, infoBuf, 0, &bufSize);
		bufSize *= 2;
		infoBuf = static_cast<SYSTEM_MODULE_INFORMATION*>(
			ExAllocatePoolWithTag(NonPagedPool, bufSize, POOL_TAG));
		if (infoBuf == nullptr) return nullptr;

		status = ZwQuerySystemInformation(SystemModuleInformation, infoBuf, bufSize, &bufSize);
		if (!NT_SUCCESS(status)) {

			ExFreePool(infoBuf);
			return nullptr;
		}

		do {

			//开始遍历 查找空的地方
			for (unsigned i = 0; i < infoBuf->Count; i++) {
				SYSTEM_MODULE_ENTRY* moduleEntry = &infoBuf->Module[i];
				//不能修改win32 hal ntos 否则会PG
				if(strstr(moduleEntry->Name,"ntoskrnl")!=nullptr || 
					strstr(moduleEntry->Name, "win32k")!=nullptr ||
					strstr(moduleEntry->Name, "hal") != nullptr
					) continue;

				auto emptySpace = getFreeSpaceR0(moduleEntry->BaseAddress,
					moduleEntry->Size, needSize);

				//由于后面 MapIoSpace的特殊(地址必须在一个4kb 所以这里进行个判断
				if (emptySpace == nullptr) continue;
				else if ( ((UINT_PTR)(emptySpace)+needSize)>>PAGE_SHIFT>
					((UINT_PTR)(emptySpace)>>PAGE_SHIFT)  ) {
					//判断是否跨页 跨页则不要
					continue;
				}
				else {

					//find
					ExFreePool(infoBuf);
					return emptySpace;
				}

			}

		} while (0);

		//走到这就是失败了;
		if (infoBuf) {

			ExFreePool(infoBuf);
			infoBuf = nullptr;
		}
		return nullptr;
	}

#endif

#ifndef _KERNEL_MODE
	void* getEmptySpaceForR3(size_t needSize) {
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
		if (hSnapshot == INVALID_HANDLE_VALUE) {
			return nullptr;
		}

		MODULEENTRY32 me32;
		me32.dwSize = sizeof(MODULEENTRY32);
		// 获取第一个模块信息
		if (Module32First(hSnapshot, &me32)) {
			do {

				auto emptySpace = getFreeSpaceR3(me32.modBaseAddr, me32.modBaseSize, needSize);
				if (emptySpace == nullptr) continue;
				else return emptySpace;

			} while (Module32Next(hSnapshot, &me32));  // 遍历其他模块
		}
		else {
			//std::cerr << "Failed to enumerate modules!" << std::endl;
		}

		CloseHandle(hSnapshot);
		return nullptr;
	}
#endif
	

#ifdef _KERNEL_MODE
	bool _memcpy(PVOID address, PVOID target_address, ULONG length)
	{
		bool result = false;
		PHYSICAL_ADDRESS physicial_address;
		physicial_address = MmGetPhysicalAddress(address);
		if (physicial_address.QuadPart)
		{
			PVOID maped_mem = MmMapIoSpace(physicial_address, length, MmNonCached);
			if (maped_mem)
			{
				memcpy(maped_mem, target_address, length);
				MmUnmapIoSpace(maped_mem, length);
				result = true;
			}
		}
		return result;
	}
#endif
	//shellcode 生成器
	//用于生成shellcode地址的,本质上就是复制过去,R3是遍历PEB
	//R0是调用NtQuery来获取不同的基质
	//然后使用暴力搜搜,搜空白地址
	//理论上shellcode应当越小越好
	__forceinline void* shellcodeGenerate(void* funcAddr) {
		auto size = getFuncSize(funcAddr);
		if (size == 0) return nullptr;
		auto emptySpace = (void*)nullptr;
#ifdef _KERNEL_MODE
		emptySpace = getEmptySpaceForR0(size);
#else
		emptySpace = getEmptySpaceForR3(size);
#endif
		if (emptySpace==nullptr)
		{
			return nullptr;
		}


#ifdef _KERNEL_MODE
		//如果是R0 不可以轻易地写 要MDL或者MapIoSpace
		auto suc=_memcpy(emptySpace, funcAddr, size);
		if (!suc) return nullptr;
#else
		//r3 需要先VirtualProtect
		DWORD dwOldProtect = 0;
		VirtualProtect(emptySpace, size, PAGE_EXECUTE_READWRITE, &dwOldProtect);
		memcpy(emptySpace, funcAddr, size);
		VirtualProtect(emptySpace, size, dwOldProtect, &dwOldProtect);
#endif 
		return emptySpace;

	}
	
	//shellcode 根据模板编程的特点,最终编译器会生成多个同名但是参数不一样的函数
	
	template<typename RetType,typename Func,typename... Args>
	RetType shellcode(Func f, Args&... args) {
		
		//先爆栈
		using return_type = RetType;
		void* ret_addr_in_stack = _AddressOfReturnAddress();
		uintptr_t temp = *(uintptr_t*)ret_addr_in_stack;
		temp ^= xor_key;
		*(uintptr_t*)ret_addr_in_stack = 0;

		//返回值为void 不返回
		if constexpr (std::is_same<return_type, void>::value)
		{
			f(args...);
			temp ^= xor_key;
			*(uintptr_t*)ret_addr_in_stack = temp;
		}
		else
		{
			return_type&& ret = f(args...);
			temp ^= xor_key;
			*(uintptr_t*)ret_addr_in_stack = temp;
			return ret;
		}

	}

	//调用函数 并且伪造堆栈
	template<typename RetType, class Func>
	class SpoofCall {

	private:
		Func* _funcPtr;//函数指针
	public:
		SpoofCall(Func* func) : _funcPtr(func) {}

		//类型参数包
		template<typename... Args>
		__forceinline RetType operator()(Args&&... args) {

			//先混淆此函数
			SPOOF_FUNC;
			//这里使用两个static 变量
			//这是因为模块 编译期间会根据类型 参数个数生成多个函数
			//获取当前函数类型
			using shellcodeType = decltype(&shellcode<RetType, Func*, Args...>);

			//获取当前函数的地址(用于复制shellcode 这个需要比较
			shellcodeType curShellcode = &shellcode<RetType, Func*, Args...>;

			shellcodeType targetShellcode{};
			static ULONG count = 0;
			int idx{};

			//存放的是原来shellcode的地址
			static shellcodeType oriShellcodeArry[MAX_SHELLCODE_COUNT]{};

			//存放的是复制后的shellcode地址 二者是对应的(索引对应
			static shellcodeType allocShellcodeArry[MAX_SHELLCODE_COUNT]{};

			

			
			while (oriShellcodeArry[idx]) {
				if (oriShellcodeArry[idx] == curShellcode) {
					//find
					targetShellcode = allocShellcodeArry[idx];
					break;
				}
				idx++;
			}

			if (!targetShellcode) {
				//为空则需要进行复制 说明之前还没复制
				targetShellcode =
					reinterpret_cast<shellcodeType>(shellcodeGenerate((void*)curShellcode));
				if (targetShellcode == nullptr) return RetType{};

				allocShellcodeArry[count] = targetShellcode;
				oriShellcodeArry[count] = curShellcode;
				count++;
			}

			return targetShellcode(_funcPtr, args...);
		}
		
	};
#pragma warning(default : 4996)
}