#include <phnt_windows.h>
#include <phnt.h>

// fnv1a begin

struct fnv1a_state
{
	DWORD m_sum;
};

constexpr static inline void fnv1a_init(fnv1a_state& state)
{
	state.m_sum = 0x811c9dc5;
}

constexpr static inline void fnv1a_append(fnv1a_state& state, BYTE const& val)
{
	state.m_sum ^= ((DWORD)(val));
	state.m_sum *= 0x01000193;
}

constexpr static inline void fnv1a_append(fnv1a_state& state, CHAR const& val)
{
	fnv1a_append(state, ((BYTE)(val)));
}

constexpr static inline void fnv1a_append(fnv1a_state& state, LPCCH const& str, DWORD const& len)
{
	DWORD n;
	DWORD i;

	n = len;
	for(i = 0; i != n; ++i)
	{
		fnv1a_append(state, str[i]);
	}
}

constexpr static inline DWORD fnv1a_finish(fnv1a_state const& state)
{
	return state.m_sum;
}

constexpr static inline DWORD fnv1a(LPCCH const& str, DWORD const& len)
{
	fnv1a_state hasher;

	fnv1a_init(hasher);
	fnv1a_append(hasher, str, len);
	return fnv1a_finish(hasher);
}

constexpr static inline DWORD fnv1a(PWCHAR const& str, DWORD const& len)
{
	fnv1a_state hasher;
	DWORD n;
	DWORD i;
	UCHAR uchar;

	fnv1a_init(hasher);
	n = len;
	for(i = 0; i != n; ++i)
	{
		uchar = (str[i] >= L'A' && str[i] <= L'Z') ? ((UCHAR)(str[i] + (L'a' - L'A'))) : ((UCHAR)(str[i]));
		fnv1a_append(hasher, uchar);
	}
	return fnv1a_finish(hasher);
}

static inline DWORD fnv1a(LPCVOID const& str, DWORD const& len)
{
	return fnv1a(((LPCCH)(str)), len);
}

template<typename t>
static inline DWORD fnv1a(t const&) = delete;

template<>
constexpr static inline DWORD fnv1a<LPCCH>(LPCCH const& str)
{
	LPCCH txt;
	fnv1a_state hasher;

	txt = str;
	fnv1a_init(hasher);
	while(*txt)
	{
		fnv1a_append(hasher, *txt++);
	}
	return fnv1a_finish(hasher);
}

template<DWORD N>
constexpr static inline DWORD fnv1a(CHAR const(&str)[N]) noexcept
{
	return fnv1a(str, N - 1);
}

// fnv1a end

static inline HMODULE find_module(PPEB const& peb, DWORD const& k_hash)
{
	HMODULE mod;
	PPEB_LDR_DATA ldr;
	PLDR_DATA_TABLE_ENTRY list;
	PLDR_DATA_TABLE_ENTRY entry;
	SHORT len;
	PWCHAR name;
	DWORD sum;

	mod = NULL;
	ldr = peb->Ldr;
	list = ((PLDR_DATA_TABLE_ENTRY)(((PBYTE)(&ldr->InLoadOrderModuleList)) + offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks)));
	entry = ((PLDR_DATA_TABLE_ENTRY)(list->InLoadOrderLinks.Flink));
	while(entry != list)
	{
		len = entry->BaseDllName.Length;
		name = entry->BaseDllName.Buffer;
		sum = fnv1a(name, len / sizeof(WCHAR));
		if(sum == k_hash)
		{
			mod = ((HMODULE)(entry->DllBase));
			break;
		}
		entry = ((PLDR_DATA_TABLE_ENTRY)(entry->InLoadOrderLinks.Flink));
	}
	return mod;
}

static inline LPVOID va_to_real(HMODULE const& mod, PIMAGE_SECTION_HEADER const& sections, WORD const& count, DWORD const& va, DWORD const& sz)
{
	LPVOID real;
	LPBYTE base;
	WORD n;
	WORD i;
	DWORD sec_va;
	DWORD raw;

	real = NULL;
	base = ((LPBYTE)(mod));
	n = count;
	for(i = 0; i != n; ++i)
	{
		sec_va = sections[i].VirtualAddress;
		if(va >= sec_va && va + sz <= sec_va + sections->SizeOfRawData)
		{
			raw = sections[i].PointerToRawData + (va - sec_va);
			real = base + raw;
			break;
		}
	}
	return real;
}

static inline FARPROC find_proc(HMODULE const& mod, DWORD const& k_hash)
{
	FARPROC proc;
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_DATA_DIRECTORY arr_dirs;
	DWORD n_dirs;
	DWORD exp_dir_va;
	DWORD exp_dir_sz;
	PIMAGE_SECTION_HEADER arr_sections;
	WORD n_sections;
	PIMAGE_EXPORT_DIRECTORY exp_dir_real;
	DWORD n_names;
	LPDWORD arr_names;
	DWORD i_names;
	DWORD name_va;
	LPCCH name_real;
	DWORD sum;
	LPWORD arr_ordinals;
	WORD ordinal;
	LPDWORD arr_functions;
	DWORD func_va;

	proc = NULL;
	dos = ((PIMAGE_DOS_HEADER)(mod));
	nt = ((PIMAGE_NT_HEADERS)(((LPBYTE)(mod)) + dos->e_lfanew));
	arr_dirs = ((PIMAGE_DATA_DIRECTORY)(((LPBYTE)(&nt->OptionalHeader.NumberOfRvaAndSizes)) + sizeof(nt->OptionalHeader.NumberOfRvaAndSizes)));
	n_dirs = nt->OptionalHeader.NumberOfRvaAndSizes;
	if(n_dirs > IMAGE_DIRECTORY_ENTRY_EXPORT)
	{
		exp_dir_va = arr_dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		exp_dir_sz = arr_dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
		arr_sections = ((PIMAGE_SECTION_HEADER)(((LPBYTE)(arr_dirs)) + n_dirs * sizeof(IMAGE_DATA_DIRECTORY)));
		n_sections = nt->FileHeader.NumberOfSections;
		exp_dir_real = ((PIMAGE_EXPORT_DIRECTORY)(va_to_real(mod, arr_sections, n_sections, exp_dir_va, exp_dir_sz)));
		n_names = exp_dir_real->NumberOfNames;
		arr_names = ((LPDWORD)(va_to_real(mod, arr_sections, n_sections, exp_dir_real->AddressOfNames, n_names * sizeof(DWORD))));
		for(i_names = 0; i_names != n_names; ++i_names)
		{
			name_va = arr_names[i_names];
			name_real = ((LPCCH)(va_to_real(mod, arr_sections, n_sections, name_va, 1)));
			sum = fnv1a(name_real);
			if(sum == k_hash)
			{
				arr_ordinals = ((LPWORD)(va_to_real(mod, arr_sections, n_sections, exp_dir_real->AddressOfNameOrdinals, exp_dir_real->NumberOfNames * sizeof(arr_ordinals[0]))));
				ordinal = arr_ordinals[i_names];
				arr_functions = ((LPDWORD)(va_to_real(mod, arr_sections, n_sections, exp_dir_real->AddressOfFunctions, exp_dir_real->NumberOfFunctions * sizeof(arr_functions[0]))));
				func_va = arr_functions[ordinal];
				proc = ((FARPROC)(va_to_real(mod, arr_sections, n_sections, func_va, sizeof(DWORD))));
				break;
			}
		}
	}
	return proc;
}

static constexpr DWORD const k_hash_kernel = fnv1a("kernel32.dll");
static constexpr DWORD const k_hash_ExitProcess = fnv1a("ExitProcess");
static constexpr DWORD const k_hash_LoadLibraryA = fnv1a("LoadLibraryA");
static constexpr DWORD const k_hash_MessageBoxA = fnv1a("MessageBoxA");

typedef void(__stdcall*tfn_ExitProcess)(UINT);
typedef HMODULE(__stdcall*tfn_LoadLibraryA)(LPCSTR);
typedef INT(__stdcall*tfn_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);

// ========== sound ==========
namespace sound
{
typedef struct wavehdr_tag
{
	LPSTR                   lpData;
	DWORD                   dwBufferLength;
	DWORD                   dwBytesRecorded;
	DWORD_PTR               dwUser;
	DWORD                   dwFlags;
	DWORD                   dwLoops;
	struct wavehdr_tag FAR* lpNext;
	DWORD_PTR               reserved;
} WAVEHDR, *PWAVEHDR, NEAR *NPWAVEHDR, FAR *LPWAVEHDR;
typedef struct tWAVEFORMATEX
{
	WORD  wFormatTag;
	WORD  nChannels;
	DWORD nSamplesPerSec;
	DWORD nAvgBytesPerSec;
	WORD  nBlockAlign;
	WORD  wBitsPerSample;
	WORD  cbSize;
} WAVEFORMATEX, *PWAVEFORMATEX, NEAR *NPWAVEFORMATEX, FAR *LPWAVEFORMATEX;
typedef HMODULE(__stdcall*tfn_LoadLibraryA)(LPCSTR);
typedef UINT(__stdcall*tfn_waveOutOpen)(LPHANDLE wo, UINT device_id, LPWAVEFORMATEX format, UINT_PTR callback, UINT_PTR instance, DWORD flags);
typedef UINT(__stdcall*tfn_waveOutReset)(HANDLE wo);
typedef UINT(__stdcall*tfn_waveOutClose)(HANDLE wo);
typedef UINT(__stdcall*tfn_waveOutPrepareHeader)(HANDLE wo, LPWAVEHDR hdr, UINT len);
typedef UINT(__stdcall*tfn_waveOutUnprepareHeader)(HANDLE wo, LPWAVEHDR hdr, UINT len);
typedef UINT(__stdcall*tfn_waveOutWrite)(HANDLE wo, LPWAVEHDR hdr, UINT len);
typedef double(__stdcall*tfn_sin)(double x);
typedef HANDLE(__stdcall*tfn_CreateEventA)(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);
typedef BOOL(__stdcall*tfn_ResetEvent)(HANDLE evt);
typedef DWORD(__stdcall*tfn_WaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);
static constexpr DWORD const k_hash_kernel = fnv1a("kernel32.dll");
static constexpr DWORD const k_hash_waveOutOpen            = fnv1a("waveOutOpen"           );
static constexpr DWORD const k_hash_waveOutReset           = fnv1a("waveOutReset"          );
static constexpr DWORD const k_hash_waveOutClose           = fnv1a("waveOutClose"          );
static constexpr DWORD const k_hash_waveOutPrepareHeader   = fnv1a("waveOutPrepareHeader"  );
static constexpr DWORD const k_hash_waveOutUnprepareHeader = fnv1a("waveOutUnprepareHeader");
static constexpr DWORD const k_hash_waveOutWrite           = fnv1a("waveOutWrite"          );
static constexpr DWORD const k_hash_ntdll = fnv1a("ntdll.dll");
static constexpr DWORD const k_hash_sin = fnv1a("sin");
static constexpr DWORD const k_hash_CreateEventA = fnv1a("CreateEventA");
static constexpr DWORD const k_hash_ResetEvent = fnv1a("ResetEvent");
static constexpr DWORD const k_hash_WaitForSingleObject = fnv1a("WaitForSingleObject");

extern "C"
{
DWORD _fltused;
}

#define k_secs 10

static inline void make_sine(WAVEHDR& hdr)
{
	PPEB peb;
	HMODULE ntdll;
	tfn_sin pfn_sin;
	DWORD n;
	DWORD i;
	FLOAT fi;
	FLOAT fn;
	FLOAT ftwo;
	FLOAT fpi;
	FLOAT famp;
	FLOAT f;
	SHORT shrt;

	peb = ((PPEB)(__readgsqword(0x60)));
	ntdll = find_module(peb, k_hash_ntdll);
	pfn_sin = ((tfn_sin)(find_proc(ntdll, k_hash_sin)));
	n = k_secs * 44100;
	for(i = 0; i != n; ++i)
	{
		fi = ((FLOAT)(i));
		fn = ((FLOAT)(n));
		ftwo = ((FLOAT)(2.0f));
		fpi = ((FLOAT)(3.1415265f));
		famp = ((FLOAT)(4 * 1024));
		f = ((ftwo * fpi * ((FLOAT)(440.0f))) * fi) / ((FLOAT)(44100.0f));
		f = ((FLOAT)(pfn_sin(f)));
		f = f * famp;
		shrt = ((SHORT)(f));
		((PSHORT)(hdr.lpData))[i] = shrt;
	}
}

static inline void sound(void)
{
	PPEB peb;
	HMODULE kernel;
	tfn_LoadLibraryA pfn_LoadLibraryA;
	tfn_CreateEventA pfn_CreateEventA;
	tfn_ResetEvent pfn_ResetEvent;
	tfn_WaitForSingleObject pfn_WaitForSingleObject;
	HANDLE evt;
	HMODULE winmm;
	tfn_waveOutOpen            pfn_waveOutOpen           ;
	tfn_waveOutReset           pfn_waveOutReset          ;
	tfn_waveOutClose           pfn_waveOutClose          ;
	tfn_waveOutPrepareHeader   pfn_waveOutPrepareHeader  ;
	tfn_waveOutUnprepareHeader pfn_waveOutUnprepareHeader;
	tfn_waveOutWrite           pfn_waveOutWrite          ;
	WAVEFORMATEX format;
	SHORT buf[k_secs * 44100];
	WAVEHDR hdr;
	UINT ui;
	DWORD waited;
	HANDLE wo;
	BOOL b;

	peb = ((PPEB)(__readgsqword(0x60)));
	kernel = find_module(peb, k_hash_kernel);
	pfn_LoadLibraryA = ((tfn_LoadLibraryA)(find_proc(kernel, k_hash_LoadLibraryA)));
	pfn_CreateEventA = ((tfn_CreateEventA)(find_proc(kernel, k_hash_CreateEventA)));
	pfn_ResetEvent = ((tfn_ResetEvent)(find_proc(kernel, k_hash_ResetEvent)));
	pfn_WaitForSingleObject = ((tfn_WaitForSingleObject)(find_proc(kernel, k_hash_WaitForSingleObject)));
	evt = pfn_CreateEventA(NULL, FALSE, FALSE, NULL);
	winmm = pfn_LoadLibraryA("winmm");
	pfn_waveOutOpen            = ((tfn_waveOutOpen           )(find_proc(winmm, k_hash_waveOutOpen           )));
	pfn_waveOutReset           = ((tfn_waveOutReset          )(find_proc(winmm, k_hash_waveOutReset          )));
	pfn_waveOutClose           = ((tfn_waveOutClose          )(find_proc(winmm, k_hash_waveOutClose          )));
	pfn_waveOutPrepareHeader   = ((tfn_waveOutPrepareHeader  )(find_proc(winmm, k_hash_waveOutPrepareHeader  )));
	pfn_waveOutUnprepareHeader = ((tfn_waveOutUnprepareHeader)(find_proc(winmm, k_hash_waveOutUnprepareHeader)));
	pfn_waveOutWrite           = ((tfn_waveOutWrite          )(find_proc(winmm, k_hash_waveOutWrite          )));
	format.wFormatTag = 1;
	format.nChannels = 1;
	format.nSamplesPerSec = 44100;
	format.nAvgBytesPerSec = 44100 * ((1 * 16) / 8);
	format.nBlockAlign = (1 * 16) / 8;
	format.wBitsPerSample = 16;
	format.cbSize = 0;
	hdr.lpData = ((PCHAR)(&buf[0]));
	hdr.dwBufferLength = sizeof(buf);
	hdr.dwBytesRecorded = 0;
	hdr.dwUser = 0;
	hdr.dwFlags = 0;
	hdr.dwLoops = 0;
	hdr.lpNext = 0;
	hdr.reserved = 0;
	make_sine(hdr);
	ui = pfn_waveOutOpen(&wo, ((UINT)(-1)), &format, ((UINT_PTR)(evt)), 0, 0x00000002 | 0x00050000);
	ui = pfn_waveOutPrepareHeader(wo, &hdr, sizeof(hdr));
	ui = pfn_waveOutWrite(wo, &hdr, sizeof(hdr));
	for(;;)
	{
		waited = pfn_WaitForSingleObject(evt, 100);
		b = pfn_ResetEvent(evt);
		if((hdr.dwFlags & 0x1) != 0)
		{
			break;
		}
	}
	ui = pfn_waveOutReset(wo);
	ui = pfn_waveOutUnprepareHeader(wo, &hdr, sizeof(hdr));
	ui = pfn_waveOutClose(wo);
}
}
// ========== sound ==========

extern "C" DWORD __stdcall mk_entry(PPEB peb)
{
	HMODULE kernel;
	tfn_ExitProcess pfn_ExitProcess;
	tfn_LoadLibraryA pfn_LoadLibraryA;
	HMODULE user;
	tfn_MessageBoxA pfn_MessageBoxA;
	INT res;

	kernel = find_module(peb, k_hash_kernel);
	pfn_ExitProcess = ((tfn_ExitProcess)(find_proc(kernel, k_hash_ExitProcess)));
	pfn_LoadLibraryA = ((tfn_LoadLibraryA)(find_proc(kernel, k_hash_LoadLibraryA)));
	user = pfn_LoadLibraryA("user32");
	pfn_MessageBoxA = ((tfn_MessageBoxA)(find_proc(user, k_hash_MessageBoxA)));
	res = pfn_MessageBoxA(NULL, "Sample text.", "Sample Caption", MB_OK | MB_ICONASTERISK);
	sound::sound();
	pfn_ExitProcess(42);
	return 0;
}

/*
int main()
{
	mk_entry(((PPEB)(__readgsqword(0x60))));
}
*/
