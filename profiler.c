
// 
// Copyright (c) 2023 Pascal Beyer
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 

// 
// This is a fairly simple sampling profiler based on the Event Tracing for Windows (ETW)
// and DbgHelp APIs. The basic idea is to use ETW to generate stack trace samples,
// symbolize these stack traces using DbgHelp and build a profile tree.
// These profile trees are displayed using the GDI (essentially FillRect + TextOut).
// 
// The command-line usage is as follows:
// 
//     profiler <command> <arg1> <arg2>...
//     
// The profiler will get the raw command line and strip everything until the first space
// and then execute the rest using 'CreateProcess'. For this reason <command> cannot be
// a batch script.
// 
// As ETW is intended to be used as a whole system profiler (including kernel) the API 
// is sort of awkward and you need administrator privileges (or at least the 
// 'SeSystemProfilePrivilege') to use it. For this reason it is advantageous to embed
// a 'requireAdministrator' Manifest into the application. The build command for this is
// 
//    cl /O2 profiler.c /link /MANIFESTUAC:level='requireAdministrator' /MANIFEST:EMBED
// 
// Otherwise, the build command is simply
// 
//    cl /O2 profiler.c
//    
// This build command has to be executed from an x64 Native Tools Command Prompt:
// 
//    https://learn.microsoft.com/en-us/cpp/build/building-on-the-command-line
// 
// The code works as follows:
// 
//    * main() sets up the ETW trace.
//    
//    * main() starts the command as 'CREATE_SUSPENDED' which already gives us the PID,
//      but does not actually run the application until we call 'ResumeThread'.
//      
//    * ETW requires a _event record_ callback, which has to run inside a processing thread.
//      This thread is created by main(). main() then calls ResumeThread to start the target process.
//      
//    * The processing thread (EventRecordCallback()) filters for events with the correct PID,
//      which are either module loads/unloads or stack walk events.
//      
//    * During this time the main thread waits for the target process to exit.
//      Once it does, it stops the tracing, causing the event trace thread to exit.
//      
//    * Now we have collected stack trace samples, the main thread opens a window and
//      creates a background thread.
//    
//    * The background thread symbolizes the stack traces and builds profiling trees.
//    
//    * The main thread renders the profiling trees and handles input events.
// 

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>

#include <Tchar.h>
#include <windows.h>
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Gdi32.lib")

#include <dbghelp.h>
#pragma comment(lib, "Dbghelp.lib")

#define INITGUID
#include <evntrace.h>
#include <evntcons.h>
#include <evntprov.h>

DEFINE_GUID(/* ce1dbfb4-137e-4da6-87b0-3f59aa102cbc */ PerfInfoGuid,  0xce1dbfb4, 0x137e, 0x4da6, 0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc);
DEFINE_GUID(/* 2cb15d1d-5fc1-11d2-abe1-00a0c911f518 */ ImageLoadGuid, 0x2cb15d1d, 0x5fc1, 0x11d2, 0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18);
DEFINE_GUID(/* def2fe46-7bd6-4b80-bd94-f57fe20d0ce3 */ StackWalkGuid, 0xdef2fe46, 0x7bd6, 0x4b80, 0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0x0d, 0x0c, 0xe3);

#pragma comment(lib, "Advapi32.lib")

// 
// Always flush after printing!
// 
void print(char *format, ...){
    va_list va;
    va_start(va, format);
    int ret = vprintf(format, va);
    va_end(va);
    fflush(0);
}

//_____________________________________________________________________________________________________________________
// Pool Allocator

typedef struct _POOL_ALLOCATOR{
    PCHAR  Base;
    SIZE_T Used;
    SIZE_T Committed;
    SIZE_T Reserved;
} POOL_ALLOCATOR, *PPOOL_ALLOCATOR;

// 
// Pool allocator for fast allocations. 
// 
// Does not return aligned memory, but it's fine, it's x64.
// 
void *PoolAllocate(PPOOL_ALLOCATOR Pool, SIZE_T Size){
    
    if(Pool->Used + Size > Pool->Committed){
        
        if(!Pool->Base){
            // 
            // If we do not have a base, the Pool is not initialized yet.
            // Initialize it by reserving 64 GiB of memory. 
            // ... that should be enough for anybody.
            // 
            
            SIZE_T ReserveSize = 64ull * 1024ull * 1024ull * 1024ull;
            Pool->Base = VirtualAlloc(NULL, ReserveSize, MEM_RESERVE, PAGE_READWRITE);
            Pool->Reserved = ReserveSize;
        }
        
        // 
        // Usually, allocate memory from the system in 10 MiB chunks.
        // 
        ULONG AllocationSize = 10 * 1024 * 1024;
        
        // 
        // Ensure we allocate enough for 'Size'.
        // 
        if(Size > AllocationSize) AllocationSize = (Size + 0xfff) & ~0xfff;
        
        if(Pool->Committed + AllocationSize > Pool->Reserved){
            print("Out of memory.\n");
            _exit(1);
        }
        
        PVOID Check = VirtualAlloc(Pool->Base + Pool->Committed, AllocationSize, MEM_COMMIT, PAGE_READWRITE);
        if(!Check){
            print("Out of memory.\n");
            _exit(1);
        }
        
        Pool->Committed += AllocationSize;
    }
    
    void *Ret = Pool->Base + Pool->Used;
    Pool->Used += Size;
    
    memset(Ret, 0, Size);
    return Ret;
}

//_____________________________________________________________________________________________________________________
// Event Trace processing structures

typedef enum _ENTRY_TRACE_ENTRY_TYPE{
    EVENT_TRACE_ENTRY_TYPE_NONE,
    
    EVENT_TRACE_ENTRY_TYPE_LOAD_MODULE,
    EVENT_TRACE_ENTRY_TYPE_UNLOAD_MODULE,
    
    EVENT_TRACE_ENTRY_TYPE_STACK_TRACE_SAMPLE,
    
    EVENT_TRACE_ENTRY_TYPE_COUNT,
} EVENT_TRACE_ENTRY_TYPE;

typedef struct _EVENT_TRACE_ENTRY_HEADER{
    EVENT_TRACE_ENTRY_TYPE EntryType;
    ULONG EntryLength;
} EVENT_TRACE_ENTRY_HEADER, *PEVENT_TRACE_ENTRY_HEADER;

typedef struct _EVENT_RECORD_CALLBACK_CONTEXT{
    ULONG  TargetProcessId;
    POOL_ALLOCATOR EventTrace;
} EVENT_RECORD_CALLBACK_CONTEXT, *PEVENT_RECORD_CALLBACK_CONTEXT;


void EventRecordCallback(PEVENT_RECORD EventRecord){
    PEVENT_RECORD_CALLBACK_CONTEXT Context = EventRecord->UserContext;
    ULONG TargetProcessId = Context->TargetProcessId;
    
    GUID ProviderId = EventRecord->EventHeader.ProviderId;
    UCHAR Opcode    = EventRecord->EventHeader.EventDescriptor.Opcode;
    
    EVENT_TRACE_ENTRY_TYPE EntryType = EVENT_TRACE_ENTRY_TYPE_NONE;
    
    if(memcmp(&ProviderId, &PerfInfoGuid, sizeof(ProviderId)) == 0){
        // 
        // @cleanup: Understand this... Did we not switch on StackTracing for these?
        // 
        // if(EventRecord->EventHeader.EventDescriptor.Opcode == /*SampledProfile*/46) return;
        return;
    }else if(memcmp(&ProviderId, &StackWalkGuid, sizeof(ProviderId)) == 0){
        // 
        // Technically, a StackWalk event is only a StackWalk_Event event if it has Opcode 32.
        // This seems to be always the case though from my limited testing.
        // 
        if(Opcode != /*Stack tracing event*/32) return;
        
        // 
        // "Parse" the user data.
        // 
        struct{
            uint64_t EventTimeStamp;
            uint32_t StackProcess;
            uint32_t StackThread;
            uint64_t Stack[1]; // Require there to be at least one element in the stack trace.
        } *StackWalk_Event = EventRecord->UserData;
        
        uint64_t StackWalkEventSize = EventRecord->UserDataLength;
        uint64_t AmountOfStacks     = (StackWalkEventSize - sizeof(*StackWalk_Event))/8;
        if(StackWalkEventSize < sizeof(*StackWalk_Event)) return;
        
        // 
        // Filter by the ProcessId we actually care about.
        // 
        if(StackWalk_Event->StackProcess != TargetProcessId) return;
        
        // 
        // For some reason, even though we specify 'ExcludeKernelStack' 
        // we still get some _small_ kernel stack events.
        // Filter these by checking if the high bits are set.
        // 
        if((int64_t)StackWalk_Event->Stack[0] < 0) return;
        
        EntryType = EVENT_TRACE_ENTRY_TYPE_STACK_TRACE_SAMPLE;
    }else if(memcmp(&ProviderId, &ImageLoadGuid, sizeof(ProviderId)) == 0){
        
        struct{
            uint64_t ImageBase;
            uint64_t ImageSize;
            uint32_t ProcessId;
            uint32_t ImageCheckSum;
            uint32_t TimeDateStamp;
            uint32_t Reserved0;
            uint64_t DefaultBase;
            uint32_t Reserved1;
            uint32_t Reserved2;
            uint32_t Reserved3;
            uint32_t Reserved4;
            WCHAR FileName[];
        } *Image_Load = EventRecord->UserData;
        
        if(EventRecord->UserDataLength < sizeof(*Image_Load)) return;
        if(Image_Load->ProcessId != TargetProcessId) return;
        
        if(Opcode == EVENT_TRACE_TYPE_LOAD/* || Opcode == EVENT_TRACE_TYPE_DC_START*/) EntryType = EVENT_TRACE_ENTRY_TYPE_LOAD_MODULE;
        if(Opcode == EVENT_TRACE_TYPE_END/*  || Opcode == EVENT_TRACE_TYPE_DC_END*/)   EntryType = EVENT_TRACE_ENTRY_TYPE_UNLOAD_MODULE;
        
    }else{
#if 0
        print("Unhandled {%.8x-%.4x-%.4x-%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x}\n",
                ProviderId.Data1, ProviderId.Data2, ProviderId.Data3,
                ProviderId.Data4[0], ProviderId.Data4[1], ProviderId.Data4[2], ProviderId.Data4[3], 
                ProviderId.Data4[4], ProviderId.Data4[5], ProviderId.Data4[6], ProviderId.Data4[7]);
#endif
        return;
    }
    
    
    // 
    // If we did not return, Copy the event to the 'EventTrace'.
    // 
    
    EVENT_TRACE_ENTRY_HEADER EventTraceEntryHeader = {
        .EntryType   = EntryType,
        .EntryLength = EventRecord->UserDataLength,
    };
    
    PCHAR EventMemory = PoolAllocate(&Context->EventTrace, sizeof(EventTraceEntryHeader) + EventRecord->UserDataLength);
    
    memcpy(EventMemory, &EventTraceEntryHeader, sizeof(EventTraceEntryHeader));
    memcpy(EventMemory + sizeof(EventTraceEntryHeader), EventRecord->UserData, EventRecord->UserDataLength);
}

int ProcessTraceThreadStartRoutine(void *parameter){
    PTRACEHANDLE ProcessTraceHandle = parameter;
    
    ProcessTrace(ProcessTraceHandle, /*HandleCount*/1, /*StartTime*/0, /*EndTime*/0);
    
    return 1;
}

//_____________________________________________________________________________________________________________________
// Profiling Tree information

typedef enum _PROFILE_TREE_KIND{
    PROFILE_TREE_TOP_DOWN,
    PROFILE_TREE_BOTTOM_UP,
    PROFILE_TREE_TOP_FUNCTIONS_UP,
    PROFILE_TREE_TOP_FUNCTIONS_DOWN,
    
    PROFILE_TREE_KIND_COUNT,
} PROFILE_TREE_KIND, *PPROFILE_TREE_KIND;

typedef struct _FILE_AND_LINE{
    PCHAR FileName;
    ULONG FileNameLength;
    ULONG LineNumber;
    ULONG Samples;
} FILE_AND_LINE, *PFILE_AND_LINE;

typedef struct _PROFILE_TREE_NODE{
    ULONG AmountOfChildren;
    ULONG MaxAmountOfChildren;
    struct _PROFILE_TREE_NODE **Children;
    
    PFILE_AND_LINE FileAndLineNumbers;
    ULONG AmountOfFileAndLineNumbers;
    ULONG MaxAmountOfFileAndLineNumbers;
    
    ULONG IsExpanded;
    ULONG Depth;
    ULONG Samples;
    
    ULONG NameLength;
    CHAR Name[];
} PROFILE_TREE_NODE, *PPROFILE_TREE_NODE;

typedef struct _LOADED_MODULE{
    struct _LOADED_MODULE *Next;
    DWORD64 ImageBase;
    DWORD64 ImageSize;
    ULONG FileNameLength;
    CHAR FileName[];
} LOADED_MODULE, *PLOADED_MODULE;

typedef struct _PROFILE_TREE_GENERATING_THREAD_CONTEXT{
    
    // The window handle to refresh the window.
    HWND WindowHandle;
    
    // The event trace to be processed.
    PCHAR  EventTraceBase;
    SIZE_T EventTraceSize;
    
    // The destination of where to put the generated profile trees.
    volatile PPROFILE_TREE_NODE (*CachedProfileTrees)[PROFILE_TREE_KIND_COUNT];
} PROFILE_TREE_GENERATING_THREAD_CONTEXT, *PPROFILE_TREE_GENERATING_THREAD_CONTEXT;

// 
// Compare functions for 'qsort'.
// 
int CompareProfileTreeNodes(const void *First, const void *Second){
    PPROFILE_TREE_NODE FirstNode  = *(PPROFILE_TREE_NODE *)First;
    PPROFILE_TREE_NODE SecondNode = *(PPROFILE_TREE_NODE *)Second;
    
    return SecondNode->Samples - FirstNode->Samples;
}

int CompareFileAndLineNumbers(const void *First, const void *Second){
    PFILE_AND_LINE FirstLine  = (PFILE_AND_LINE)First;
    PFILE_AND_LINE SecondLine = (PFILE_AND_LINE)Second;
    
    return SecondLine->Samples - FirstLine->Samples;
}

void GenerateProfileTree(PPROFILE_TREE_GENERATING_THREAD_CONTEXT Context, PPOOL_ALLOCATOR ProfileTreePool, HANDLE DbgHelpHandle, PLOADED_MODULE LoadedModules, PROFILE_TREE_KIND ProfileTreeKind){
    
    // 
    // Allocate the 'RootNode'. This node does not correspond to any function.
    // 
    PPROFILE_TREE_NODE RootNode = PoolAllocate(ProfileTreePool, sizeof(*RootNode));
    
    SIZE_T EventTraceSize = Context->EventTraceSize;
    for(SIZE_T EventTraceAt = 0; EventTraceAt < EventTraceSize; ){
        PEVENT_TRACE_ENTRY_HEADER EventTraceEntryHeader = (PEVENT_TRACE_ENTRY_HEADER)(Context->EventTraceBase + EventTraceAt);
        
        if(EventTraceEntryHeader->EntryType != EVENT_TRACE_ENTRY_TYPE_STACK_TRACE_SAMPLE){
            EventTraceAt += EventTraceEntryHeader->EntryLength + sizeof(*EventTraceEntryHeader);
            continue;
        }
        
        // 
        // Save the total amount of samples in the 'RootNode->Samples'.
        // 
        RootNode->Samples += 1;
        
        struct{
            uint64_t EventTimeStamp;
            uint32_t StackProcess;
            uint32_t StackThread;
            uint64_t Stack[];
        } *StackWalk_Event = (PVOID)(EventTraceEntryHeader + 1);
        
        uint64_t AmountOfStacks = (EventTraceEntryHeader->EntryLength - sizeof(*StackWalk_Event))/8;
        
        int64_t TopFunctionIteratorStart = 0;
        if(ProfileTreeKind == PROFILE_TREE_TOP_FUNCTIONS_UP || ProfileTreeKind == PROFILE_TREE_TOP_FUNCTIONS_DOWN){
            TopFunctionIteratorStart = AmountOfStacks - 1;
        }
        
        for(int64_t TopFunctionIterator = TopFunctionIteratorStart; TopFunctionIterator >= 0; TopFunctionIterator--){
            PPROFILE_TREE_NODE CurrentNode = RootNode;
            
            int64_t StackIndexStart  = 0;
            int64_t StackIndexEnd    = 0;
            BOOL    IterateBackwards = 0;
            
            if(ProfileTreeKind == PROFILE_TREE_TOP_DOWN){
                // 
                // Top Down means we start at the highest stack frame (index 0 of stacks)
                // and iterate until we are back at the root stack frame, 
                // i.e the main() or whatever.
                // 
                StackIndexStart  = 0;
                StackIndexEnd    = AmountOfStacks;
                IterateBackwards = FALSE;
            }else if(ProfileTreeKind == PROFILE_TREE_BOTTOM_UP){
                // 
                // Bottom up means we start at the root stack frame, 
                // i.e main() or whatever and iterate till the top of the stack.
                // 
                StackIndexStart  = AmountOfStacks-1;
                StackIndexEnd    = -1;
                IterateBackwards = TRUE;
            }else if(ProfileTreeKind == PROFILE_TREE_TOP_FUNCTIONS_UP){
                // 
                // Top functions up means we iterate in the same way as 'bottom up'
                // but re-start at every stack frame along the way.
                // 
                StackIndexStart  = TopFunctionIterator;
                StackIndexEnd    = -1;
                IterateBackwards = TRUE;
            }else if(ProfileTreeKind == PROFILE_TREE_TOP_FUNCTIONS_DOWN){
                // 
                // Top functions down means we iterate in the same way as 'top down'
                // but re-start at every stack frame along the way.
                // 
                StackIndexStart  = TopFunctionIterator;
                StackIndexEnd    = AmountOfStacks;
                IterateBackwards = FALSE;
            }
            
            ULONG Depth = 0;
            for(int64_t StackIndex = StackIndexStart; StackIndex != StackIndexEnd; StackIndex = IterateBackwards ? (StackIndex - 1) : (StackIndex + 1)){
                uint64_t Stack = StackWalk_Event->Stack[StackIndex];
                
                // 
                // Skip kernel addresses.
                // 
                if((int64_t)Stack < 0) continue;
                
                char *SymbolName = NULL;
                ULONG NameLength = 0;
                
                
                // 
                // Get the 'SymbolName' either from 'SymFromAddr' or if that fails by iterating the modules.
                // 
                union{
                    union{ SYMBOL_INFO; SYMBOL_INFO Base; };
                    CHAR buffer[0x100];
                } SymbolInfo = {
                    // 
                    // "Note that the total size of the data is the SizeOfStruct + (MaxNameLen - 1) * sizeof(TCHAR)."
                    //  The reason to subtract one is that the first character in the name is accounted for in the size of the structure."
                    // 
                    .SizeOfStruct = sizeof(SYMBOL_INFO),
                    .MaxNameLen   = (sizeof(SymbolInfo) - sizeof(SYMBOL_INFO))/sizeof(TCHAR),
                };
                
                DWORD64 Displacement;
                BOOL SymFromAddrSuccess = SymFromAddr(DbgHelpHandle, Stack, &Displacement, &SymbolInfo.Base);
                if(SymFromAddrSuccess){
                    SymbolName = SymbolInfo.Name;
                    NameLength = SymbolInfo.NameLen;
                }else{
                    // 
                    // This happens for modules which don't have loaded symbols.
                    // 
                    int found = 0;
                    for(PLOADED_MODULE Iterator = LoadedModules; Iterator; Iterator = Iterator->Next){
                        if(Iterator->ImageBase <= Stack && Stack <= Iterator->ImageBase + Iterator->ImageSize){
                            SymbolName = Iterator->FileName;
                            NameLength = Iterator->FileNameLength;
                            found = 1;
                            break;
                        }
                    }
                    
                    if(!found){
                        // 
                        // This might happen for JIT-code or something.
                        // It also randomly happens sometimes, not sure why.
                        // 
                        static CHAR Unknown[] = "Unknown";
                        SymbolName = Unknown;
                        NameLength = sizeof(Unknown) - 1;
                    }
                }
                
                PPROFILE_TREE_NODE TreeNode = NULL;
                
                for(ULONG ChildIndex = 0; ChildIndex < CurrentNode->AmountOfChildren; ChildIndex++){
                    PPROFILE_TREE_NODE Iterator = CurrentNode->Children[ChildIndex];
                    if(Iterator->NameLength == NameLength && strcmp(Iterator->Name, SymbolName) == 0){
                        // 
                        // We found an existing node.
                        // 
                        TreeNode = Iterator;
                        break;
                    }
                }
                
                if(!TreeNode){
                    // 
                    // If we could not find the node, allocate a new one.
                    // 
                    TreeNode = PoolAllocate(ProfileTreePool, sizeof(*TreeNode) + NameLength + 1);
                    TreeNode->NameLength = NameLength;
                    memcpy(TreeNode->Name, SymbolName, NameLength);
                    TreeNode->Name[TreeNode->NameLength] = 0;
                    TreeNode->Depth = Depth;
                    
                    // 
                    // Append the 'TreeNode' as a child of 'CurrentNode'.
                    // 
                    if(CurrentNode->AmountOfChildren + 1 >= CurrentNode->MaxAmountOfChildren){
                        ULONG NewMax = CurrentNode->MaxAmountOfChildren ? 2 * CurrentNode->MaxAmountOfChildren : 8;
                        
                        PPROFILE_TREE_NODE *NewChildren = PoolAllocate(ProfileTreePool, NewMax * sizeof(*CurrentNode->Children));
                        memcpy(NewChildren, CurrentNode->Children, CurrentNode->MaxAmountOfChildren * sizeof(*CurrentNode->Children));
                        
                        CurrentNode->MaxAmountOfChildren = NewMax;
                        CurrentNode->Children = NewChildren;
                    }
                    
                    CurrentNode->Children[CurrentNode->AmountOfChildren++] = TreeNode;
                }
                
                // 
                // Remember that we hit this node!
                // 
                TreeNode->Samples += 1;
                
                if(SymFromAddrSuccess){
                    // 
                    // Get the file/line which was hit and store it in the node.
                    // 
                    IMAGEHLP_LINE64 Line = { .SizeOfStruct = sizeof(Line) };
                    DWORD LineDisplacement = 0;
                    BOOL SymGetLineFromAddr64Success = SymGetLineFromAddr64(DbgHelpHandle, Stack, &LineDisplacement, &Line);
                    if(SymGetLineFromAddr64Success){
                        
                        PFILE_AND_LINE Found = NULL;
                        
                        ULONG FileNameLength = strlen(Line.FileName);
                        
                        for(ULONG Index = 0; Index < TreeNode->AmountOfFileAndLineNumbers; Index++){
                            PFILE_AND_LINE FileAndLine = TreeNode->FileAndLineNumbers + Index;
                            if(FileAndLine->LineNumber == Line.LineNumber && FileAndLine->FileNameLength == FileNameLength && strcmp(FileAndLine->FileName, Line.FileName) == 0){
                                Found = FileAndLine;
                                break;
                            }
                        }
                        
                        if(!Found){
                            
                            if(TreeNode->AmountOfFileAndLineNumbers + 1 >= TreeNode->MaxAmountOfFileAndLineNumbers){
                                ULONG NewMax = TreeNode->MaxAmountOfFileAndLineNumbers ? 2 * TreeNode->MaxAmountOfFileAndLineNumbers : 8;
                                
                                PFILE_AND_LINE NewLines = PoolAllocate(ProfileTreePool, NewMax * sizeof(*TreeNode->FileAndLineNumbers));
                                memcpy(NewLines, TreeNode->FileAndLineNumbers, TreeNode->MaxAmountOfFileAndLineNumbers * sizeof(*TreeNode->FileAndLineNumbers));
                                
                                TreeNode->MaxAmountOfFileAndLineNumbers = NewMax;
                                TreeNode->FileAndLineNumbers = NewLines;
                            }
                            
                            PCHAR CopiedFileName = PoolAllocate(ProfileTreePool, FileNameLength + 1);
                            memcpy(CopiedFileName, Line.FileName, FileNameLength);
                            CopiedFileName[FileNameLength] = 0;
                            
                            PFILE_AND_LINE NewLine = &TreeNode->FileAndLineNumbers[TreeNode->AmountOfFileAndLineNumbers++];
                            NewLine->LineNumber = Line.LineNumber;
                            NewLine->FileName   = CopiedFileName;
                            NewLine->FileNameLength = FileNameLength;
                            
                            Found = NewLine;
                        }
                        
                        Found->Samples++;
                    }
                }
                
                // 
                // Iterate down the tree.
                // 
                Depth += 1;
                CurrentNode = TreeNode;
            }
            
        }
        
        EventTraceAt += EventTraceEntryHeader->EntryLength + sizeof(*EventTraceEntryHeader);
    }
    
    {
        // 
        // Sort all the tree nodes:
        // 
        
        struct {
            PPROFILE_TREE_NODE TreeNode;
            ULONG ChildIndex;
        } Stack[0x100] = {
            {RootNode, 0}
        };
        LONG StackAt = 0;
        
        while(StackAt >= 0){
            PPROFILE_TREE_NODE ParentNode = Stack[StackAt].TreeNode;
            ULONG              ChildIndex = Stack[StackAt].ChildIndex++;
            
            if(ChildIndex == ParentNode->AmountOfChildren){
                // 
                // Pop the StackNode, if this is past the last child.
                // 
                StackAt--;
                continue;
            }
            
            // 
            // If we are on the first child, _first_ sort the whole array.
            // 
            if(ChildIndex == 0){
                qsort(ParentNode->Children, ParentNode->AmountOfChildren, sizeof(*ParentNode->Children), CompareProfileTreeNodes);
            }
            
            // 
            // Add the Child to the Stack.
            // 
            PPROFILE_TREE_NODE ChildNode = ParentNode->Children[ChildIndex];
            
            
            // 
            // Sort the file and line numbers of the Child node.
            // 
            if(ChildNode->AmountOfFileAndLineNumbers){
                qsort(ChildNode->FileAndLineNumbers, ChildNode->AmountOfFileAndLineNumbers, sizeof(*ChildNode->FileAndLineNumbers), CompareFileAndLineNumbers);
            }
            
            if(StackAt + 1 < ARRAYSIZE(Stack)){
                ULONG Index = ++StackAt;
                Stack[Index].TreeNode = ChildNode;
                Stack[Index].ChildIndex = 0;
            }
        }
    }
    
    (*Context->CachedProfileTrees)[ProfileTreeKind] = RootNode;
    
    // 
    // Redraw the entire window just in case the Window thread is waiting on us.
    // 
    RedrawWindow(Context->WindowHandle, NULL, NULL, RDW_INVALIDATE);
}

int ProfileTreeGeneratorThreadStartRoutine(void *parameter){
    PPROFILE_TREE_GENERATING_THREAD_CONTEXT Context = parameter;
    
    // 
    // Setup the 'DbgHelp' state.
    // 
    
    // "A handle that identifies the caller. This value should be unique and nonzero, 
    //  but need not be a process handle."
    HANDLE DbgHelpHandle = (HANDLE)1337; 
    BOOL SymInitializeSuccess = SymInitialize(DbgHelpHandle, /*UserSearchPath*/NULL, /*fInvaldeProcess*/FALSE);
    if(!SymInitializeSuccess){
        print("Failed to initialize DbgHelp with error %d\n", GetLastError());
        return 1;
    }
    
    // 
    // Set the Search Path to the microsoft symbol server.
    // 
    BOOL SymSetSearchPathSuccess = SymSetSearchPath(DbgHelpHandle, TEXT("srv**symbols*http://msdl.microsoft.com/download/symbols"));
    if(!SymSetSearchPathSuccess){
        print("Failed to SymSetSearchPath.\n");
        return 1;
    }
    
    // 
    // Load line number information.
    // 
    SymSetOptions(SymGetOptions() | SYMOPT_LOAD_LINES);
    
    PLOADED_MODULE LoadedModules = NULL;
    
    // 
    // Load all the modules into 'DbgHelp'.
    // 
    PCHAR  EventTraceBase = Context->EventTraceBase;
    SIZE_T EventTraceSize = Context->EventTraceSize;
    for(SIZE_T EventTraceAt = 0; EventTraceAt < EventTraceSize; ){
        PEVENT_TRACE_ENTRY_HEADER EventTraceEntryHeader = (PEVENT_TRACE_ENTRY_HEADER)(EventTraceBase + EventTraceAt);
        switch(EventTraceEntryHeader->EntryType){
            case EVENT_TRACE_ENTRY_TYPE_LOAD_MODULE:
            case EVENT_TRACE_ENTRY_TYPE_UNLOAD_MODULE:{
                struct{
                    uint64_t ImageBase;
                    uint64_t ImageSize;
                    uint32_t ProcessId;
                    uint32_t ImageCheckSum;
                    uint32_t TimeDateStamp;
                    uint32_t Reserved0;
                    uint64_t DefaultBase;
                    uint32_t Reserved1;
                    uint32_t Reserved2;
                    uint32_t Reserved3;
                    uint32_t Reserved4;
                    WCHAR FileName[];
                } *Image_Load = (PVOID)(EventTraceEntryHeader + 1);
                
                WCHAR FileNameBuffer[0x100];
                _snwprintf(FileNameBuffer, sizeof(FileNameBuffer), L"\\\\.\\GLOBALROOT%ws", Image_Load->FileName);
                
                if(EventTraceEntryHeader->EntryType == EVENT_TRACE_ENTRY_TYPE_LOAD_MODULE){
                    DWORD64 BaseAddress = SymLoadModuleExW(DbgHelpHandle, NULL, FileNameBuffer, NULL, Image_Load->ImageBase, Image_Load->ImageSize, NULL, 0);
                    if(BaseAddress == 0 || BaseAddress != Image_Load->ImageBase){
                        print("Failed to SymLoadModuleExW for %ws with error %d\n", FileNameBuffer, GetLastError());
                    }
                    
                    // "If 'wcstombs' successfully converts the multi-byte string, 
                    //  it returns the number of bytes written into the output string, 
                    //  excluding the terminating NULL (if any). If the destination parameter
                    //  is NULL, 'wcstombs' returns the required size in bytes of the destination
                    //  string. If 'wcstombs' encounters a wide character it can't convert to 
                    //  a multi-byte character, it returns '-1'.
                    size_t size_or_error = wcstombs(NULL, Image_Load->FileName, 0);
                    if(size_or_error == (size_t)-1) continue;
                    
                    PLOADED_MODULE Module = malloc(sizeof(LOADED_MODULE) + size_or_error + 1);
                    Module->ImageBase = Image_Load->ImageBase;
                    Module->ImageSize = Image_Load->ImageSize;
                    Module->FileNameLength = size_or_error;
                    wcstombs(Module->FileName, Image_Load->FileName, size_or_error + 1);
                    
                    Module->Next = LoadedModules;
                    LoadedModules = Module;
                }
                char *type = EventTraceEntryHeader->EntryType == EVENT_TRACE_ENTRY_TYPE_LOAD_MODULE ? "Load" : "Unload";
                
            }break;
        }
        EventTraceAt += EventTraceEntryHeader->EntryLength + sizeof(*EventTraceEntryHeader);
    }
    
    
    // 
    // Generate all the Profile trees one by one.
    // We could make this even more parallel, but DbgHelp is single threaded.
    // 
    
    POOL_ALLOCATOR ProfileTreePool = {0};
    
    GenerateProfileTree(Context, &ProfileTreePool, DbgHelpHandle, LoadedModules, PROFILE_TREE_BOTTOM_UP);
    GenerateProfileTree(Context, &ProfileTreePool, DbgHelpHandle, LoadedModules, PROFILE_TREE_TOP_FUNCTIONS_DOWN);
    GenerateProfileTree(Context, &ProfileTreePool, DbgHelpHandle, LoadedModules, PROFILE_TREE_TOP_DOWN);
    GenerateProfileTree(Context, &ProfileTreePool, DbgHelpHandle, LoadedModules, PROFILE_TREE_TOP_FUNCTIONS_UP);
    
    return 0;
}

//_____________________________________________________________________________________________________________________
// Window procedure (Drawing and handling input).

typedef struct _WINDOW_PROCEDURE_CONTEXT{
    ULONG SelectedRow;
    ULONG LeftPressed;
    ULONG RightPressed;
    PROFILE_TREE_KIND ProfileTreeToShow;
    
    volatile PPROFILE_TREE_NODE CachedProfileTrees[PROFILE_TREE_KIND_COUNT];
} WINDOW_PROCEDURE_CONTEXT, *PWINDOW_PROCEDURE_CONTEXT;

#define WINDOW_TITLE_KEY_HELPER TEXT("1 - Top Down | 2 - Bottom Up | 3 - Top Functions Down | 4 - Top Functions Up")

LRESULT ProfileWindowProc(HWND WindowHandle, UINT Message, WPARAM WParam, LPARAM LParam){
    
    // @note: It is fine to always call this, its initial value is zero.
    PWINDOW_PROCEDURE_CONTEXT WindowContext = (PWINDOW_PROCEDURE_CONTEXT)GetWindowLongPtr(WindowHandle, GWLP_USERDATA);
    
    switch(Message){
        
        case WM_DESTROY:{
            _exit(0);
        }break;
        
        case WM_CREATE:{
            // 
            // On create, get the 'WINDOW_PROCEDURE_CONTEXT' and stash it in the window pointer,
            // where we can find it. This seems to be the thread safe way to not use a global 
            // and pass a context pointer to a window.
            // 
            CREATESTRUCT *CreateStruct = (CREATESTRUCT *)LParam;
            
            SetWindowLongPtr(WindowHandle, GWLP_USERDATA, (LONG_PTR)CreateStruct->lpCreateParams);
        }break;
        
        case WM_KEYDOWN:{
            WORD vkCode = LOWORD(WParam);
            
            if(vkCode == VK_UP && WindowContext->SelectedRow != 0) WindowContext->SelectedRow -= 1;
            if(vkCode == VK_DOWN) WindowContext->SelectedRow += 1;
            
            if(vkCode == VK_LEFT)  WindowContext->LeftPressed = 1;
            if(vkCode == VK_RIGHT) WindowContext->RightPressed = 1;
            
            if(vkCode == '1'){
                WindowContext->ProfileTreeToShow =  PROFILE_TREE_TOP_DOWN;
                SetWindowText(WindowHandle, TEXT("Profiler - Top Down | ") WINDOW_TITLE_KEY_HELPER);
            }
            
            if(vkCode == '2'){
                WindowContext->ProfileTreeToShow =  PROFILE_TREE_BOTTOM_UP;
                SetWindowText(WindowHandle, TEXT("Profiler - Bottom Up | ") WINDOW_TITLE_KEY_HELPER);
            }
            
            if(vkCode == '3'){
                WindowContext->ProfileTreeToShow =  PROFILE_TREE_TOP_FUNCTIONS_DOWN;
                SetWindowText(WindowHandle, TEXT("Profiler - Top Functions Down | ") WINDOW_TITLE_KEY_HELPER);
            }
            
            if(vkCode == '4'){
                WindowContext->ProfileTreeToShow =  PROFILE_TREE_TOP_FUNCTIONS_UP;
                SetWindowText(WindowHandle, TEXT("Profiler - Top Functions Up | ") WINDOW_TITLE_KEY_HELPER);
            }
            
            // 
            // Invalidate the entire windows for redrawing.
            // 
            RedrawWindow(WindowHandle, NULL, NULL, RDW_INVALIDATE);
        }break;
        
        case WM_PAINT:{
            
            PAINTSTRUCT PaintStruct;
            HDC DeviceHandle = BeginPaint(WindowHandle, &PaintStruct);
            
            // 
            // Always redraw the entire screen.
            // Maybe we could do something smart in the final call to 'BitBlt'?
            // 
            RECT ClientRect = {0};
            GetClientRect(WindowHandle, &ClientRect);
            
            LONG Width  = ClientRect.right  - ClientRect.left;
            LONG Height = ClientRect.bottom - ClientRect.top;
            
            // 
            // Set up double buffering state.
            // We first draw to a backbuffer and then use 'BitBlt' in the very end, 
            // to avoid flickering.
            // 
            HDC BackbufferDeviceHandle = CreateCompatibleDC(DeviceHandle);
            HBITMAP Backbuffer = CreateCompatibleBitmap(DeviceHandle, Width, Height);
            SelectObject(BackbufferDeviceHandle, Backbuffer);
            
            HBRUSH HighlightBrush = CreateSolidBrush(RGB(0x88, 0x66, 0x44));
            
            // 
            // Set the Text color to black and the background of the characters to TRANSPARENT.
            // 
            SetBkMode(BackbufferDeviceHandle, TRANSPARENT);
            SetTextColor(BackbufferDeviceHandle, RGB(0, 0, 0));
            
            // 
            // Quick hack, to restart drawing if we changed something due to input handling.
            // 
            RestartDrawingBecauseWeChangedSomething:
            
            // 
            // Clear the background to the default window color.
            // 
            FillRect(BackbufferDeviceHandle, &ClientRect, (HBRUSH)(COLOR_WINDOW + 1));
            
            PPROFILE_TREE_NODE RootNode = WindowContext->CachedProfileTrees[WindowContext->ProfileTreeToShow];
            
            if(!RootNode){
                // 
                // The DbgHelp thread has not gotten to this ProfileTree yet.
                // Just show 'Loading...'. It will notify us when it finished.
                // 
                
                static TCHAR Loading[] = TEXT("Loading...");
                TextOut(BackbufferDeviceHandle, ClientRect.left, ClientRect.top, Loading, ARRAYSIZE(Loading));
            }else{
                
                PPROFILE_TREE_NODE SelectedNode = NULL;
                
                ULONG LastExpandedIndex = 0;
                PPROFILE_TREE_NODE LastExpandedNode = NULL;
                
                struct {
                    PPROFILE_TREE_NODE TreeNode;
                    ULONG ChildIndex;
                } Stack[0x100] = {
                    {RootNode, 0}
                };
                LONG StackAt = 0;
                
                ULONG DrawIndex = 0;
                
                while(StackAt >= 0){
                    PPROFILE_TREE_NODE ParentNode = Stack[StackAt].TreeNode;
                    ULONG              ChildIndex = Stack[StackAt].ChildIndex++;
                    
                    if(ChildIndex == ParentNode->AmountOfChildren){
                        // 
                        // Pop the StackNode, if this is past the last child.
                        // 
                        StackAt--;
                        continue;
                    }
                    
                    PPROFILE_TREE_NODE ChildNode = ParentNode->Children[ChildIndex];
                    
                    // 
                    // Only draw as many as we can fit.
                    // 
                    if(DrawIndex * 16 > Height) break;
                    
                    RECT OutlineRect = {
                        .left   = ClientRect.left,
                        .right  = ClientRect.left + (ClientRect.left + ClientRect.right)/2,
                        .top    = ClientRect.top + DrawIndex * 16,
                        .bottom = ClientRect.top + (DrawIndex + 1) * 16,
                    };
                    
                    if(StackAt == 0 && DrawIndex < WindowContext->SelectedRow && ChildIndex + 1 == ParentNode->AmountOfChildren && !ChildNode->IsExpanded){
                        // 
                        // If we are on the last entry we should draw, and the 'SelectedRow' is past
                        // last thing we should draw, reset it to be in bounds.
                        // 
                        WindowContext->SelectedRow = DrawIndex;
                    }
                    
                    if(ChildNode->IsExpanded){
                        LastExpandedIndex = DrawIndex;
                        LastExpandedNode  = ChildNode;
                    }
                    
                    if(DrawIndex == WindowContext->SelectedRow){
                        if(WindowContext->LeftPressed){
                            WindowContext->LeftPressed = 0;
                            
                            if(LastExpandedNode){
                                LastExpandedNode->IsExpanded = 0;
                                WindowContext->SelectedRow = LastExpandedIndex;
                                
                                // 
                                // Different things are expanded now.
                                // Hence, we have to restart the drawing.
                                // 
                                goto RestartDrawingBecauseWeChangedSomething;
                            }
                        }
                        
                        if(WindowContext->RightPressed){
                            WindowContext->RightPressed = 0;
                            
                            if(ChildNode->AmountOfChildren) ChildNode->IsExpanded = 1;
                            WindowContext->SelectedRow += 1;
                        }
                    }
                    
                    // Re-check if we are the selected row, as the selected row changes on a right press.
                    if(DrawIndex == WindowContext->SelectedRow){
                        SelectedNode = ChildNode;
                        
                        FillRect(BackbufferDeviceHandle, &OutlineRect, HighlightBrush);
                    }
                    
                    DrawIndex++;
                    
                    char buffer[0x100];
                    {
                        // 
                        // Draw the amount of samples:
                        // 
                        int length = snprintf(buffer, sizeof(buffer), "%8d", ChildNode->Samples);
                        TextOutA(BackbufferDeviceHandle, OutlineRect.left, OutlineRect.top, buffer, length);
                        
                        OutlineRect.left += 60;
                    }
                    
                    {
                        // 
                        // Draw the percent of samples:
                        // 
                        int length = snprintf(buffer, sizeof(buffer), "%2.2f", (double)ChildNode->Samples/(double)RootNode->Samples * 100.0);
                        TextOutA(BackbufferDeviceHandle, OutlineRect.left, OutlineRect.top, buffer, length);
                        
                        OutlineRect.left += 60;
                    }
                    
                    char *PlusOrMinus = ChildNode->IsExpanded ? "--" : "+";
                    if(!ChildNode->AmountOfChildren){
                        PlusOrMinus = "  ";
                    }
                    
                    int length = snprintf(buffer, sizeof(buffer), "%*s%s %.*s", 4 * ChildNode->Depth, "", PlusOrMinus, ChildNode->NameLength, ChildNode->Name);
                    
                    TextOutA(BackbufferDeviceHandle, OutlineRect.left, OutlineRect.top, buffer, length);
                    
                    if(ChildNode->IsExpanded){
                        // 
                        // If we should expand the child, put it on the stack.
                        // 
                        
                        ULONG StackIndex = ++StackAt;
                        Stack[StackIndex].TreeNode = ChildNode;
                        Stack[StackIndex].ChildIndex = 0;
                    }
                }
                
                // 
                // We have drawn the tree, on the right side, draw which line numbers where hit 
                // and how often.
                // 
                for(ULONG LineIndex = 0; LineIndex < SelectedNode->AmountOfFileAndLineNumbers; LineIndex++){
                    PFILE_AND_LINE Line = &SelectedNode->FileAndLineNumbers[LineIndex];
                    
                    RECT OutlineRect = {
                        .left   = ClientRect.left + (ClientRect.left + ClientRect.right)/2,
                        .right  = ClientRect.right,
                        .top    = ClientRect.top + LineIndex * 16,
                        .bottom = ClientRect.top + (LineIndex + 1) * 16,
                    };
                    
                    char buffer[0x100];
                    {
                        // 
                        // Draw the amount of samples:
                        // 
                        int length = snprintf(buffer, sizeof(buffer), "%8d", Line->Samples);
                        TextOutA(BackbufferDeviceHandle, OutlineRect.left, OutlineRect.top, buffer, length);
                        
                        OutlineRect.left += 60;
                    }
                    
                    {
                        // 
                        // Draw the percent of samples:
                        // 
                        int length = snprintf(buffer, sizeof(buffer), "%2.2f", (double)Line->Samples/(double)SelectedNode->Samples * 100.0);
                        TextOutA(BackbufferDeviceHandle, OutlineRect.left, OutlineRect.top, buffer, length);
                        
                        OutlineRect.left += 60;
                    }
                    
                    int length = snprintf(buffer, sizeof(buffer), "%s(%d)", Line->FileName, Line->LineNumber);
                    TextOutA(BackbufferDeviceHandle, OutlineRect.left, OutlineRect.top, buffer, length);
                }
            }
            
            BitBlt(DeviceHandle, 0, 0, Width, Height, BackbufferDeviceHandle, 0, 0, SRCCOPY);
            
            EndPaint(WindowHandle, &PaintStruct);
            
            DeleteObject(HighlightBrush);
            DeleteObject(Backbuffer);
            DeleteDC(BackbufferDeviceHandle);
            
            return 0;
        }break;
        
        case WM_ERASEBKGND:{
            // 
            // We don't need the Windows API to erase the background, 
            // and it causes flickering.
            // 
            return 1;
        }break;
    }
    
    return DefWindowProc(WindowHandle, Message, WParam, LParam);
}

//_____________________________________________________________________________________________________________________
// The main function

int main(){
    
    TCHAR *CommandLine = GetCommandLine();
    
    TCHAR *TargetCommandLine = CommandLine;
    TCHAR *TargetWorkingDirectory = NULL;
    
    // 
    // Skip until we have a space, then skip until we don't have a space.
    // This is somewhat hacky. We do this because we want to be able to just have any command line.
    //     command.exe argument_one argument_two ...
    // And just profile it using 
    //     profile command.exe argument_one argument_two ...
    // 
    while(*TargetCommandLine && *TargetCommandLine != TEXT(' ')) TargetCommandLine++;
    while(*TargetCommandLine && *TargetCommandLine == TEXT(' ')) TargetCommandLine++;
    
    print("Target Command: %s\n", TargetCommandLine);
    
    // 
    // Lookup the 'SeSystemProfilePrivilege'. 
    // We need to enable it to start the ETW trace.
    // 
    LUID SeSystemProfilePrivilege;
    BOOL LookupPrivilegeValueSuccess = LookupPrivilegeValue(NULL, SE_SYSTEM_PROFILE_NAME, &SeSystemProfilePrivilege);
    if(!LookupPrivilegeValueSuccess){
        print("Failed to lookup SeSystemProfilePrivilege. (GetLastError %d)\n", GetLastError());
        return 1;
    }
    
    // 
    // Open a handle to the current process, to adjust its privileges.
    // 
    HANDLE ProcessToken;
    BOOL OpenProcessTokenSuccess = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &ProcessToken);
    if(!OpenProcessTokenSuccess){
        print("Failed to OpenProcessToken for the current process. (GetLastError %d)\n", GetLastError());
        return 1;
    }
    
    // 
    // Attempt to enable the 'SeSystemProfilePrivilege'.
    // If the user does not have the correct privileges this will fail.
    // 
    TOKEN_PRIVILEGES TokenPrivileges = {0};
    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    TokenPrivileges.Privileges[0].Luid = SeSystemProfilePrivilege;
    
    BOOL AdjustTokenPrivilegesSuccess = AdjustTokenPrivileges(ProcessToken, /*DisableAllPrivileges*/FALSE, &TokenPrivileges, /*BufferLength*/0, /*PreviousState*/NULL, /*ReturnLength*/NULL);
    if(!AdjustTokenPrivilegesSuccess){
        print("Failed to gain the 'SeSystemProfilePrivilege'. You need to run this as administrator.\n");
        return 1;
    }
    
    // 
    // Close the 'ProcessToken' now that we don't need it anymore.
    // 
    CloseHandle(ProcessToken);
    
    // 
    // At this point we know, that we have the privileges to trace the program.
    // So in theory nothing should go wrong anymore, so start the process we want to trace.
    // We set the 'DEBUG_PROCESS' flag so we get informed about events in the target.
    // 
    STARTUPINFO TargetStartupInformation = {.cb = sizeof(TargetStartupInformation) };
    PROCESS_INFORMATION TargetProcessInformation;
    BOOL CreateProcessSuccess = CreateProcess(NULL, TargetCommandLine, NULL, NULL, 0, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, TargetWorkingDirectory, &TargetStartupInformation, &TargetProcessInformation); // @cleanup: start the process with limited privileges.
    if(!CreateProcessSuccess){
        print("Failed to create the target process. (GetLastError %d)\n", GetLastError());
        return 1;
    }
    
    // 
    // Set the global sampling interval to the maximum value.
    // 
    TRACE_PROFILE_INTERVAL Interval = {.Interval = /*8kHz*/1250};
    ULONG TraceSetProfileIntervalError = TraceSetInformation(/*SessionHandle*/0, TraceSampledProfileIntervalInfo, &Interval, sizeof(Interval));
    if(TraceSetProfileIntervalError != ERROR_SUCCESS){
        print("Failed to set the tracing interval with error %d. You need to run this as administrator.\n", TraceSetProfileIntervalError);
        return 1;
    }
    
    // 
    // We want to filter events based on the process id.
    // We only want to get events for the process we created.
    // For this we need to set up a EVENT_FILTER_DESCRIPTOR.
    // 
    
    EVENT_FILTER_DESCRIPTOR ProcessIdentifierEventFilterDescriptor = {
        .Type = EVENT_FILTER_TYPE_PID,
        
        // "If the Type member is set to EVENT_FILTER_TYPE_PID, the Ptr member points to an array of process IDs (PIDs)."
        .Ptr = (ULONGLONG)&TargetProcessInformation.dwProcessId,
        .Size = sizeof(TargetProcessInformation.dwProcessId),
    };
    
    // 
    // Get the SYSTEM_INFO to figure out the amount of processors on the system.
    // 
    SYSTEM_INFO SystemInformation;
    GetSystemInfo(&SystemInformation);
    
    // 
    // Setup EVENT_TRACE_PROPERTIES for the kernel logger.
    // 
    struct _EVENT_TRACE_PROPERTIES_AND_KERNEL_LOGGER{
        EVENT_TRACE_PROPERTIES_V2 EventTraceProperties;
        TCHAR KernelLoggerName[sizeof(KERNEL_LOGGER_NAME)];
    } EventTraceProperties = {
        .EventTraceProperties = {
            .Wnode = {
                // "Total size of memory allocated, in bytes, for the event tracing session properties."
                .BufferSize = sizeof(struct _EVENT_TRACE_PROPERTIES_AND_KERNEL_LOGGER),
                
                // "For an NT Kernel Logger session, set this member to SystemTraceControlGuid."
                .Guid = SystemTraceControlGuid,
                
                // "Clock resolution to use when logging the time stamp for each event."
                // 1 - Query performance counter.
                // 2 - System time.
                // 3 - CPU cycle counter.
                .ClientContext = 3,
                
                // "Must contain WNODE_FLAG_TRACED_GUID to indicate that the structure contains event tracing information."
                .Flags = WNODE_FLAG_TRACED_GUID | WNODE_FLAG_VERSIONED_PROPERTIES,
            },
            
            .BufferSize = 1024,
            .MinimumBuffers = 4 * SystemInformation.dwNumberOfProcessors,
            .MaximumBuffers = 6 * SystemInformation.dwNumberOfProcessors,
            
            // "You use this member to specify whether you want events written to an in-memory circular buffer, a log file, or a real-time consumer."
            .LogFileMode = EVENT_TRACE_REAL_TIME_MODE,
            
            // We want to trace sampling (profile) events as we want to profile.
            // We want to trace image loads/unloads to be able to resolve addresses.
            .EnableFlags = EVENT_TRACE_FLAG_IMAGE_LOAD | EVENT_TRACE_FLAG_PROFILE,
            
            .LoggerNameOffset = FIELD_OFFSET(struct _EVENT_TRACE_PROPERTIES_AND_KERNEL_LOGGER, KernelLoggerName),
            
            // 
            // We use Version two of the EVENT_TRACE_PROPERTIES to exclude kernel stacks.
            // We would also like to set a filter for our process id (which it sort of supports),
            // but sadly the filter does not apply to many events we care about.
            // We still apply the filter here to maybe filter out events we don't care about.
            // 
            .FilterDesc = &ProcessIdentifierEventFilterDescriptor,
            .FilterDescCount = 1,
            
            .VersionNumber = 2,
            .ExcludeKernelStack = 1,
        },
        
        .KernelLoggerName = KERNEL_LOGGER_NAME,
    };
    
    // 
    // Start an event tracing session. This will cause the kernel to start collecting samples.
    // 
    TRACEHANDLE EventTracingSessionHandle;
    ULONG StartTraceError = StartTrace(&EventTracingSessionHandle, KERNEL_LOGGER_NAME, (void *)&EventTraceProperties.EventTraceProperties);
    if(StartTraceError != ERROR_SUCCESS && StartTraceError != ERROR_ALREADY_EXISTS){
        print("StartTrace failed with error %d\n", StartTraceError);
        return 1;
    }
    
    // 
    // Enable call-stack sampling for PerfInfo SampledProfile events.
    // 
    CLASSIC_EVENT_ID Events[1];
    Events[0].EventGuid = PerfInfoGuid;
    Events[0].Type = /*SampledProfile*/46;
    ULONG TraceSetStackTracingError = TraceSetInformation(EventTracingSessionHandle, TraceStackTracingInfo, Events, sizeof(Events));
    if(TraceSetStackTracingError != ERROR_SUCCESS){
        print("Failed to enable Stack tracing with error %d.\n", TraceSetStackTracingError);
        return 1;
    }
    
    PEVENT_RECORD_CALLBACK_CONTEXT EventRecordCallbackContext = VirtualAlloc(NULL, sizeof(*EventRecordCallbackContext), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    EventRecordCallbackContext->TargetProcessId = TargetProcessInformation.dwProcessId;
    
    // 
    // Open the trace we have just started and configured.
    // This is taking a _log_ file, as ETW usually works with .etl files.
    // We specify a _logger_ instead.
    // 
    EVENT_TRACE_LOGFILE EventTraceLogfile = {
        .LoggerName = KERNEL_LOGGER_NAME,
        .ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP, 
        .EventRecordCallback = EventRecordCallback,
        .Context = EventRecordCallbackContext,
    };
    
    TRACEHANDLE TraceProcessingHandle = OpenTrace(&EventTraceLogfile);
    if(TraceProcessingHandle == INVALID_PROCESSTRACE_HANDLE){
        print("Failed to Open the trace we started. Possibly a race? (Error code %d)\n", GetLastError());
        return 1;
    }
    
    // 
    // Start processing the trace we just opened using 'ProcessTrace'.
    // This function blocks until the processing ends.
    // As we are specifying a logger instead of a .etl file, the processing will never stop.
    // Hence, we need to run 'ProcessTrace' inside another thread.
    // 
    HANDLE ProcessTraceThreadHandle = CreateThread(NULL, 0, ProcessTraceThreadStartRoutine, &TraceProcessingHandle, 0, NULL);
    if(ProcessTraceThreadHandle == NULL){
        print("Failed to create the trace processing thread with error %d.\n", GetLastError());
        return 1;
    }
    
    // @cleanup: Maybe we should communicate with the thread here?
    //           How do I check if it is tracing?
    //           
    
    // 
    // Now that the 'ProcessTraceThread' is up and sampling, resume (start) the target process.
    // 
    DWORD PreviousSuspendCount = ResumeThread(TargetProcessInformation.hThread);
    if(PreviousSuspendCount == -1){
        print("Failed to ResumeThread with error %d\n", GetLastError());
        return 1;
    }
    
    DWORD WaitForProcessError = WaitForSingleObject(TargetProcessInformation.hProcess, INFINITE);
    if(WaitForProcessError == WAIT_FAILED){
        print("Faild to wait for Process to terminate with error %d\n", GetLastError());
        return 1;
    }
    
    // 
    // Close the handles so the 'ProcessTraceThread' can exit.
    // 
    CloseTrace(TraceProcessingHandle);
    CloseTrace(EventTracingSessionHandle);
    
    // 
    // Stop the logger, otherwise it will continue to run, even if this process exits.
    // 
    ULONG ControlTraceStopError = ControlTrace(0, KERNEL_LOGGER_NAME, (void *)&EventTraceProperties.EventTraceProperties, EVENT_TRACE_CONTROL_STOP);
    if(ControlTraceStopError != ERROR_SUCCESS){
        print("Failed to Stop trace with error %d\n", ControlTraceStopError);
        return 1;
    }
    
    // 
    // Wait for the process trace thread such that we know the it does not touch the 
    // 'EventRecordCallbackContext' anymore.
    // 
    DWORD WaitForProcessTraceThreadError = WaitForSingleObject(ProcessTraceThreadHandle, INFINITE);
    if(WaitForProcessTraceThreadError){
        print("WaitForProcessTraceThreadError %d\n", WaitForProcessTraceThreadError);
        // @note: ignore.
    }
    
    // 
    // Create a window which we will use to display the data.
    // We have to do this before bringing the DbgHelp thread online, 
    // as the DbgHelp thread needs the 'WindowHandle' to invalidate the screen.
    // 
    
    WINDOW_PROCEDURE_CONTEXT WindowProcedureContext = {
        .ProfileTreeToShow = PROFILE_TREE_BOTTOM_UP,
    };
    
    WNDCLASSEX WindowClassEx = {
        .cbSize = sizeof(WindowClassEx),
        .style  = CS_HREDRAW | CS_VREDRAW,
        .lpfnWndProc = ProfileWindowProc,
        .hInstance = GetModuleHandleA(NULL),
        .lpszClassName = "FrameWindowClass",
        .hCursor = LoadCursor(NULL, IDC_ARROW),
    };
    
    ATOM WindowClassAtom = RegisterClassExA(&WindowClassEx);
    if(!WindowClassAtom){
        print("Unable to initialize window class.\n");
        return 1;
    }
    
    HWND WindowHandle = CreateWindowEx(0, WindowClassEx.lpszClassName, TEXT("Profiler - Bottom Up | ") WINDOW_TITLE_KEY_HELPER, WS_OVERLAPPEDWINDOW | WS_VISIBLE, 
            CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, 0, 0, WindowClassEx.hInstance, &WindowProcedureContext);
    
    if(WindowHandle == NULL){
        print("Unable to create window with error %d\n", GetLastError());
        return 1;
    }
    
    // 
    // Initialize the context for the DbgHelp thread.
    // 
    PROFILE_TREE_GENERATING_THREAD_CONTEXT DbgHelpThreadContext = {
        .WindowHandle = WindowHandle,
        .EventTraceBase = EventRecordCallbackContext->EventTrace.Base,
        .EventTraceSize = EventRecordCallbackContext->EventTrace.Used,
        
        .CachedProfileTrees = &WindowProcedureContext.CachedProfileTrees,
    };
    
    // 
    // Create the DbgHelp thread. It will generate the profile trees.
    // 
    HANDLE DbgHelpThreadHandle = CreateThread(NULL, 0, ProfileTreeGeneratorThreadStartRoutine, &DbgHelpThreadContext, 0, NULL);
    if(DbgHelpThreadHandle == NULL){
        print("Failed to create the profile tree generator thread with error %d.\n", GetLastError());
        return 1;
    }
    
    // 
    // Enter the window loop.
    // 
    MSG Message;
    while(GetMessage(&Message, NULL, 0, 0) != -1){
        TranslateMessage(&Message);
        DispatchMessage(&Message);
    }
    
    return 0;
}

