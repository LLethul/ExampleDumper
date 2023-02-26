#include <iostream>
#include "eyestep/eyestep_utility.cpp"
#include "eyestep/eyestep.cpp"
#include <Windows.h>
using namespace std;

int main()
{
    SetConsoleTitleA("Example Dumper");
    if (FindWindowA(0, (LPCSTR)"Roblox") == NULL)
    {
        printf("Unable to find Roblox window!\n");
        return 0;
    }

    EyeStep::open(L"RobloxPlayerBeta.exe");
    printf("Opened RobloxPlayerBeta.exe with EyeStep! (this is good)\n");

    printf("---- BEGIN DUMP ----\n");

    // task.defer XRef: "Maximum re-entrancy depth (%i) exceeded calling task.defer"
    auto taskdefer_call = EyeStep::scanner::scan_xrefs("Maximum re-entrancy depth (%i) exceeded calling task.defer")[0];
    auto taskdefer_addy = EyeStep::util::getPrologue(taskdefer_call);

    printf("task.defer addy: 0x%X", EyeStep::util::raslr(taskdefer_addy)); printf("\n");

    // getstate sig: "55 8B EC 8B 45 08 8B 00 83 F8 ?? 77 ?? FF 24 85 ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C8"
    auto getstate_siggy = EyeStep::util::getPrologue(EyeStep::scanner::scan("55 8B EC 8B 45 08 8B 00 83 F8 ?? 77 ?? FF 24 85 ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C8")[0]);

    printf("getstate addy: 0x%X", EyeStep::util::raslr(getstate_siggy)); printf("\n");

    // taskscheduler sig: "55 8B EC 64 A1 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 64 A1 ?? ?? ?? ?? 8B 08 A1 ?? ?? ?? ?? 3B 81 08 00 00 00 7F ?? A1 ?? ?? ?? ?? 8B 4D F4 64 89 0D ?? ?? ?? ?? 8B E5 5D C3 8D 4D E4 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 45 E4 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 83 3D ?? ?? ?? ?? ?? 75 ?? 68 ?? ?? ?? ??"
    auto taskscheduler = EyeStep::util::getPrologue(EyeStep::scanner::scan("55 8B EC 64 A1 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 64 A1 ?? ?? ?? ?? 8B 08 A1 ?? ?? ?? ?? 3B 81 08 00 00 00 7F ?? A1 ?? ?? ?? ?? 8B 4D F4 64 89 0D ?? ?? ?? ?? 8B E5 5D C3 8D 4D E4 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 45 E4 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 83 3D ?? ?? ?? ?? ?? 75 ?? 68 ?? ?? ?? ??")[0]);

    printf("taskscheduler addy: 0x%X", EyeStep::util::raslr(taskscheduler)); printf("\n");

    // print XRef: "Video recording started"
    auto print_call = EyeStep::util::nextCall(EyeStep::scanner::scan_xrefs("Video recording started")[0], false, false);

    printf("print addy: 0x%X", EyeStep::util::raslr(print_call)); printf("\n");

    // pushvfstring XRef: "%s:%d: %s"
    auto pv = EyeStep::util::nextCall(EyeStep::scanner::scan_xrefs("%s:%d: %s")[0], false, false);

    printf("pushvfstring addy: 0x%X", EyeStep::util::raslr(pv)); printf("\n");

    // LuaVM::load XRef: "oldResult, moduleRef  = ..."
    auto lvm_call = EyeStep::util::nextCall(EyeStep::scanner::scan_xrefs("oldResult, moduleRef  = ...")[0], false, false);

    printf("LuaVM::load addy: 0x%X", EyeStep::util::raslr(lvm_call)); printf("\n");

    printf("---- END DUMP ----\n");
    printf("Remember, use ASLR on the addies!");

    exit(0x00000);
}