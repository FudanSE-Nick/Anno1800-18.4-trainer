using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

// Anno 1800 18.4.1412158, Steam build 16367353, single-player memory trainer.
// It reads saves only to identify human-owned area IDs. All cheats write process memory.
// The save parser below is a native port of refresh_owned_areas.py, so the owned island
// list is refreshed in the background whenever a newer save appears: no restart needed.
internal static class Anno1800MemoryTrainer
{
    private const string ExpectedExeSha256 = "C323FD6BE31BEF2CFD30A80CC6585818BA01E99799DC48E47862AB5A150DA1E7";
    private const int PinHotkeyMainId = 910, PinHotkeyNumpadId = 911;
    private const uint PinHotkeyModifiers = 0x0002U | 0x0001U | 0x4000U;
    private const uint VkControl = 0x11, VkMenu = 0x12, VkMinusMain = 0xBD, VkMinusNumpad = 0x6D;
    private const double PinIntervalSeconds = 0.25, PinRecordRefreshSeconds = 5.0, SaveCheckSeconds = 3.0;
    private const int PinCapacityFloor = 50, PinCapacityCeiling = 100000;
    private const ulong PlayerResourcesVtableRva = 0x514B830UL;
    private const ulong AreaWarehouseEntityVtableRva = 0x5106BD0UL;
    private const ulong WarehouseVtableRva = 0x514BE90UL;
    private const uint ProcessAccess = 0x0010 | 0x0020 | 0x0008 | 0x0400;
    private const uint MemCommit = 0x1000, MemPrivate = 0x20000;
    private const uint MemReserve = 0x2000, MemRelease = 0x8000;
    private const uint PageReadWrite = 0x04, PageWriteCopy = 0x08;
    private const uint PageExecuteReadWrite = 0x40, PageExecuteWriteCopy = 0x80;
    private static readonly byte[] ShipSignature = { 0xF3,0x0F,0x11,0x47,0x14,0x0F,0x2F,0xF8,0x72,0x0B,0x8B,0x57,0x10 };
    private static readonly byte[] ShipOriginal = { 0xF3,0x0F,0x11,0x47,0x14 };
    private static IntPtr processHandle = IntPtr.Zero;
    private static Process game;
    private static ulong moduleBase;
    private static ulong moduleSize;
    private static ulong shipPatchAddress;
    private static ulong shipCaveAddress;
    private static bool shipEnabled;
    private static Dictionary<int,List<GoodTarget>> stockTargets;
    private static SortedDictionary<int,HotkeyAssignment> hotkeys = new SortedDictionary<int,HotkeyAssignment>();
    private static HashSet<int> selectedGuids = new HashSet<int>();
    private static HashSet<uint> ownedAreaIds;
    private static string loadedHotkeysText;
    private static string rejectedHotkeysText;
    private static readonly Dictionary<ulong,StockChange> stockChanges = new Dictionary<ulong,StockChange>();
    private static readonly List<StockChange> stockChangeOrder = new List<StockChange>();
    private static InfluenceTarget influenceTarget;
    private static int influenceCandidateCount;
    private static long influenceGrant;
    private static int influenceOriginalTotal, influenceOriginalAvailable, influenceLastWrittenTotal;
    private static bool influenceWriteUncertain;
    // The influence table used to be located once, at start-up: if the game was still loading
    // at that moment the whole session refused to write. It is now retried in the background
    // (3s, 5s, 10s, 20s, then every 40s) until it is uniquely located.
    private static volatile List<InfluenceTarget> pendingInfluence;
    private static int influenceScanRunning;
    private static DateTime nextInfluenceRetryUtc;
    private static int influenceRetrySeconds = 3;
    // Ctrl+Alt+- stock lock: every goods record of every owned island is held at capacity.
    private static bool pinEnabled;
    private static List<GoodTarget> pinCandidates = new List<GoodTarget>();
    private static readonly List<PinGroup> pinGroups = new List<PinGroup>();
    private static int pinRecordCount;
    private static DateTime nextPinTickUtc, nextPinRescanUtc, nextSaveCheckUtc, pinReportUtc, nextPinRecoverUtc;
    private static int pinRecoverAttempts;
    // Automatic island refresh: newest save file tracking plus the background scan handoff.
    private static string ownedAreasSaveName = "";
    private static string lastSeenSavePath = "", appliedSavePath = "";
    private static DateTime lastSeenSaveWriteUtc, appliedSaveWriteUtc;
    private static long lastSeenSaveLength = -1, appliedSaveLength = -1;
    private static volatile ScanOutput pendingScan;
    private static int scanRunning;
    private static readonly HashSet<uint> baselineUnknownAreas = new HashSet<uint>();
    private static readonly HashSet<uint> reportedUnknownAreas = new HashSet<uint>();
    private static bool fallbackPollingNeeded;
    // A thread timer (hWnd == NULL) ignores a caller supplied id and generates its own, so
    // the value returned by SetTimer is the one that comes back in WM_TIMER's wParam.
    private static UIntPtr pollTimerId = UIntPtr.Zero;

    private sealed class HotkeyAssignment
    {
        public int Slot, Guid;
        public string Name;
        // Set by a trailing |toggle in hotkeys.txt: the key then switches between
        // "every island at capacity" and "every island at zero".
        public bool ToggleZero;
    }
    private sealed class HotkeyConfiguration
    {
        public SortedDictionary<int,HotkeyAssignment> Map=new SortedDictionary<int,HotkeyAssignment>();
        public HashSet<int> Guids=new HashSet<int>();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryBasicInformation
    {
        public ulong BaseAddress, AllocationBase;
        public uint AllocationProtect, Alignment1;
        public ulong RegionSize;
        public uint State, Protect, Type, Alignment2;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct Msg
    {
        public IntPtr hWnd;
        public uint message;
        public UIntPtr wParam;
        public IntPtr lParam;
        public uint time;
        public int ptX, ptY;
        public uint lPrivate;
    }
    [DllImport("kernel32.dll", SetLastError=true)] private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool ReadProcessMemory(IntPtr handle, IntPtr address, byte[] data, IntPtr length, out IntPtr read);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool WriteProcessMemory(IntPtr handle, IntPtr address, byte[] data, IntPtr length, out IntPtr written);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern int VirtualQueryEx(IntPtr handle, IntPtr address, out MemoryBasicInformation info, IntPtr length);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern IntPtr VirtualAllocEx(IntPtr handle, IntPtr address, IntPtr size, uint type, uint protection);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool VirtualFreeEx(IntPtr handle, IntPtr address, IntPtr size, uint type);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool VirtualProtectEx(IntPtr handle, IntPtr address, IntPtr size, uint protection, out uint oldProtection);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool FlushInstructionCache(IntPtr handle, IntPtr address, IntPtr size);
    [DllImport("user32.dll", SetLastError=true)] private static extern bool RegisterHotKey(IntPtr hWnd, int id, uint modifiers, uint virtualKey);
    [DllImport("user32.dll", SetLastError=true)] private static extern bool UnregisterHotKey(IntPtr hWnd, int id);
    [DllImport("user32.dll")] private static extern int GetMessage(out Msg msg, IntPtr hWnd, uint min, uint max);
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
    [DllImport("user32.dll", SetLastError=true)] private static extern UIntPtr SetTimer(IntPtr hWnd, UIntPtr id, uint milliseconds, IntPtr callback);
    [DllImport("user32.dll", SetLastError=true)] private static extern bool KillTimer(IntPtr hWnd, UIntPtr id);
    [DllImport("user32.dll")] private static extern short GetAsyncKeyState(int virtualKey);

    private static IntPtr Ptr(ulong value) { return new IntPtr(unchecked((long)value)); }
    private static ulong U64(byte[] data, int offset) { return BitConverter.ToUInt64(data, offset); }
    private static uint U32(byte[] data, int offset) { return BitConverter.ToUInt32(data, offset); }
    private static ushort U16(byte[] data, int offset) { return BitConverter.ToUInt16(data, offset); }

    private static bool Read(ulong address, byte[] data)
    {
        IntPtr read;
        return ReadProcessMemory(processHandle, Ptr(address), data, Ptr((ulong)data.Length), out read) && read.ToInt64() == data.Length;
    }
    private static byte[] ReadBytes(ulong address, int length)
    {
        byte[] data = new byte[length];
        return Read(address, data) ? data : null;
    }
    private static void Write(ulong address, byte[] data)
    {
        IntPtr written;
        if (!WriteProcessMemory(processHandle, Ptr(address), data, Ptr((ulong)data.Length), out written) || written.ToInt64() != data.Length)
            throw new InvalidOperationException("WriteProcessMemory failed at 0x" + address.ToString("X") + ": " + Marshal.GetLastWin32Error());
    }
    private static void ScanPrivate(Action<ulong,byte[],int> inspect)
    {
        byte[] buffer = new byte[1024 * 1024];
        ulong cursor = 0;
        while (cursor < 0x00007FFFFFF00000UL)
        {
            MemoryBasicInformation info;
            if (VirtualQueryEx(processHandle, Ptr(cursor), out info, Ptr((ulong)Marshal.SizeOf(typeof(MemoryBasicInformation)))) == 0) break;
            ulong end = info.BaseAddress + info.RegionSize;
            if (end <= cursor) break;
            uint protection = info.Protect & 0xFF;
            if (info.State == MemCommit && info.Type == MemPrivate &&
                (protection == PageReadWrite || protection == PageWriteCopy ||
                 protection == PageExecuteReadWrite || protection == PageExecuteWriteCopy))
            {
                for (ulong address = info.BaseAddress; address < end; )
                {
                    int length = (int)Math.Min((ulong)buffer.Length, end-address);
                    IntPtr read;
                    if (ReadProcessMemory(processHandle, Ptr(address), buffer, Ptr((ulong)length), out read) && read.ToInt64() > 0)
                        inspect(address, buffer, (int)read.ToInt64());
                    address += (uint)length;
                }
            }
            cursor = end;
        }
    }
    private static ulong FindListHead(ulong record)
    {
        HashSet<ulong> seen = new HashSet<ulong>();
        ulong current = record;
        for (int i=0; i<600 && current != 0 && seen.Add(current); i++)
        {
            byte[] node = ReadBytes(current, 0x30);
            if (node == null) return 0;
            if (U32(node,0x18) == 0 && U64(node,0) != 0 && U64(node,8) != 0) return current;
            current = U64(node,8);
        }
        return 0;
    }
    // Saved head pointers are more reliable than the head node's GUID field:
    // the New World uses a nonzero value in that field on this game build.
    private static bool IsLinkedToHead(ulong record,ulong expectedHead)
    {
        HashSet<ulong> seen=new HashSet<ulong>();
        ulong current=record;
        for (int i=0;i<1000 && current!=0 && seen.Add(current);i++)
        {
            if (current==expectedHead) return true;
            byte[] node=ReadBytes(current,0x10);
            if (node==null) return false;
            ulong previous=U64(node,8);
            byte[] previousNode=ReadBytes(previous,8);
            if (previousNode==null || U64(previousNode,0)!=current) return false;
            current=previous;
        }
        return false;
    }
    private static Dictionary<ulong,Dictionary<int,ulong>> FindGoodHeads()
    {
        Dictionary<ulong,Dictionary<int,ulong>> result = new Dictionary<ulong,Dictionary<int,ulong>>();
        List<KeyValuePair<ulong,int>> candidates = new List<KeyValuePair<ulong,int>>();
        bool[] firstBytes = new bool[256];
        foreach (int guid in selectedGuids) firstBytes[BitConverter.GetBytes(guid)[0]]=true;
        ScanPrivate(delegate(ulong start, byte[] data, int length)
        {
            for (int i=0; i<=length-4; i++)
                if (firstBytes[data[i]] && start+(uint)i>=0x18)
                {
                    int guid=unchecked((int)U32(data,i));
                    if (selectedGuids.Contains(guid))
                        candidates.Add(new KeyValuePair<ulong,int>(start+(uint)i-0x18,guid));
                }
        });
        foreach (KeyValuePair<ulong,int> candidate in candidates)
        {
            ulong address=candidate.Key;
            int guid=candidate.Value;
            byte[] data = ReadBytes(address,0x30);
            if (data==null || U32(data,0x18)!=(uint)guid || U16(data,0x12)!=15 || U16(data,0x1A)!=15) continue;
            uint capacity=U32(data,0x1C), count=U32(data,0x20);
            if (capacity<50 || capacity>100000 || count>capacity) continue;
            ulong head=FindListHead(address);
            if (head==0) continue;
            Dictionary<int,ulong> goods;
            if (!result.TryGetValue(head,out goods)) { goods=new Dictionary<int,ulong>();result.Add(head,goods); }
            if (!goods.ContainsKey(guid)) goods.Add(guid,address);
        }
        return result;
    }
    private static Dictionary<ulong,ulong> FindWarehouseObjects(Dictionary<ulong,Dictionary<int,ulong>> heads)
    {
        Dictionary<ulong,ulong> result = new Dictionary<ulong,ulong>();
        ScanPrivate(delegate(ulong start, byte[] data, int length)
        {
            for (int i=0; i<=length-8; i+=8)
            {
                ulong head=U64(data,i);
                if (!heads.ContainsKey(head) || start+(uint)i<0x28) continue;
                ulong parent=start+(uint)i-0x28;
                byte[] header=ReadBytes(parent,0x40);
                if (header==null) continue;
                ulong vtable=U64(header,0);
                if (vtable<moduleBase || vtable>=moduleBase+moduleSize || U64(header,0x28)!=head) continue;
                ulong count=U64(header,0x30);
                if (count<20 || count>1000) continue;
                result[parent]=head;
            }
        });
        return result;
    }
    private sealed class GoodTarget
    {
        public ulong Address;
        public ulong HeadAddress, ParentAddress, EntityAddress;
        public int Guid;
        public uint AreaId, Capacity, Count;
    }
    private sealed class StockChange
    {
        public GoodTarget Target;
        public uint OriginalCount;
    }
    // A warehouse list node carries its asset category in two u16 fields. On this build the
    // categories seen for real goods are 15 (Old World/Cape, 1010xxx), 1 (New World and other
    // DLC goods, 112xxx-120xxx), 2 (High Life lifestyle goods, 135xxx, e.g. 135186 Chewing
    // Gum) and 0 (New World Rising goods with small GUIDs: 5382 ice cream, 5385 milk,
    // 5388 perfume, 5803 soccer balls, 836 bauxite, ...). The same lists also hold non-goods
    // entries (mails, science reports, scenario counters) but those always have capacity 0 and
    // are already rejected by the capacity floor applied by every caller.
    private static bool IsGoodsRecord(byte[] record)
    {
        return U16(record,0x12)==U16(record,0x1A);
    }
    private sealed class InfluenceTarget
    {
        public ulong ObjectAddress, HeadAddress, Address, CoinAddress;
        public int Total, Available, Coin;
    }
    // One owned island warehouse during the Ctrl+Alt+- lock. The area entity and the
    // warehouse object are re-checked every tick, the individual goods records every write.
    private sealed class PinGroup
    {
        public ulong EntityAddress, WarehouseAddress, HeadAddress;
        public uint AreaId;
        public List<GoodTarget> Targets = new List<GoodTarget>();
    }
    // Result of one process memory scan. It is built either on the startup thread or by the
    // background refresh thread; the main thread applies it, so no field races on state.
    private sealed class ScanOutput
    {
        public HashSet<uint> Areas;
        public Dictionary<int,List<GoodTarget>> Configured;
        public List<GoodTarget> AllGoods;
        public List<InfluenceTarget> InfluenceCandidates;
        public HashSet<uint> SeenAreas;
        public HashSet<int> WantedGuids;
        public string SaveName, Detail, Error;
        public int ConfiguredCount
        {
            get
            {
                int total=0;
                if (Configured!=null) foreach (List<GoodTarget> list in Configured.Values) total+=list.Count;
                return total;
            }
        }
    }
    private static InfluenceTarget ReadInfluenceObject(ulong objectAddress)
    {
        byte[] owner=ReadBytes(objectAddress,0x38);
        if (owner==null || U64(owner,0)!=moduleBase+PlayerResourcesVtableRva || U64(owner,0x30)!=6) return null;
        ulong headAddress=U64(owner,0x28);
        if (headAddress<0x10000 || headAddress>=0x00007FFFFFF00000UL) return null;
        byte[] head=ReadBytes(headAddress,0x28);
        // The head node's category field is 1 on this build (it used to be 0), so it is not
        // used to recognise the head: the doubly linked closure below is what proves it.
        if (head==null || U64(head,0)==0 || U64(head,8)==0) return null;
        ulong current=U64(head,0), previous=headAddress;
        HashSet<ulong> visited=new HashSet<ulong>();
        InfluenceTarget found=new InfluenceTarget {ObjectAddress=objectAddress,HeadAddress=headAddress};
        int influenceCount=0, coinCount=0, count=0;
        while (current!=headAddress && current!=0 && count<6 && visited.Add(current))
        {
            byte[] item=ReadBytes(current,0x28);
            if (item==null || U64(item,8)!=previous) return null;
            uint guid=U32(item,0x18);
            if (guid==1010190)
            {
                if (U16(item,0x12)!=15) return null;
                influenceCount++;
                found.Address=current;
                found.Total=unchecked((int)U32(item,0x1C));
                found.Available=unchecked((int)U32(item,0x20));
            }
            else if (guid==1010017)
            {
                if (U16(item,0x12)!=15) return null;
                coinCount++;
                found.CoinAddress=current;
                found.Coin=unchecked((int)U32(item,0x20));
            }
            previous=current;
            current=U64(item,0);
            count++;
        }
        if (count!=6 || current!=headAddress || U64(head,8)!=previous || influenceCount!=1 || coinCount!=1 ||
            found.Total<0 || found.Total>10000000 || found.Available< -10000000 || found.Available>10000000)
            return null;
        return found;
    }
    private static Dictionary<int,List<GoodTarget>> FindOwnedGoods(HashSet<uint> owned)
    {
        Dictionary<ulong,Dictionary<int,ulong>> heads=FindGoodHeads();
        Dictionary<ulong,ulong> warehouses=FindWarehouseObjects(heads);
        Dictionary<int,List<GoodTarget>> result=new Dictionary<int,List<GoodTarget>>();
        foreach (int guid in selectedGuids) result[guid]=new List<GoodTarget>();
        HashSet<ulong> seen=new HashSet<ulong>();
        ScanPrivate(delegate(ulong start, byte[] data, int length)
        {
            for (int i=0; i<=length-8; i+=8)
            {
                ulong parent=U64(data,i), head;
                if (!warehouses.TryGetValue(parent,out head) || start+(uint)i<0x180) continue;
                ulong areaAddress=start+(uint)i-0x180;
                byte[] entity=ReadBytes(areaAddress,0x10);
                if (entity==null) continue;
                uint areaId=U32(entity,0);
                ulong vtable=U64(entity,8);
                if (!owned.Contains(areaId) || U32(entity,4)!=0 || vtable<moduleBase || vtable>=moduleBase+moduleSize) continue;
                foreach (KeyValuePair<int,ulong> good in heads[head])
                {
                    ulong address=good.Value;
                    if (seen.Contains(address)) continue;
                    byte[] record=ReadBytes(address,0x28);
                    if (record==null || U32(record,0x18)!=(uint)good.Key) continue;
                    seen.Add(address);
                    result[good.Key].Add(new GoodTarget { Address=address,HeadAddress=head,ParentAddress=parent,EntityAddress=areaAddress,
                        Guid=good.Key,AreaId=areaId,Capacity=U32(record,0x1C),Count=U32(record,0x20) });
                }
            }
        });
        return result;
    }
    // The save already tells us which AreaIDs are ours. Locate those area objects
    // directly, then follow their warehouse and goods-list pointers in one sweep.
    // wanted == null collects nothing for the hotkeys; collectAll additionally records
    // every other goods type of those warehouses, which the Ctrl+Alt+- lock fills.
    // collectSeenAreas reports area entities that are not ours, so a freshly settled
    // island can be announced before it ever reaches a save file.
    private static ScanOutput ScanOwnedGoods(HashSet<uint> owned,HashSet<int> wanted,bool collectAll,bool collectSeenAreas,bool scanInfluence)
    {
        ScanOutput output=new ScanOutput();
        output.Areas=owned;
        output.WantedGuids=wanted;
        output.Configured=wanted==null ? null : new Dictionary<int,List<GoodTarget>>();
        if (wanted!=null) foreach (int guid in wanted) output.Configured[guid]=new List<GoodTarget>();
        output.AllGoods=collectAll ? new List<GoodTarget>() : null;
        output.SeenAreas=collectSeenAreas ? new HashSet<uint>() : null;
        output.InfluenceCandidates=scanInfluence ? new List<InfluenceTarget>() : null;
        ulong playerResourcesVtable=moduleBase+PlayerResourcesVtableRva;
        HashSet<ulong> seenRecords=new HashSet<ulong>();
        ScanPrivate(delegate(ulong start,byte[] data,int length)
        {
            for (int i=0;i<=length-8;i+=8)
            {
                if (output.InfluenceCandidates!=null && data[i]==(byte)playerResourcesVtable && U64(data,i)==playerResourcesVtable)
                {
                    InfluenceTarget candidate=ReadInfluenceObject(start+(uint)i);
                    if (candidate!=null && candidate.Total>0) output.InfluenceCandidates.Add(candidate);
                }
                ulong entityAddress=start+(uint)i;
                ulong vtable;
                if (i+16<=length) vtable=U64(data,i+8);
                else
                {
                    byte[] vtableBytes=ReadBytes(entityAddress+8,8);
                    if (vtableBytes==null) continue;
                    vtable=U64(vtableBytes,0);
                }
                if (vtable!=moduleBase+AreaWarehouseEntityVtableRva) continue;
                uint areaId;
                if (i+0x68<=length) areaId=U16(data,i+0x64);
                else
                {
                    byte[] areaBytes=ReadBytes(entityAddress+0x64,2);
                    if (areaBytes==null) continue;
                    areaId=U16(areaBytes,0);
                }
                if (output.SeenAreas!=null) output.SeenAreas.Add(areaId);
                if (owned==null || !owned.Contains(areaId)) continue;
                ulong parent;
                if (i+0x188<=length) parent=U64(data,i+0x180);
                else
                {
                    byte[] link=ReadBytes(entityAddress+0x180,8);
                    if (link==null) continue;
                    parent=U64(link,0);
                }
                if (parent<0x10000 || parent>=0x00007FFFFFF00000UL) continue;
                byte[] warehouse=ReadBytes(parent,0x38);
                if (warehouse==null) continue;
                ulong warehouseVtable=U64(warehouse,0);
                ulong headAddress=U64(warehouse,0x28);
                ulong nodeCount=U64(warehouse,0x30);
                if (warehouseVtable!=moduleBase+WarehouseVtableRva ||
                    headAddress<0x10000 || nodeCount<20 || nodeCount>1000) continue;
                byte[] head=ReadBytes(headAddress,0x28);
                if (head==null || U64(head,0)==0 || U64(head,8)==0) continue;
                ulong current=U64(head,0), previous=headAddress;
                HashSet<ulong> visited=new HashSet<ulong>();
                List<GoodTarget> found=new List<GoodTarget>();
                for (int node=0;node<(int)nodeCount && current!=headAddress && current!=0 && visited.Add(current);node++)
                {
                    byte[] record=ReadBytes(current,0x28);
                    if (record==null || U64(record,8)!=previous) break;
                    int guid=unchecked((int)U32(record,0x18));
                    uint capacity=U32(record,0x1C), count=U32(record,0x20);
                    bool wantedGood = output.Configured!=null && output.Configured.ContainsKey(guid);
                    if ((collectAll || wantedGood) && guid>0 && IsGoodsRecord(record) &&
                        capacity>=PinCapacityFloor && capacity<=PinCapacityCeiling && count<=capacity)
                        found.Add(new GoodTarget {Address=current,HeadAddress=headAddress,ParentAddress=parent,
                            EntityAddress=entityAddress,Guid=guid,AreaId=areaId,Capacity=capacity,Count=count});
                    previous=current;
                    current=U64(record,0);
                }
                if (current!=headAddress || U64(head,8)!=previous) continue;
                foreach (GoodTarget target in found)
                {
                    if (!seenRecords.Add(target.Address)) continue;
                    List<GoodTarget> configured;
                    if (output.Configured!=null && output.Configured.TryGetValue(target.Guid,out configured))
                        configured.Add(target);
                    if (output.AllGoods!=null) output.AllGoods.Add(target);
                }
            }
        });
        return output;
    }
    // ------------------------------------------------------------------------------
    // 只读存档解析。refresh_owned_areas.py 的原生实现：
    // RDA 容器 -> 连续 zlib 流 -> Anno FileDB 二进制 XML -> GameSessionManager/
    // AreaInfo/Owner。解析全部在内存里完成，不改写存档；有它才能在运行中自动识别新岛。
    // ------------------------------------------------------------------------------
    private const uint FileDbMagic = 0xFFFFFFFD;
    private const int RdaDirectoryEntrySize = 560, RdaFirstBlockOffset = 0x310;
    private sealed class InflateState
    {
        public byte[] Input;
        public int Position, End;
        public uint Bits;
        public int BitCount;
    }
    private sealed class HuffmanTable
    {
        public readonly int[] Count = new int[16];
        public readonly int[] Symbol = new int[288];
    }
    private static readonly int[] LengthBase = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
    private static readonly int[] LengthExtra = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
    private static readonly int[] DistanceBase = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
    private static readonly int[] DistanceExtra = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
    private static readonly int[] CodeLengthOrder = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};
    private static int InflateBits(InflateState state,int count)
    {
        while (state.BitCount<count)
        {
            if (state.Position>=state.End) throw new InvalidDataException("压缩流提前结束。");
            state.Bits|=(uint)state.Input[state.Position++]<<state.BitCount;
            state.BitCount+=8;
        }
        int value=(int)(state.Bits&((1U<<count)-1));
        state.Bits>>=count;
        state.BitCount-=count;
        return value;
    }
    private static int BuildHuffman(HuffmanTable table,int[] lengths,int count)
    {
        for (int length=0;length<16;length++) table.Count[length]=0;
        for (int symbol=0;symbol<count;symbol++) table.Count[lengths[symbol]]++;
        if (table.Count[0]==count) return 0;
        int left=1;
        for (int length=1;length<=15;length++)
        {
            left<<=1;
            left-=table.Count[length];
            if (left<0) return left;
        }
        int[] offsets=new int[16];
        for (int length=1;length<15;length++) offsets[length+1]=offsets[length]+table.Count[length];
        for (int symbol=0;symbol<count;symbol++)
            if (lengths[symbol]!=0) table.Symbol[offsets[lengths[symbol]]++]=symbol;
        return left;
    }
    private static int DecodeSymbol(InflateState state,HuffmanTable table)
    {
        int code=0,first=0,index=0;
        for (int length=1;length<=15;length++)
        {
            code|=InflateBits(state,1);
            int count=table.Count[length];
            if (code-count<first) return table.Symbol[index+(code-first)];
            index+=count;
            first+=count;
            first<<=1;
            code<<=1;
        }
        return -1;
    }
    private static void CopyMatch(MemoryStream output,int distance,int length)
    {
        for (int i=0;i<length;i++)
        {
            if (distance>output.Length) throw new InvalidDataException("压缩流引用了输出之前的数据。");
            byte[] buffer=output.GetBuffer();
            output.WriteByte(buffer[output.Length-distance]);
        }
    }
    // Raw DEFLATE decoder. consumed reports the absolute end offset of the bit stream,
    // which is what makes the consecutive zlib streams of an RDA entry separable.
    private static byte[] InflateRaw(byte[] input,int start,int end,out int consumed)
    {
        InflateState state=new InflateState {Input=input,Position=start,End=end};
        MemoryStream output=new MemoryStream();
        HuffmanTable literals=new HuffmanTable(), distances=new HuffmanTable(), codeLengths=new HuffmanTable();
        int[] codeLengthList=new int[19];
        int[] distanceLengths=new int[30];
        int[] tableLengths=new int[320];
        int[] fixedLengths=new int[288];
        int last;
        do
        {
            last=InflateBits(state,1);
            int type=InflateBits(state,2);
            if (type==0)
            {
                state.Bits=0;
                state.BitCount=0;
                if (state.Position+4>state.End) throw new InvalidDataException("未压缩块头部不完整。");
                int length=input[state.Position]|(input[state.Position+1]<<8);
                int complement=input[state.Position+2]|(input[state.Position+3]<<8);
                state.Position+=4;
                if ((length^0xFFFF)!=complement) throw new InvalidDataException("未压缩块长度校验失败。");
                if (state.Position+length>state.End) throw new InvalidDataException("未压缩块数据不完整。");
                output.Write(input,state.Position,length);
                state.Position+=length;
                continue;
            }
            if (type==1)
            {
                int symbol;
                for (symbol=0;symbol<144;symbol++) fixedLengths[symbol]=8;
                for (;symbol<256;symbol++) fixedLengths[symbol]=9;
                for (;symbol<280;symbol++) fixedLengths[symbol]=7;
                for (;symbol<288;symbol++) fixedLengths[symbol]=8;
                BuildHuffman(literals,fixedLengths,288);
                for (symbol=0;symbol<30;symbol++) fixedLengths[symbol]=5;
                BuildHuffman(distances,fixedLengths,30);
            }
            else if (type==2)
            {
                int literalCount=InflateBits(state,5)+257;
                int distanceCount=InflateBits(state,5)+1;
                int codeCount=InflateBits(state,4)+4;
                if (literalCount>286 || distanceCount>30) throw new InvalidDataException("动态哈夫曼表超出范围。");
                for (int i=0;i<19;i++) codeLengthList[i]=0;
                for (int i=0;i<codeCount;i++) codeLengthList[CodeLengthOrder[i]]=InflateBits(state,3);
                BuildHuffman(codeLengths,codeLengthList,19);
                int index=0;
                while (index<literalCount+distanceCount)
                {
                    int symbol=DecodeSymbol(state,codeLengths);
                    if (symbol<0) throw new InvalidDataException("码长表解码失败。");
                    if (symbol<16) { tableLengths[index++]=symbol; continue; }
                    int repeat,value=0;
                    if (symbol==16)
                    {
                        if (index==0) throw new InvalidDataException("码长重复没有可用的前置值。");
                        value=tableLengths[index-1];
                        repeat=3+InflateBits(state,2);
                    }
                    else if (symbol==17) repeat=3+InflateBits(state,3);
                    else repeat=11+InflateBits(state,7);
                    if (index+repeat>literalCount+distanceCount) throw new InvalidDataException("码长重复次数超出范围。");
                    while (repeat-->0) tableLengths[index++]=value;
                }
                if (tableLengths[256]==0) throw new InvalidDataException("压缩块缺少结束码。");
                BuildHuffman(literals,tableLengths,literalCount);
                for (int i=0;i<distanceCount;i++) distanceLengths[i]=tableLengths[literalCount+i];
                BuildHuffman(distances,distanceLengths,distanceCount);
            }
            else throw new InvalidDataException("无效的压缩块类型。");
            for (;;)
            {
                int symbol=DecodeSymbol(state,literals);
                if (symbol<0) throw new InvalidDataException("字面量解码失败。");
                if (symbol<256) { output.WriteByte((byte)symbol); continue; }
                if (symbol==256) break;
                int lengthIndex=symbol-257;
                if (lengthIndex>=29) throw new InvalidDataException("长度码超出范围。");
                int matchLength=LengthBase[lengthIndex]+InflateBits(state,LengthExtra[lengthIndex]);
                int distanceSymbol=DecodeSymbol(state,distances);
                if (distanceSymbol<0 || distanceSymbol>=30) throw new InvalidDataException("距离码超出范围。");
                CopyMatch(output,DistanceBase[distanceSymbol]+InflateBits(state,DistanceExtra[distanceSymbol]),matchLength);
            }
        }
        while (last==0);
        consumed=state.Position-(state.BitCount>>3);
        return output.ToArray();
    }
    private static uint Adler32(byte[] data)
    {
        const uint Modulus=65521;
        uint a=1,b=0;
        int index=0;
        while (index<data.Length)
        {
            int block=Math.Min(5552,data.Length-index);
            for (int end=index+block;index<end;index++) { a+=data[index]; b+=a; }
            a%=Modulus;
            b%=Modulus;
        }
        return (b<<16)|a;
    }
    private static byte[] InflateZlib(byte[] data,int start,int end,out int consumed)
    {
        if (end-start<6) throw new InvalidDataException("zlib 流长度不足。");
        int method=data[start], flags=data[start+1];
        if ((method&0x0F)!=8) throw new InvalidDataException("不支持的 zlib 压缩方式。");
        if ((((method<<8)|flags)%31)!=0) throw new InvalidDataException("zlib 头校验失败。");
        if ((flags&0x20)!=0) throw new InvalidDataException("不支持带预置字典的 zlib 流。");
        int deflateEnd;
        byte[] output=InflateRaw(data,start+2,end,out deflateEnd);
        // InflateRaw reports an absolute offset, so the checksum follows it directly.
        // zlib stores the Adler-32 big-endian, unlike the rest of the file format.
        int checksumAt=deflateEnd;
        if (checksumAt+4>end) throw new InvalidDataException("zlib 校验和缺失。");
        uint stored=((uint)data[checksumAt]<<24)|((uint)data[checksumAt+1]<<16)|
            ((uint)data[checksumAt+2]<<8)|data[checksumAt+3];
        if (stored!=Adler32(output)) throw new InvalidDataException("zlib 校验和不匹配（存档可能正在写入）。");
        consumed=checksumAt+4-start;
        return output;
    }
    // An RDA entry holds consecutive zlib streams; an empty stream terminates the data and
    // a trailing uint32 repeats the decompressed size.
    private static byte[] DecompressStream(byte[] raw)
    {
        int capacity=0;
        if (raw.Length>=4)
        {
            uint declared=U32(raw,raw.Length-4);
            if (declared>0 && declared<=400U*1024U*1024U) capacity=(int)declared;
        }
        MemoryStream output=new MemoryStream(capacity);
        int position=0;
        while (position<raw.Length)
        {
            int consumed;
            byte[] piece=InflateZlib(raw,position,raw.Length,out consumed);
            if (consumed<=0) throw new InvalidDataException("zlib 流没有推进。");
            position+=consumed;
            if (piece.Length==0) break;
            output.Write(piece,0,piece.Length);
        }
        byte[] result=output.ToArray();
        if (raw.Length-position>=4 && U32(raw,position)!=(uint)result.Length)
            throw new InvalidDataException("解压长度与存档记录不一致："+result.Length+" != "+U32(raw,position)+"。");
        return result;
    }
    private static string DecodeUtf16Name(byte[] data,int offset,int length)
    {
        string text=Encoding.Unicode.GetString(data,offset,length);
        int end=text.IndexOf('\0');
        return end<0 ? text : text.Substring(0,end);
    }
    private static byte[] ExtractRdaFile(byte[] data,string wantedName)
    {
        if (data.Length<RdaFirstBlockOffset+8) throw new InvalidDataException("文件太小，不是 RDA 容器。");
        if (!Encoding.ASCII.GetString(data,0,18).StartsWith("Resource File")) throw new InvalidDataException("找不到 RDA 签名。");
        long offset=(long)U64(data,RdaFirstBlockOffset);
        HashSet<long> seen=new HashSet<long>();
        while (offset>0 && offset<data.Length && seen.Add(offset))
        {
            int at=(int)offset;
            uint flags=U32(data,at), count=U32(data,at+4);
            ulong directorySize=U64(data,at+8), directoryRawSize=U64(data,at+16), nextOffset=U64(data,at+24);
            if ((flags&2)!=0) throw new InvalidDataException("不支持加密的 RDA 块。");
            if (directorySize>directoryRawSize || directorySize>(ulong)at) throw new InvalidDataException("RDA 目录长度不合理。");
            byte[] directory;
            if ((flags&1)!=0)
            {
                int consumed;
                directory=InflateZlib(data,at-(int)directorySize,at,out consumed);
            }
            else
            {
                directory=new byte[directorySize];
                Array.Copy(data,at-(int)directorySize,directory,0,(int)directorySize);
            }
            if ((ulong)directory.Length!=directoryRawSize) throw new InvalidDataException("RDA 目录解压长度不一致。");
            for (uint i=0;i<count;i++)
            {
                int entry=checked((int)i*RdaDirectoryEntrySize);
                string name=DecodeUtf16Name(directory,entry,520);
                if (!name.Equals(wantedName,StringComparison.OrdinalIgnoreCase)) continue;
                long fileOffset=(long)U64(directory,entry+520);
                long packedSize=(long)U64(directory,entry+528);
                if (fileOffset<0 || packedSize<0 || fileOffset+packedSize>data.Length)
                    throw new InvalidDataException("RDA 条目超出文件范围。");
                if ((flags&1)!=0)
                {
                    int consumed;
                    return InflateZlib(data,(int)fileOffset,(int)(fileOffset+packedSize),out consumed);
                }
                byte[] blob=new byte[packedSize];
                Array.Copy(data,fileOffset,blob,0,(int)packedSize);
                return blob;
            }
            offset=(long)nextOffset;
        }
        return null;
    }
    // [uint32 count][count x uint16 id][count x null terminated UTF-8 name]
    private static Dictionary<ushort,string> ReadFileDbDictionary(byte[] data,int offset)
    {
        Dictionary<ushort,string> names=new Dictionary<ushort,string>();
        uint count=U32(data,offset);
        if (count>65536 || offset+4+(long)count*2>data.Length) throw new InvalidDataException("FileDB 字典长度不合理。");
        ushort[] identifiers=new ushort[count];
        for (uint i=0;i<count;i++) identifiers[i]=U16(data,offset+4+(int)i*2);
        int position=offset+4+(int)count*2;
        for (uint i=0;i<count;i++)
        {
            int end=position;
            while (end<data.Length && data[end]!=0) end++;
            if (end>=data.Length) throw new InvalidDataException("FileDB 字典字符串未结束。");
            names[identifiers[i]]=Encoding.UTF8.GetString(data,position,end-position);
            position=end+1;
        }
        return names;
    }
    private delegate void FileDbLeaf(List<string> path,string attributeName,byte[] data,int offset,int size);
    // Binary XML walk: opening tags push, id 0 pops, id & 0x8000 is a leaf with content
    // padded to eight bytes. Names come from the trailer dictionaries.
    private static void WalkFileDb(byte[] data,FileDbLeaf leaf)
    {
        if (data.Length<20) throw new InvalidDataException("FileDB 数据太短。");
        int trailer=data.Length-20;
        uint tagOffset=U32(data,trailer+4), attributeOffset=U32(data,trailer+8);
        if (U32(data,trailer+16)!=FileDbMagic) throw new InvalidDataException("找不到 FileDB 签名。");
        if (tagOffset>(uint)data.Length || attributeOffset>(uint)data.Length || tagOffset>trailer)
            throw new InvalidDataException("FileDB 字典偏移不合理。");
        Dictionary<ushort,string> tags=ReadFileDbDictionary(data,(int)tagOffset);
        Dictionary<ushort,string> attributes=ReadFileDbDictionary(data,(int)attributeOffset);
        // Unnamed nodes stay unnamed here: refresh_owned_areas.py treats a tag id that is
        // not in the dictionary as '?' and an unknown attribute id as no name at all.
        List<string> path=new List<string>();
        int bodyEnd=(int)tagOffset;
        long position=0;
        while (position+8<=bodyEnd)
        {
            long size=U32(data,(int)position);
            ushort identifier=U16(data,(int)position+4);
            position+=8;
            if (identifier==0)
            {
                if (path.Count>0) path.RemoveAt(path.Count-1);
                continue;
            }
            if ((identifier&0x8000)!=0)
            {
                string name;
                if (!attributes.TryGetValue(identifier,out name)) name=null;
                leaf(path,name,data,(int)position,(int)size);
                position+=(size+7)&~7L;
                continue;
            }
            string tag;
            if (!tags.TryGetValue(identifier,out tag)) tag="?";
            if (path.Count>=512) throw new InvalidDataException("FileDB 标签嵌套异常。");
            path.Add(tag);
        }
    }
    private static bool PathContains(List<string> path,string name)
    {
        for (int i=0;i<path.Count;i++) if (path[i]==name) return true;
        return false;
    }
    private static bool PathEndsWith(List<string> path,params string[] names)
    {
        if (path.Count<names.Length) return false;
        int start=path.Count-names.Length;
        for (int i=0;i<names.Length;i++) if (path[start+i]!=names[i]) return false;
        return true;
    }
    private static string SaveRoot()
    {
        string overridden=Environment.GetEnvironmentVariable("ANNO_TRAINER_SAVE_ROOT");
        if (!string.IsNullOrEmpty(overridden)) return overridden;
        return Path.Combine(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),"Anno 1800"),"accounts");
    }
    // Mirrors the */*/*.a7s glob of refresh_owned_areas.py: two directory levels below accounts.
    private static bool TryFindNewestSave(out string path,out DateTime writeUtc,out long length)
    {
        path=null;
        writeUtc=DateTime.MinValue;
        length=0;
        string root=SaveRoot();
        if (!Directory.Exists(root)) return false;
        foreach (string account in Directory.GetDirectories(root))
            foreach (string profile in Directory.GetDirectories(account))
                foreach (string file in Directory.GetFiles(profile,"*.a7s"))
                {
                    DateTime write=File.GetLastWriteTimeUtc(file);
                    if (path==null || write>writeUtc)
                    {
                        path=file;
                        writeUtc=write;
                        length=new FileInfo(file).Length;
                    }
                }
        return path!=null;
    }
    private static string FindNewestSave()
    {
        string path;
        DateTime writeUtc;
        long length;
        if (!TryFindNewestSave(out path,out writeUtc,out length))
            throw new InvalidOperationException("在 "+SaveRoot()+" 下找不到 Anno 1800 存档（*.a7s）。");
        return path;
    }
    // Reads one save and returns the AreaIDs owned by human participant 0.
    private static HashSet<uint> ParseOwnedAreas(string path,out string detail)
    {
        byte[] file=File.ReadAllBytes(path);
        byte[] packed=ExtractRdaFile(file,"data.a7s");
        if (packed==null) throw new InvalidDataException("存档容器里找不到 data.a7s。");
        byte[] raw=DecompressStream(packed);
        List<KeyValuePair<ulong,byte[]>> sessions=new List<KeyValuePair<ulong,byte[]>>();
        ulong sessionGuid=0;
        WalkFileDb(raw,delegate(List<string> current,string attributeName,byte[] data,int offset,int size)
        {
            if (attributeName=="SessionGUID" && PathContains(current,"SessionDesc"))
            {
                if (size>0 && size<=8)
                {
                    ulong value=0;
                    for (int i=size-1;i>=0;i--) value=(value<<8)|data[offset+i];
                    sessionGuid=value;
                }
            }
            else if (attributeName=="BinaryData" && PathContains(current,"SessionData"))
            {
                byte[] blob=new byte[size];
                Array.Copy(data,offset,blob,0,size);
                sessions.Add(new KeyValuePair<ulong,byte[]>(sessionGuid,blob));
            }
        });
        Dictionary<uint,int> owners=new Dictionary<uint,int>();
        HashSet<uint> owned=new HashSet<uint>();
        foreach (KeyValuePair<ulong,byte[]> session in sessions)
        {
            Dictionary<uint,int> found=new Dictionary<uint,int>();
            bool hasArea=false;
            uint areaId=0;
            WalkFileDb(session.Value,delegate(List<string> current,string attributeName,byte[] data,int offset,int size)
            {
                if (attributeName==null && size==2 && PathEndsWith(current,"GameSessionManager","AreaInfo"))
                {
                    areaId=U16(data,offset);
                    hasArea=true;
                    if (!found.ContainsKey(areaId)) found[areaId]=-1;
                }
                else if (attributeName=="id" && hasArea && PathEndsWith(current,"GameSessionManager","AreaInfo","?","Owner"))
                {
                    found[areaId]=unchecked((int)U32(data,offset));
                }
            });
            foreach (KeyValuePair<uint,int> entry in found)
            {
                int previous;
                if (owners.TryGetValue(entry.Key,out previous) && previous!=entry.Value)
                    throw new InvalidDataException("Area "+entry.Key+" 在不同会话中的拥有者不一致（"+previous+" 与 "+entry.Value+"）；未更新名单。");
                owners[entry.Key]=entry.Value;
                if (entry.Value==0) owned.Add(entry.Key);
            }
        }
        if (owned.Count==0) throw new InvalidDataException("存档里没有属于玩家 0 的岛屿；未更新名单。");
        detail=sessions.Count+" 个会话、"+owners.Count+" 座岛";
        return owned;
    }
    private static List<uint> SortedAreas(HashSet<uint> areas)
    {
        List<uint> sorted=new List<uint>(areas);
        sorted.Sort();
        return sorted;
    }
    private static void WriteOwnedAreasFile(HashSet<uint> areas,string sourceName)
    {
        string path=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"owned_areas.txt");
        StringBuilder text=new StringBuilder();
        text.Append("# Anno 1800 human participant 0; generated from ").Append(sourceName).Append('\n');
        foreach (uint area in SortedAreas(areas)) text.Append(area).Append('\n');
        string temporary=path+".tmp";
        File.WriteAllText(temporary,text.ToString(),new UTF8Encoding(false));
        try
        {
            if (File.Exists(path)) File.Replace(temporary,path,null);
            else File.Move(temporary,path);
        }
        catch (Exception)
        {
            File.Copy(temporary,path,true);
            File.Delete(temporary);
        }
    }
    private static void RememberSaveState(string path)
    {
        appliedSavePath=path;
        appliedSaveWriteUtc=File.GetLastWriteTimeUtc(path);
        appliedSaveLength=new FileInfo(path).Length;
        lastSeenSavePath=appliedSavePath;
        lastSeenSaveWriteUtc=appliedSaveWriteUtc;
        lastSeenSaveLength=appliedSaveLength;
    }
    private static HashSet<uint> RefreshOwnedAreasFromNewestSave()
    {
        Stopwatch watch=Stopwatch.StartNew();
        string path=FindNewestSave();
        string detail;
        HashSet<uint> areas=ParseOwnedAreas(path,out detail);
        watch.Stop();
        string name=Path.GetFileName(path);
        ownedAreasSaveName=name;
        WriteOwnedAreasFile(areas,name);
        RememberSaveState(path);
        Console.WriteLine("解析最新存档 "+name+"（"+detail+"，"+watch.Elapsed.TotalSeconds.ToString("F1")+" 秒）：本人岛屿 "+
            areas.Count+" 座，已写入 owned_areas.txt。");
        return areas;
    }
    private static HashSet<uint> LoadOwnedAreas()
    {
        string path=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"owned_areas.txt");
        if (!File.Exists(path)) throw new InvalidOperationException("owned_areas.txt 不存在，且自动解析存档未能生成名单；"+
            "请确认存档目录，或运行 Anno1800MemoryTrainer.exe --refresh-areas 后重试。");
        HashSet<uint> result=new HashSet<uint>();
        foreach (string line in File.ReadAllLines(path))
        {
            string clean=line.Split('#')[0].Trim();
            uint id;
            if (uint.TryParse(clean,out id)) result.Add(id);
        }
        if (result.Count==0) throw new InvalidOperationException("No owned island IDs in owned_areas.txt.");
        return result;
    }
    // ------------------------------------------------------------------------------
    // 运行中自动识别新岛。每 3 秒看一次最新存档：文件稳定且与上次解析的不同就交给
    // 后台线程解析，主线程在下一个计时器消息里应用结果并重新扫描仓库。扫描只在名单
    // 真的变化（或有库存锁定时）才做，所以普通自动存档只花一次后台解析的时间。
    // ------------------------------------------------------------------------------
    private static bool TryStartScan(Func<ScanOutput> work)
    {
        if (Interlocked.CompareExchange(ref scanRunning,1,0)!=0) return false;
        Thread thread=new Thread(delegate()
        {
            ScanOutput result;
            try
            {
                result=work();
                if (game!=null && game.HasExited) throw new InvalidOperationException("游戏进程已退出。");
            }
            catch (Exception ex) { result=new ScanOutput {Error=ex.Message}; }
            pendingScan=result;
            Interlocked.Exchange(ref scanRunning,0);
        });
        thread.IsBackground=true;
        thread.Name="Anno1800TrainerScan";
        thread.Start();
        return true;
    }
    private static void StartSaveRefresh(string savePath)
    {
        HashSet<uint> current=ownedAreaIds;
        HashSet<int> wanted=selectedGuids;
        bool needAll=pinEnabled;
        bool started=TryStartScan(delegate()
        {
            string detail;
            HashSet<uint> areas=ParseOwnedAreas(savePath,out detail);
            ScanOutput result=new ScanOutput {Areas=areas,SaveName=Path.GetFileName(savePath),Detail=detail};
            if (!areas.SetEquals(current) || needAll)
            {
                ScanOutput scan=ScanOwnedGoods(areas,wanted,needAll,true,false);
                result.Configured=scan.Configured;
                result.AllGoods=scan.AllGoods;
                result.SeenAreas=scan.SeenAreas;
                result.WantedGuids=wanted;
            }
            return result;
        });
        if (started) RememberSaveState(savePath);
    }
    private static void RequestBackgroundRescan()
    {
        if (scanRunning!=0) return;
        HashSet<uint> areas=ownedAreaIds;
        HashSet<int> wanted=selectedGuids;
        TryStartScan(delegate() { return ScanOwnedGoods(areas,wanted,true,true,false); });
    }
    // A warehouse can gain goods records while the lock runs (a new good type delivered to
    // the island). Re-walking the known list is a few hundred reads, so it needs no scan.
    private static void RefreshPinRecords()
    {
        if (!pinEnabled) return;
        int added=0;
        foreach (PinGroup group in pinGroups)
        {
            if (!ownedAreaIds.Contains(group.AreaId) || !ValidatePinArea(group)) continue;
            byte[] warehouse=ReadBytes(group.WarehouseAddress,0x38);
            if (warehouse==null) continue;
            ulong nodeCount=U64(warehouse,0x30);
            if (nodeCount<20 || nodeCount>1000) continue;
            byte[] head=ReadBytes(group.HeadAddress,0x28);
            if (head==null || U64(head,0)==0) continue;
            HashSet<ulong> known=new HashSet<ulong>();
            foreach (GoodTarget target in group.Targets) known.Add(target.Address);
            HashSet<ulong> visited=new HashSet<ulong>();
            ulong current=U64(head,0), previous=group.HeadAddress;
            for (int node=0;node<(int)nodeCount && current!=group.HeadAddress && current!=0 && visited.Add(current);node++)
            {
                byte[] record=ReadBytes(current,0x28);
                if (record==null || U64(record,8)!=previous) break;
                if (!known.Contains(current))
                {
                    int guid=unchecked((int)U32(record,0x18));
                    uint capacity=U32(record,0x1C), count=U32(record,0x20);
                    if (guid>0 && IsGoodsRecord(record) &&
                        capacity>=PinCapacityFloor && capacity<=PinCapacityCeiling && count<=capacity)
                    {
                        group.Targets.Add(new GoodTarget {Address=current,HeadAddress=group.HeadAddress,
                            ParentAddress=group.WarehouseAddress,EntityAddress=group.EntityAddress,
                            Guid=guid,AreaId=group.AreaId,Capacity=capacity,Count=count});
                        pinRecordCount++;
                        added++;
                    }
                }
                previous=current;
                current=U64(record,0);
            }
        }
        if (added>0)
            Console.WriteLine("库存锁定：新发现 "+added+" 条物资记录（共 "+pinRecordCount+" 条），已纳入锁定。");
    }
    private static void CheckNewestSave()
    {
        string path;
        DateTime writeUtc;
        long length;
        if (!TryFindNewestSave(out path,out writeUtc,out length)) return;
        if (path==lastSeenSavePath && writeUtc==lastSeenSaveWriteUtc && length==lastSeenSaveLength)
        {
            if (path==appliedSavePath && writeUtc==appliedSaveWriteUtc && length==appliedSaveLength) return;
            if ((DateTime.UtcNow-writeUtc).TotalSeconds<2) return;
            StartSaveRefresh(path);
            return;
        }
        lastSeenSavePath=path;
        lastSeenSaveWriteUtc=writeUtc;
        lastSeenSaveLength=length;
    }
    private static void NoteNewUnknownAreas(HashSet<uint> seen)
    {
        if (seen==null || seen.Count==0) return;
        List<uint> fresh=new List<uint>();
        foreach (uint area in seen)
            if (!ownedAreaIds.Contains(area) && !baselineUnknownAreas.Contains(area) && !reportedUnknownAreas.Contains(area))
                fresh.Add(area);
        if (fresh.Count==0) return;
        fresh.Sort();
        foreach (uint area in fresh) reportedUnknownAreas.Add(area);
        Console.WriteLine("提示：内存中新出现未列入名单的岛屿 Area "+string.Join(",",fresh)+
            "（可能是 AI 的岛，也可能是你刚占领、还没存档的新岛）。若是你的新岛，在游戏里保存一次即可自动加入，无需重启修改器。");
    }
    private static void ApplyPendingScan()
    {
        ScanOutput scan=pendingScan;
        if (scan==null) return;
        pendingScan=null;
        if (scan.Error!=null)
        {
            Console.WriteLine("自动刷新存档失败："+scan.Error+"。继续使用当前岛屿名单（"+ownedAreaIds.Count+" 座）；下次存档变化时会重试。");
            return;
        }
        List<uint> added=new List<uint>(), removed=new List<uint>();
        foreach (uint area in scan.Areas) if (!ownedAreaIds.Contains(area)) added.Add(area);
        foreach (uint area in ownedAreaIds) if (!scan.Areas.Contains(area)) removed.Add(area);
        added.Sort();
        removed.Sort();
        bool moved=added.Count>0 || removed.Count>0;
        if (moved)
        {
            ownedAreaIds=scan.Areas;
            WriteOwnedAreasFile(scan.Areas,scan.SaveName);
        }
        if (scan.Configured!=null)
        {
            if (scan.WantedGuids!=null && !scan.WantedGuids.SetEquals(selectedGuids))
                Console.WriteLine("已丢弃一次过期的仓库定位（hotkeys.txt 期间有改动）。");
            else if (scan.ConfiguredCount==0 && stockTargets!=null && CountTargets(stockTargets)>0)
                Console.WriteLine("自动刷新没有定位到任何物资记录（扫描可能被中断）；保留原定位，下次存档变化时重试。");
            else stockTargets=scan.Configured;
        }
        if (scan.AllGoods!=null && scan.AllGoods.Count>0)
        {
            pinCandidates=scan.AllGoods;
            // New islands must join the running lock immediately, so rebuild its groups.
            if (pinEnabled) BuildPinGroups(pinCandidates);
        }
        if (moved)
        {
            if (added.Count>0)
                Console.WriteLine("自动识别到新岛 Area "+string.Join(",",added)+"：已加入名单，物资快捷键和库存锁定立即对它们生效。");
            if (removed.Count>0)
                Console.WriteLine("存档显示 Area "+string.Join(",",removed)+" 已不再属于你：已从名单移除，不会再有写入。");
            Console.WriteLine("当前本人岛屿 "+scan.Areas.Count+" 座（来自 "+scan.SaveName+"）。");
        }
        NoteNewUnknownAreas(scan.SeenAreas);
    }
    private static int CountTargets(Dictionary<int,List<GoodTarget>> targets)
    {
        int total=0;
        if (targets!=null) foreach (List<GoodTarget> list in targets.Values) total+=list.Count;
        return total;
    }
    // Slots 0-9 are Ctrl+digit, 10-19 Ctrl+Shift+digit,
    // 20-29 Ctrl+Alt+digit, and 30-39 Ctrl+Shift+Alt+digit.
    private static string HotkeyLabel(int slot)
    {
        int group=slot/10;
        return "Ctrl+"+(group==1 || group==3 ? "Shift+" : "")+
            (group==2 || group==3 ? "Alt+" : "")+(slot%10);
    }
    private static uint HotkeyModifiers(int slot)
    {
        int group=slot/10;
        return 0x0002U | 0x4000U | (group==1 || group==3 ? 0x0004U : 0U) |
            (group==2 || group==3 ? 0x0001U : 0U);
    }
    private static int ParseHotkeySlot(string label)
    {
        int digit;
        if (int.TryParse(label.Trim(),out digit))
            return digit>=0 && digit<=9 ? digit : -1;
        string[] parts=label.Split('+');
        if (parts.Length<2 || !int.TryParse(parts[parts.Length-1].Trim(),out digit) || digit<0 || digit>9)
            return -1;
        bool control=false,shift=false,alt=false;
        for (int i=0;i<parts.Length-1;i++)
        {
            string modifier=parts[i].Trim();
            if (modifier.Equals("Ctrl",StringComparison.OrdinalIgnoreCase) ||
                modifier.Equals("Control",StringComparison.OrdinalIgnoreCase))
            { if (control) return -1; control=true; }
            else if (modifier.Equals("Shift",StringComparison.OrdinalIgnoreCase))
            { if (shift) return -1; shift=true; }
            else if (modifier.Equals("Alt",StringComparison.OrdinalIgnoreCase))
            { if (alt) return -1; alt=true; }
            else return -1;
        }
        if (!control) return -1;
        return digit+(shift ? 10 : 0)+(alt ? 20 : 0);
    }
    private static HotkeyConfiguration ParseHotkeys(string content)
    {
        HotkeyConfiguration configuration=new HotkeyConfiguration();
        foreach (string raw in content.Split(new[]{'\r','\n'},StringSplitOptions.RemoveEmptyEntries))
        {
            string line=raw.TrimStart('\uFEFF').Split('#')[0].Trim();
            if (line.Length==0) continue;
            string[] pair=line.Split(new[]{'='},2);
            int slot=pair.Length==2 ? ParseHotkeySlot(pair[0]) : -1;
            if (slot<0 || configuration.Map.ContainsKey(slot))
                throw new InvalidOperationException("Invalid or duplicate hotkey: "+raw);
            string value=pair[1].Trim();
            if (slot==1)
            {
                if (!value.Equals("ship",StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Ctrl+1 is reserved for ship construction.");
                configuration.Map.Add(1,new HotkeyAssignment {Slot=1,Guid=0,Name="Ship construction"});
                continue;
            }
            string[] fields=value.Split('|');
            if (fields.Length>3) throw new InvalidOperationException("Too many '|' fields: "+raw);
            int guid;
            if (!int.TryParse(fields[0].Trim(),out guid) || guid<=0 || !configuration.Guids.Add(guid))
                throw new InvalidOperationException("Invalid or duplicate goods GUID: "+raw);
            string name=fields.Length>=2 ? fields[1].Trim() : "";
            bool toggleZero=false;
            if (fields.Length==3)
            {
                string flag=fields[2].Trim();
                if (flag.Equals("toggle",StringComparison.OrdinalIgnoreCase) || flag=="切换" || flag=="反向")
                    toggleZero=true;
                else throw new InvalidOperationException("Unknown hotkey flag '"+flag+"' (only |toggle is supported): "+raw);
            }
            configuration.Map.Add(slot,new HotkeyAssignment {Slot=slot,Guid=guid,
                Name=name.Length>0?name:"GUID "+guid,ToggleZero=toggleZero});
        }
        if (!configuration.Map.ContainsKey(1) || configuration.Guids.Count==0)
            throw new InvalidOperationException("hotkeys.txt must contain 1=ship and at least one goods key.");
        return configuration;
    }
    private static void LoadHotkeys()
    {
        string path=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"hotkeys.txt");
        if (!File.Exists(path)) throw new InvalidOperationException("hotkeys.txt is missing.");
        string content=File.ReadAllText(path,Encoding.UTF8);
        HotkeyConfiguration configuration=ParseHotkeys(content);
        hotkeys=configuration.Map;
        selectedGuids=configuration.Guids;
        loadedHotkeysText=content;
    }
    private static List<int> RegisterSlot(int slot)
    {
        List<int> added=new List<int>();
        for (int variant=0;variant<2;variant++)
        {
            int id=100+slot*2+variant;
            uint key=(uint)((variant==0 ? 0x30 : 0x60)+(slot%10));
            if (!RegisterHotKey(IntPtr.Zero,id,HotkeyModifiers(slot),key))
            {
                int error=Marshal.GetLastWin32Error();
                Console.WriteLine("无法注册 "+HotkeyLabel(slot)+(variant==0 ? " 主键盘" : " 小键盘")+
                    "（错误码="+error+"）；该按键变体不可用。");
                continue;
            }
            added.Add(id);
        }
        if (added.Count==0) Console.WriteLine(HotkeyLabel(slot)+" 的主键盘和小键盘组合均被占用；该快捷键暂不可用。");
        return added;
    }
    private static void TryReloadHotkeys(List<int> registered)
    {
        string content;
        try
        {
            string path=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"hotkeys.txt");
            content=File.ReadAllText(path,Encoding.UTF8);
        }
        catch (Exception ex)
        {
            Console.WriteLine("读取 hotkeys.txt 失败，将保持旧键位："+ex.Message);
            return;
        }
        if (content==loadedHotkeysText || content==rejectedHotkeysText) return;
        List<int> added=new List<int>();
        try
        {
            HotkeyConfiguration next=ParseHotkeys(content);
            Dictionary<int,List<GoodTarget>> nextTargets=stockTargets;
            if (!next.Guids.SetEquals(selectedGuids))
            {
                Console.WriteLine("hotkeys.txt 已改变，正在更新物资定位...");
                ScanOutput rescan=ScanOwnedGoods(ownedAreaIds,next.Guids,pinEnabled,false,false);
                nextTargets=rescan.Configured;
                if (pinEnabled && rescan.AllGoods!=null && rescan.AllGoods.Count>0)
                {
                    pinCandidates=rescan.AllGoods;
                    BuildPinGroups(pinCandidates);
                }
            }
            foreach (int slot in next.Map.Keys)
                if (!hotkeys.ContainsKey(slot)) added.AddRange(RegisterSlot(slot));
            foreach (int slot in hotkeys.Keys)
                if (!next.Map.ContainsKey(slot))
                    for (int variant=0;variant<2;variant++)
                    {
                        int id=100+slot*2+variant;
                        if (registered.Remove(id)) UnregisterHotKey(IntPtr.Zero,id);
                    }
            registered.AddRange(added);
            hotkeys=next.Map;
            selectedGuids=next.Guids;
            stockTargets=nextTargets;
            loadedHotkeysText=content;
            rejectedHotkeysText=null;
            Console.WriteLine("hotkeys.txt 热更新成功：");
            foreach (HotkeyAssignment assignment in hotkeys.Values)
                Console.WriteLine("  "+HotkeyLabel(assignment.Slot)+" = "+assignment.Name);
        }
        catch (Exception ex)
        {
            foreach (int id in added) UnregisterHotKey(IntPtr.Zero,id);
            rejectedHotkeysText=content;
            Console.WriteLine("hotkeys.txt 更新失败，原键位继续有效："+ex.Message);
        }
    }
    private static int FindShipFileOffset(string path)
    {
        int count=0, offset=-1;
        byte[] data=File.ReadAllBytes(path);
        for (int i=0; i<=data.Length-ShipSignature.Length; i++)
        {
            if (data[i]!=ShipSignature[0]) continue;
            bool match=true;
            for (int j=1; j<ShipSignature.Length; j++) if (data[i+j]!=ShipSignature[j]) {match=false;break;}
            if (match) {count++;offset=i;}
        }
        if (count!=1) throw new InvalidOperationException("Ship timer signature count="+count+"; refusing patch.");
        int pe=BitConverter.ToInt32(data,0x3C);
        int sections=BitConverter.ToUInt16(data,pe+6);
        int sectionTable=pe+24+BitConverter.ToUInt16(data,pe+20);
        for (int i=0; i<sections; i++)
        {
            int s=sectionTable+i*40;
            uint virtualAddress=U32(data,s+12), rawSize=U32(data,s+16), rawAddress=U32(data,s+20);
            if (offset>=rawAddress && offset<(long)rawAddress+rawSize) return checked((int)(virtualAddress+offset-rawAddress));
        }
        throw new InvalidOperationException("Could not convert ship signature file offset to RVA.");
    }
    private static bool TryIdentifyOurShipPatch(byte[] current,out ulong caveAddress)
    {
        caveAddress=0;
        if (current==null || current.Length!=ShipSignature.Length || current[0]!=0xE9) return false;
        for (int i=5;i<ShipSignature.Length;i++) if (current[i]!=ShipSignature[i]) return false;
        long destination=checked((long)shipPatchAddress+5+BitConverter.ToInt32(current,1));
        if (destination<0x10000 || destination>=0x00007FFFFFF00000L) return false;
        ulong candidate=(ulong)destination;
        MemoryBasicInformation info;
        if (VirtualQueryEx(processHandle,Ptr(candidate),out info,Ptr((ulong)Marshal.SizeOf(typeof(MemoryBasicInformation))))==0 ||
            info.State!=MemCommit || info.Type!=MemPrivate || candidate<info.BaseAddress ||
            candidate+13>info.BaseAddress+info.RegionSize) return false;
        uint protection=info.Protect&0xFF;
        if (protection!=PageExecuteReadWrite && protection!=PageExecuteWriteCopy) return false;
        byte[] code=ReadBytes(candidate,13);
        byte[] expectedBody={0x0F,0x57,0xC0,0xF3,0x0F,0x11,0x47,0x14};
        if (code==null) return false;
        for (int i=0;i<expectedBody.Length;i++) if (code[i]!=expectedBody[i]) return false;
        byte[] back=RelativeJump(candidate+8,shipPatchAddress+5);
        for (int i=0;i<back.Length;i++) if (code[i+8]!=back[i]) return false;
        caveAddress=candidate;
        return true;
    }
    private static void Attach(bool dryRun)
    {
        Process[] games=Process.GetProcessesByName("Anno1800");
        if (games.Length!=1) throw new InvalidOperationException("Expected exactly one running Anno1800.exe; found "+games.Length);
        game=games[0];
        string path=game.MainModule.FileName;
        using (SHA256 sha=SHA256.Create()) using (FileStream file=File.OpenRead(path))
        {
            string hash=BitConverter.ToString(sha.ComputeHash(file)).Replace("-","");
            if (!hash.Equals(ExpectedExeSha256,StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Game executable SHA256 differs from verified 18.4 build; refusing memory writes. Found "+hash);
        }
        moduleBase=(ulong)game.MainModule.BaseAddress.ToInt64();
        moduleSize=(ulong)game.MainModule.ModuleMemorySize;
        processHandle=OpenProcess(ProcessAccess,false,game.Id);
        if (processHandle==IntPtr.Zero) throw new InvalidOperationException("OpenProcess failed "+Marshal.GetLastWin32Error()+". Run as administrator.");
        int rva=FindShipFileOffset(path);
        shipPatchAddress=moduleBase+(uint)rva;
        byte[] current=ReadBytes(shipPatchAddress,ShipSignature.Length);
        if (current==null || !Equal(current,ShipSignature))
        {
            ulong previousCave;
            if (TryIdentifyOurShipPatch(current,out previousCave))
            {
                Console.WriteLine("识别到本修改器旧版留下的造船补丁，代码缓存 0x"+previousCave.ToString("X")+"。");
                if (!dryRun)
                {
                    shipCaveAddress=previousCave;
                    shipEnabled=true;
                    Console.WriteLine("已接管该补丁；Ctrl+1 已生效，Ctrl+F12 可恢复原始指令。");
                }
            }
            else
            {
                if (!dryRun) throw new InvalidOperationException("当前造船指令被未知代码修改，无法安全接管。请关闭其他修改器并重启游戏。");
                Console.WriteLine("Read-only mode: ship timer has an unknown patch; no memory will be changed.");
            }
        }
        Console.WriteLine("Attached Anno1800 PID="+game.Id+"; verified 18.4 executable.");
    }
    private static void RefuseOtherTrainers()
    {
        int self=Process.GetCurrentProcess().Id;
        foreach (Process other in Process.GetProcessesByName("Anno1800MemoryTrainer"))
        {
            if (other.Id!=self)
                throw new InvalidOperationException("另一个 Anno1800MemoryTrainer.exe（PID "+other.Id+"）仍在运行。请先关闭旧修改器窗口，再运行本版。");
        }
    }
    private static bool Equal(byte[] a, byte[] b)
    {
        if (a==null || a.Length!=b.Length) return false;
        for(int i=0;i<a.Length;i++) if(a[i]!=b[i]) return false;
        return true;
    }
    private static bool KeyDown(uint virtualKey)
    {
        return (GetAsyncKeyState((int)virtualKey)&0x8000)!=0;
    }
    private static bool GameIsForeground()
    {
        uint foregroundPid;
        IntPtr window=GetForegroundWindow();
        return window!=IntPtr.Zero && GetWindowThreadProcessId(window,out foregroundPid)!=0 && foregroundPid==(uint)game.Id;
    }
    private static ulong AllocateNear(ulong address)
    {
        for (ulong delta=0x10000;delta<0x70000000;delta+=0x10000)
        {
            ulong candidate=(address+delta)&~0xFFFFUL;
            IntPtr cave=VirtualAllocEx(processHandle,Ptr(candidate),Ptr(0x1000),MemCommit|MemReserve,PageExecuteReadWrite);
            if (cave!=IntPtr.Zero) return (ulong)cave.ToInt64();
            if (address>delta)
            {
                candidate=(address-delta)&~0xFFFFUL;
                cave=VirtualAllocEx(processHandle,Ptr(candidate),Ptr(0x1000),MemCommit|MemReserve,PageExecuteReadWrite);
                if (cave!=IntPtr.Zero) return (ulong)cave.ToInt64();
            }
        }
        throw new InvalidOperationException("Could not allocate a code cave within 2 GB of ship timer.");
    }
    private static byte[] RelativeJump(ulong from, ulong to)
    {
        long distance=unchecked((long)to-(long)(from+5));
        if (distance<int.MinValue || distance>int.MaxValue) throw new InvalidOperationException("Code cave is outside rel32 jump range.");
        byte[] result=new byte[5]; result[0]=0xE9;
        Array.Copy(BitConverter.GetBytes((int)distance),0,result,1,4);
        return result;
    }
    private static void PatchCode(ulong address, byte[] bytes)
    {
        uint old;
        if (!VirtualProtectEx(processHandle,Ptr(address),Ptr((ulong)bytes.Length),PageExecuteReadWrite,out old))
            throw new InvalidOperationException("VirtualProtectEx failed: "+Marshal.GetLastWin32Error());
        try { Write(address,bytes); FlushInstructionCache(processHandle,Ptr(address),Ptr((ulong)bytes.Length)); }
        finally { uint ignored; VirtualProtectEx(processHandle,Ptr(address),Ptr((ulong)bytes.Length),old,out ignored); }
    }
    private static void EnableShips()
    {
        if (shipEnabled) { Console.WriteLine("Ship one-second mode is already enabled."); return; }
        if (!Equal(ReadBytes(shipPatchAddress,ShipSignature.Length),ShipSignature))
            throw new InvalidOperationException("Ship timer code changed; refusing patch.");
        ulong cave=AllocateNear(shipPatchAddress);
        try
        {
            byte[] code=new byte[13];
            byte[] body={0x0F,0x57,0xC0,0xF3,0x0F,0x11,0x47,0x14};
            Array.Copy(body,code,body.Length);
            Array.Copy(RelativeJump(cave+8,shipPatchAddress+5),0,code,8,5);
            Write(cave,code);
            FlushInstructionCache(processHandle,Ptr(cave),Ptr((ulong)code.Length));
            PatchCode(shipPatchAddress,RelativeJump(shipPatchAddress,cave));
            shipCaveAddress=cave;
            shipEnabled=true;
            Console.WriteLine("Ship timer patched; future ship orders complete on the next update tick (about one second).");
        }
        catch { VirtualFreeEx(processHandle,Ptr(cave),IntPtr.Zero,MemRelease); throw; }
    }
    private static bool RestoreShips()
    {
        if (!shipEnabled) return true;
        if (processHandle==IntPtr.Zero || game==null || game.HasExited)
        {
            Console.WriteLine("无法恢复造船代码：游戏进程已退出。");
            return false;
        }
        try
        {
            if (!Equal(ReadBytes(shipPatchAddress,5),RelativeJump(shipPatchAddress,shipCaveAddress)))
                throw new InvalidOperationException("造船代码已被其他程序改动，未覆盖未知指令。");
            PatchCode(shipPatchAddress,ShipOriginal);
            Thread.Sleep(100);
            if (!Equal(ReadBytes(shipPatchAddress,5),ShipOriginal))
                throw new InvalidOperationException("原始造船指令写入后又发生变化，未释放代码缓存。");
            if (!VirtualFreeEx(processHandle,Ptr(shipCaveAddress),IntPtr.Zero,MemRelease))
                Console.WriteLine("造船原指令已恢复，但代码缓存释放失败；退出游戏后会释放。");
            shipEnabled=false;
            Console.WriteLine("造船计时代码已恢复。");
            return true;
        }
        catch (Exception ex) { Console.WriteLine("无法恢复造船代码："+ex.Message); return false; }
    }
    private static string GoodName(int guid)
    {
        foreach (HotkeyAssignment hotkey in hotkeys.Values)
            if (hotkey.Guid==guid) return hotkey.Name;
        return "GUID "+guid;
    }
    private static bool ValidateTarget(GoodTarget target)
    {
        byte[] entity=ReadBytes(target.EntityAddress,0x68);
        byte[] link=ReadBytes(target.EntityAddress+0x180,8);
        byte[] warehouse=ReadBytes(target.ParentAddress,0x38);
        byte[] record=ReadBytes(target.Address,0x28);
        return entity!=null && link!=null && warehouse!=null && record!=null &&
            U16(entity,0x64)==target.AreaId &&
            U64(entity,8)==moduleBase+AreaWarehouseEntityVtableRva &&
            U64(link,0)==target.ParentAddress &&
            U64(warehouse,0)==moduleBase+WarehouseVtableRva &&
            U64(warehouse,0x28)==target.HeadAddress &&
            U64(warehouse,0x30)>=20 && U64(warehouse,0x30)<=1000 &&
            U32(record,0x18)==(uint)target.Guid && IsGoodsRecord(record) &&
            IsLinkedToHead(target.Address,target.HeadAddress);
    }
    private static uint FillGoodToCapacity(GoodTarget target)
    {
        if (!ValidateTarget(target)) throw new InvalidOperationException(GoodName(target.Guid)+" ownership link changed; restart the trainer.");
        byte[] current=ReadBytes(target.Address+0x1C,8);
        if (current==null) throw new InvalidOperationException("Could not read "+GoodName(target.Guid)+" stock.");
        uint capacity=U32(current,0);
        if (capacity<1 || capacity>100000) throw new InvalidOperationException("Invalid capacity for "+GoodName(target.Guid)+": "+capacity);
        uint count=U32(current,4);
        if (count!=capacity)
        {
            RecordStockChange(target,count);
            Write(target.Address+0x20,BitConverter.GetBytes(capacity));
        }
        return capacity;
    }
    // The first value seen at an address is the one Ctrl+F12 restores; the stock lock keeps
    // refilling the same address, so later writes must not overwrite that record.
    private static void RecordStockChange(GoodTarget target,uint count)
    {
        StockChange previous;
        if (!stockChanges.TryGetValue(target.Address,out previous))
        {
            previous=new StockChange { Target=target, OriginalCount=count };
            stockChanges.Add(target.Address,previous);
            stockChangeOrder.Add(previous);
        }
        else if (previous.Target.Guid!=target.Guid || previous.Target.AreaId!=target.AreaId)
            throw new InvalidOperationException("库存地址已被其他物资复用，拒绝继续写入。");
    }
    private static uint ClearGoodToZero(GoodTarget target)
    {
        byte[] current=ReadBytes(target.Address+0x1C,8);
        if (current==null) throw new InvalidOperationException("Could not read "+GoodName(target.Guid)+" stock.");
        uint capacity=U32(current,0);
        if (capacity<1 || capacity>100000) throw new InvalidOperationException("Invalid capacity for "+GoodName(target.Guid)+": "+capacity);
        uint count=U32(current,4);
        if (count!=0)
        {
            RecordStockChange(target,count);
            Write(target.Address+0x20,BitConverter.GetBytes(0u));
        }
        return capacity;
    }
    private static byte[] InfluenceValues(int total,int available)
    {
        byte[] values=new byte[8];
        Array.Copy(BitConverter.GetBytes(total),0,values,0,4);
        Array.Copy(BitConverter.GetBytes(available),0,values,4,4);
        return values;
    }
    private static void WriteInfluencePair(ulong address,byte[] desired,byte[] before)
    {
        try
        {
            Write(address,desired);
            if (!Equal(ReadBytes(address,8),desired))
                throw new InvalidOperationException("写入后读回校验失败。");
        }
        catch (Exception ex)
        {
            try
            {
                Write(address,before);
                if (!Equal(ReadBytes(address,8),before))
                    throw new InvalidOperationException("恢复写前值后读回校验失败。");
            }
            catch (Exception recoveryError)
            {
                influenceWriteUncertain=true;
                throw new InvalidOperationException("影响力写入失败且写前值未能确认恢复；停止继续加点。"+
                    "请勿保存并重启游戏。原错误："+ex.Message+"；恢复错误："+recoveryError.Message);
            }
            throw new InvalidOperationException("影响力写入失败，已恢复写前值："+ex.Message);
        }
    }
    private static InfluenceTarget ValidateInfluenceTarget()
    {
        if (influenceWriteUncertain)
            throw new InvalidOperationException("先前影响力写入状态未确认，拒绝继续操作；请勿保存并重启游戏。");
        if (influenceTarget==null)
            throw new InvalidOperationException("无法唯一定位玩家影响力记录（候选 "+influenceCandidateCount+" 条）；没有写入。请重新载入存档并启动修改器。");
        InfluenceTarget current=ReadInfluenceObject(influenceTarget.ObjectAddress);
        if (current==null || current.HeadAddress!=influenceTarget.HeadAddress ||
            current.Address!=influenceTarget.Address || current.CoinAddress!=influenceTarget.CoinAddress || current.Total<=0)
            throw new InvalidOperationException("玩家影响力资源表已变化；没有写入。请重启修改器。");
        byte[] values=ReadBytes(current.Address+0x1C,8);
        if (values==null || unchecked((int)U32(values,0))!=current.Total ||
            unchecked((int)U32(values,4))!=current.Available)
            throw new InvalidOperationException("影响力数值在校验时发生变化；没有写入，请重试。");
        return current;
    }
    // A separate light-weight pass that only looks for the player resources table, used when
    // the start-up attempt ran before the game had finished loading a save.
    private static void RequestInfluenceScan()
    {
        if (Interlocked.CompareExchange(ref influenceScanRunning,1,0)!=0) return;
        Thread thread=new Thread(delegate()
        {
            List<InfluenceTarget> found=new List<InfluenceTarget>();
            try
            {
                ulong vtable=moduleBase+PlayerResourcesVtableRva;
                ScanPrivate(delegate(ulong start,byte[] data,int length)
                {
                    for (int i=0;i<=length-8;i+=8)
                    {
                        if (data[i]!=(byte)vtable || U64(data,i)!=vtable) continue;
                        InfluenceTarget candidate=ReadInfluenceObject(start+(uint)i);
                        if (candidate!=null && candidate.Total>0) found.Add(candidate);
                    }
                });
            }
            catch (Exception) { found.Clear(); }
            pendingInfluence=found;
            Interlocked.Exchange(ref influenceScanRunning,0);
        });
        thread.IsBackground=true;
        thread.Name="Anno1800TrainerInfluence";
        thread.Start();
    }
    private static void ApplyInfluenceScan()
    {
        List<InfluenceTarget> found=pendingInfluence;
        if (found==null) return;
        pendingInfluence=null;
        influenceCandidateCount=found.Count;
        if (influenceCandidateCount==1 && (influenceTarget==null || influenceTarget.ObjectAddress!=found[0].ObjectAddress))
        {
            influenceTarget=found[0];
            influenceRetrySeconds=3;
            Console.WriteLine("Ctrl+- 影响力已就绪：当前总量 "+influenceTarget.Total+"、可用 "+influenceTarget.Available+
                "；玩家资源表 0x"+influenceTarget.ObjectAddress.ToString("X")+"。");
            Console.Beep(900,80);
            return;
        }
        if (influenceCandidateCount==1) { influenceTarget=found[0]; influenceRetrySeconds=3; return; }
        influenceTarget=null;
        Console.WriteLine("影响力重新定位未成功（候选 "+influenceCandidateCount+" 条）；"+
            (influenceCandidateCount==0 ? "游戏可能还没载入存档，" : "")+"约 "+influenceRetrySeconds+" 秒后自动重试。");
    }
    private static void AddInfluence()
    {
        if (influenceTarget==null)
        {
            RequestInfluenceScan();
            throw new InvalidOperationException("影响力资源表还没定位好，已在后台重新扫描（约 10 秒）；请稍后再按一次 Ctrl+-。");
        }
        InfluenceTarget current=ValidateInfluenceTarget();
        if (influenceGrant>0 && current.Total<influenceLastWrittenTotal)
            throw new InvalidOperationException("影响力总量比上次写入后下降，可能已切换存档；拒绝继续增加。");
        int nextTotal=checked(current.Total+100);
        int nextAvailable=checked(current.Available+100);
        byte[] original=InfluenceValues(current.Total,current.Available);
        byte[] next=InfluenceValues(nextTotal,nextAvailable);
        WriteInfluencePair(current.Address+0x1C,next,original);
        if (influenceGrant==0)
        {
            influenceOriginalTotal=current.Total;
            influenceOriginalAvailable=current.Available;
        }
        influenceGrant=checked(influenceGrant+100);
        influenceLastWrittenTotal=nextTotal;
        Console.WriteLine("影响力 +100：总量 "+current.Total+" -> "+nextTotal+"，可用 "+current.Available+" -> "+nextAvailable+"；本次累计 +"+influenceGrant+"。");
    }
    private static bool RestoreInfluence(out string result)
    {
        if (influenceWriteUncertain)
        {
            result="  影响力恢复失败：先前写入状态未确认，可能残留本次加点或部分写入；请勿保存并重启游戏。";
            Console.WriteLine(result);
            return false;
        }
        if (influenceGrant==0) { result="  影响力：本次未修改。"; return true; }
        try
        {
            if (game==null || game.HasExited) throw new InvalidOperationException("游戏进程已退出。");
            InfluenceTarget current=ValidateInfluenceTarget();
            if (current.Total<influenceLastWrittenTotal)
                throw new InvalidOperationException("当前总量低于上次写入后总量，可能已切换存档或游戏重算；拒绝盲目扣回。");
            int grant=checked((int)influenceGrant);
            int restoredTotal=checked(current.Total-grant);
            int restoredAvailable=checked(current.Available-grant);
            if (restoredTotal<0) throw new InvalidOperationException("扣回后总量将为负；拒绝写入。");
            byte[] expected=InfluenceValues(restoredTotal,restoredAvailable);
            WriteInfluencePair(current.Address+0x1C,expected,InfluenceValues(current.Total,current.Available));
            result="  影响力：扣回本次累计 +"+grant+"；总量 "+current.Total+" -> "+restoredTotal+
                "，可用 "+current.Available+" -> "+restoredAvailable+
                "（首次修改前为 "+influenceOriginalTotal+" / "+influenceOriginalAvailable+"）。";
            influenceGrant=0;
            Console.WriteLine(result);
            return true;
        }
        catch (Exception ex)
        {
            result="  影响力恢复失败："+ex.Message;
            Console.WriteLine(result);
            return false;
        }
    }
    // ------------------------------------------------------------------------------
    // Ctrl+Alt+- 库存锁定：把每座本人岛屿仓库里的全部物资按住上限持续补满。
    // 每次写入前都重新核对岛屿实体/仓库链和物资记录本身，名单外的岛一律不写。
    // 再按一次只停止锁定，库存保持拉满；Ctrl+F12 才会连同锁定一起还原到修改前。
    // ------------------------------------------------------------------------------
    private static void ActivatePinHotkey(bool readOnly)
    {
        if (game.HasExited || !GameIsForeground()) return;
        try
        {
            TogglePinAll(readOnly);
            Console.Beep(readOnly ? 700 : (pinEnabled ? 900 : 600),120);
        }
        catch (Exception ex) { Console.WriteLine("Ctrl+Alt+- failed: "+ex.Message); Console.Beep(300,200); }
    }
    private static void TogglePinAll(bool readOnly)
    {
        if (readOnly)
        {
            Console.WriteLine("READ ONLY: Ctrl+Alt+- would "+(pinEnabled ? "stop" : "start")+
                " holding every warehouse good of your islands at its capacity.");
            return;
        }
        if (pinEnabled) StopPinAll("再按一次关闭"); else StartPinAll();
    }
    private static void StartPinAll()
    {
        int dropped=BuildPinGroups(pinCandidates);
        if (pinRecordCount==0)
        {
            Console.WriteLine("缓存的仓库记录已失效，正在重新扫描各岛仓库（约 6 秒）...");
            ScanOutput scan=ScanOwnedGoods(ownedAreaIds,selectedGuids,true,true,false);
            if (scan.Configured!=null && scan.ConfiguredCount>0) stockTargets=scan.Configured;
            pinCandidates=scan.AllGoods!=null ? scan.AllGoods : new List<GoodTarget>();
            NoteNewUnknownAreas(scan.SeenAreas);
            dropped=BuildPinGroups(pinCandidates);
        }
        if (pinRecordCount==0)
            throw new InvalidOperationException("没有找到可锁定的仓库物资记录；未开启锁定。请确认已载入存档并重启修改器。");
        pinEnabled=true;
        pinReportUtc=DateTime.MinValue;
        nextPinTickUtc=DateTime.UtcNow;
        nextPinRescanUtc=DateTime.UtcNow.AddSeconds(PinRecordRefreshSeconds);
        ResetPollTimer();
        HashSet<int> guids=new HashSet<int>();
        HashSet<uint> areas=new HashSet<uint>();
        foreach (PinGroup group in pinGroups)
        {
            areas.Add(group.AreaId);
            foreach (GoodTarget target in group.Targets) guids.Add(target.Guid);
        }
        Console.WriteLine("全部物资锁定已开启："+pinRecordCount+" 条仓库记录、"+guids.Count+" 种物资、"+areas.Count+
            " 座岛，按各岛上限持续补满"+(dropped>0 ? "（"+dropped+" 条记录校验失败已跳过）" : "")+"。");
        Console.WriteLine("  再按 Ctrl+Alt+- 只停止锁定，库存保持拉满；Ctrl+F12 会连同锁定一起还原到修改前。");
        PinTick();
    }
    private static void EndPin()
    {
        if (!pinEnabled) return;
        pinEnabled=false;
        ResetPollTimer();
    }
    private static void StopPinAll(string reason)
    {
        if (!pinEnabled) return;
        EndPin();
        Console.WriteLine("全部物资锁定已停止（"+reason+"）：库存保持当前拉满数值；需要还原到修改前请按 Ctrl+F12。");
    }
    private static int BuildPinGroups(List<GoodTarget> targets)
    {
        pinGroups.Clear();
        pinRecordCount=0;
        pinRecoverAttempts=0;
        Dictionary<string,PinGroup> map=new Dictionary<string,PinGroup>();
        int dropped=0;
        foreach (GoodTarget target in targets)
        {
            byte[] record=ReadBytes(target.Address,0x28);
            if (record==null || U32(record,0x18)!=(uint)target.Guid || !IsGoodsRecord(record))
            {
                dropped++;
                continue;
            }
            string key=target.EntityAddress.ToString("X")+"|"+target.ParentAddress.ToString("X")+"|"+
                target.HeadAddress.ToString("X")+"|"+target.AreaId;
            PinGroup group;
            if (!map.TryGetValue(key,out group))
            {
                group=new PinGroup {EntityAddress=target.EntityAddress,WarehouseAddress=target.ParentAddress,
                    HeadAddress=target.HeadAddress,AreaId=target.AreaId};
                map.Add(key,group);
                pinGroups.Add(group);
            }
            group.Targets.Add(target);
            pinRecordCount++;
        }
        return dropped;
    }
    private static bool ValidatePinArea(PinGroup group)
    {
        byte[] entity=ReadBytes(group.EntityAddress,0x68);
        byte[] link=ReadBytes(group.EntityAddress+0x180,8);
        byte[] warehouse=ReadBytes(group.WarehouseAddress,0x38);
        return entity!=null && link!=null && warehouse!=null &&
            U16(entity,0x64)==(ushort)group.AreaId &&
            U64(entity,8)==moduleBase+AreaWarehouseEntityVtableRva &&
            U64(link,0)==group.WarehouseAddress &&
            U64(warehouse,0)==moduleBase+WarehouseVtableRva &&
            U64(warehouse,0x28)==group.HeadAddress &&
            U64(warehouse,0x30)>=20 && U64(warehouse,0x30)<=1000;
    }
    private static void PinTick()
    {
        if (!pinEnabled) return;
        int written=0, skipped=0, validGroups=0;
        try
        {
            foreach (PinGroup group in pinGroups)
            {
                if (!ownedAreaIds.Contains(group.AreaId) || !ValidatePinArea(group))
                {
                    skipped+=group.Targets.Count;
                    continue;
                }
                validGroups++;
                foreach (GoodTarget target in group.Targets)
                {
                    byte[] record=ReadBytes(target.Address,0x28);
                    if (record==null)
                    {
                        skipped++;
                        continue;
                    }
                    uint capacity=U32(record,0x1C), count=U32(record,0x20);
                    if (U32(record,0x18)!=(uint)target.Guid || !IsGoodsRecord(record) ||
                        capacity<PinCapacityFloor || capacity>PinCapacityCeiling || count>capacity)
                    {
                        skipped++;
                        continue;
                    }
                    if (count==capacity) continue;
                    RecordStockChange(target,count);
                    Write(target.Address+0x20,BitConverter.GetBytes(capacity));
                    written++;
                }
            }
        }
        catch (Exception ex)
        {
            EndPin();
            Console.WriteLine("全部物资锁定已因写入失败停止："+ex.Message);
            Console.WriteLine("  已写入的数量仍记录在本次修改里，可按 Ctrl+F12 尝试还原。");
            Console.Beep(300,200);
            return;
        }
        // Every warehouse link broke, which is what loading a save in game looks like.
        // Re-locate in the background instead of writing into stale addresses.
        if (validGroups==0 && pinGroups.Count>0)
        {
            if (DateTime.UtcNow>=nextPinRecoverUtc)
            {
                nextPinRecoverUtc=DateTime.UtcNow.AddSeconds(20);
                pinRecoverAttempts++;
                if (pinRecoverAttempts>3)
                {
                    EndPin();
                    Console.WriteLine("全部物资锁定已停止：仓库记录持续失效（可能换了存档或重开了游戏）。"+
                        "需要时请重新按 Ctrl+Alt+- 开启。");
                    return;
                }
                Console.WriteLine("全部物资锁定：各岛仓库链暂时失效，正在后台重新定位（第 "+pinRecoverAttempts+" 次）...");
                RequestBackgroundRescan();
            }
            return;
        }
        pinRecoverAttempts=0;
        if (written>0 && DateTime.UtcNow>=pinReportUtc)
        {
            pinReportUtc=DateTime.UtcNow.AddSeconds(30);
            Console.WriteLine("锁定中：本次补满 "+written+" 条记录（共 "+pinRecordCount+" 条"+
                (skipped>0 ? "，"+skipped+" 条本轮跳过" : "")+"）。");
        }
    }
    private static bool EmergencyRestore()
    {
        Console.WriteLine("Ctrl+F12：停止全部快捷键，开始恢复本次运行的内存修改...");
        if (pinEnabled)
        {
            EndPin();
            Console.WriteLine("  已停止全部物资锁定，下面按记录还原库存。");
        }
        bool complete=RestoreShips();
        int restored=0;
        // With the stock lock a run can hold thousands of recorded addresses, so the island
        // chain is validated once per island and each record is re-checked by identity only.
        Dictionary<string,bool> areaValidity=new Dictionary<string,bool>();
        Dictionary<uint,int> restoredPerArea=new Dictionary<uint,int>();
        int failed=0;
        bool compact=stockChangeOrder.Count>200;
        StringBuilder details=new StringBuilder();
        string influenceResult;
        bool influenceRestored=RestoreInfluence(out influenceResult);
        if (!influenceRestored) complete=false;
        details.AppendLine(influenceResult);
        for (int i=stockChangeOrder.Count-1;i>=0;i--)
        {
            StockChange change=stockChangeOrder[i];
            GoodTarget target=change.Target;
            try
            {
                if (game.HasExited) throw new InvalidOperationException("游戏进程已退出。");
                string areaKey=target.EntityAddress.ToString("X")+"|"+target.ParentAddress.ToString("X")+"|"+
                    target.HeadAddress.ToString("X")+"|"+target.AreaId;
                bool areaOk;
                if (!areaValidity.TryGetValue(areaKey,out areaOk))
                {
                    PinGroup group=new PinGroup {EntityAddress=target.EntityAddress,WarehouseAddress=target.ParentAddress,
                        HeadAddress=target.HeadAddress,AreaId=target.AreaId};
                    areaOk=ownedAreaIds.Contains(target.AreaId) && ValidatePinArea(group);
                    areaValidity[areaKey]=areaOk;
                }
                if (!areaOk) throw new InvalidOperationException("库存或岛屿归属已变化，未写入该条目。");
                byte[] current=ReadBytes(target.Address,0x28);
                if (current==null || U32(current,0x18)!=(uint)target.Guid || !IsGoodsRecord(current))
                    throw new InvalidOperationException("库存记录已变化，未写入该条目。");
                uint capacity=U32(current,0x1C);
                if (capacity<change.OriginalCount) throw new InvalidOperationException("当前上限低于原始库存，未写入该条目。");
                if (U32(current,0x20)!=change.OriginalCount)
                    Write(target.Address+0x20,BitConverter.GetBytes(change.OriginalCount));
                byte[] verify=ReadBytes(target.Address+0x20,4);
                if (verify==null || U32(verify,0)!=change.OriginalCount)
                    throw new InvalidOperationException("恢复后的内存读回校验失败。");
                restored++;
                int areaCount;
                restoredPerArea.TryGetValue(target.AreaId,out areaCount);
                restoredPerArea[target.AreaId]=areaCount+1;
                string message="  Area "+target.AreaId+" "+GoodName(target.Guid)+" 恢复为 "+change.OriginalCount;
                if (!compact) Console.WriteLine(message);
                details.AppendLine(message);
            }
            catch (Exception ex)
            {
                complete=false;
                failed++;
                string message="  Area "+target.AreaId+" "+GoodName(target.Guid)+" 恢复失败："+ex.Message;
                Console.WriteLine(message);
                details.AppendLine(message);
            }
        }
        if (compact)
        {
            Console.WriteLine("  已还原 "+restored+" 条库存记录，涉及 "+restoredPerArea.Count+" 座岛；逐条明细见 trainer.log。");
            foreach (KeyValuePair<uint,int> entry in restoredPerArea)
                Console.WriteLine("    Area "+entry.Key+"：还原 "+entry.Value+" 条");
        }
        if (failed>0) Console.WriteLine("  有 "+failed+" 条记录未还原，逐条原因见上面和 trainer.log。");
        string summary="Ctrl+F12 恢复完成：库存 "+restored+"/"+stockChangeOrder.Count+" 条，影响力"+
            (influenceRestored ? "已扣回或未修改" : "未扣回")+"，造船代码"+
            (shipEnabled ? "未恢复" : "已恢复或未启用")+"，全部物资锁定"+
            (pinEnabled ? "仍在运行" : "已停止")+"；修改器退出。";
        Console.WriteLine(summary);
        try
        {
            string log=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"trainer.log");
            File.AppendAllText(log,DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")+" "+summary+Environment.NewLine+details.ToString(),Encoding.UTF8);
        }
        catch (Exception ex) { Console.WriteLine("写入恢复日志失败："+ex.Message); }
        return complete;
    }
    private static void FillGood(int guid)
    {
        WriteGood(guid,false);
    }
    // hotkeys.txt 里带 |toggle 的物资键是开关：这批物资全都已在上限时按一次清空为 0，
    // 否则按一次拉满。判断依据是当前库存本身，所以不会因为手动改动而失步。
    private static void ToggleGood(int guid)
    {
        WriteGood(guid,true);
    }
    private static void WriteGood(int guid,bool toggle)
    {
        List<GoodTarget> targets=stockTargets[guid];
        if (targets.Count==0) throw new InvalidOperationException("No validated "+GoodName(guid)+
            " stock record found among "+ownedAreaIds.Count+" known owned island(s); nothing changed.");
        foreach (GoodTarget target in targets)
            if (!ValidateTarget(target))
                throw new InvalidOperationException(GoodName(guid)+" ownership link changed; no island was modified. Restart the trainer.");
        bool clear=false;
        if (toggle)
        {
            clear=true;
            foreach (GoodTarget target in targets)
            {
                byte[] record=ReadBytes(target.Address,0x28);
                if (record==null) throw new InvalidOperationException("Could not read "+GoodName(guid)+" stock.");
                uint capacity=U32(record,0x1C), count=U32(record,0x20);
                if (capacity<1 || capacity>100000)
                    throw new InvalidOperationException("Invalid capacity for "+GoodName(guid)+": "+capacity);
                if (count!=capacity) { clear=false; break; }
            }
        }
        foreach (GoodTarget target in targets)
        {
            uint capacity=clear ? ClearGoodToZero(target) : FillGoodToCapacity(target);
            uint wanted=clear ? 0u : capacity;
            byte[] verify=ReadBytes(target.Address+0x1C,8);
            if (verify==null || U32(verify,0)!=capacity || U32(verify,4)!=wanted)
                throw new InvalidOperationException(GoodName(guid)+" write failed immediate readback at 0x"+target.Address.ToString("X"));
            Console.WriteLine("  Area "+target.AreaId+(clear ? " cleared to 0/" : " filled to ")+wanted+"/"+capacity);
        }
        Console.WriteLine(GoodName(guid)+(clear ? " cleared to 0" : " filled")+" on "+targets.Count+"/"+
            ownedAreaIds.Count+" known owned island(s)"+
            (toggle ? "；再按一次同一快捷键即"+(clear ? "拉满" : "清空")+"。" : ", once."));
        List<uint> missing=MissingAreaIds(targets);
        if (missing.Count>0)
            Console.WriteLine("  未定位库存记录的本人岛 Area ID: "+string.Join(",",missing)+"。这些岛没有写入。");
    }
    private static List<uint> MissingAreaIds(List<GoodTarget> targets)
    {
        HashSet<uint> present=new HashSet<uint>();
        foreach (GoodTarget target in targets) present.Add(target.AreaId);
        List<uint> missing=new List<uint>();
        foreach (uint area in ownedAreaIds)
            if (!present.Contains(area)) missing.Add(area);
        missing.Sort();
        return missing;
    }
    private static void ValidateStockTargets()
    {
        foreach (KeyValuePair<int,List<GoodTarget>> goods in stockTargets)
        {
            HashSet<uint> seenAreas=new HashSet<uint>();
            foreach (GoodTarget target in goods.Value)
            {
                if (!seenAreas.Add(target.AreaId) || !ValidateTarget(target))
                    throw new InvalidOperationException("仓库映射验证失败：Area "+target.AreaId+
                        "，物资 GUID "+goods.Key+"。没有启用快捷键。");
            }
        }
    }
    private static void ShowStockTargets()
    {
        foreach (HotkeyAssignment assignment in hotkeys.Values)
        {
            if (assignment.Guid==0) continue;
            List<GoodTarget> targets=stockTargets[assignment.Guid];
            Console.WriteLine(HotkeyLabel(assignment.Slot)+" "+assignment.Name+": "+targets.Count+"/"+
                ownedAreaIds.Count+" known owned island record(s)");
            foreach (GoodTarget target in targets)
                Console.WriteLine("  Area "+target.AreaId+" = "+target.Count+"/"+target.Capacity+" at 0x"+target.Address.ToString("X"));
            List<uint> missing=MissingAreaIds(targets);
            if (missing.Count>0)
                Console.WriteLine("  未定位库存记录的本人岛 Area ID: "+string.Join(",",missing));
        }
        if (influenceTarget!=null)
            Console.WriteLine("Ctrl+- 影响力 +100：当前总量 "+influenceTarget.Total+"、可用 "+influenceTarget.Available+
                "；玩家资源表 0x"+influenceTarget.ObjectAddress.ToString("X"));
        else
            Console.WriteLine("Ctrl+- 影响力：玩家资源表候选 "+influenceCandidateCount+" 条，不能唯一定位时此键拒绝写入。");
    }
    private static void ActivateInfluenceHotkey(bool readOnly)
    {
        if (game.HasExited || !GameIsForeground()) return;
        try
        {
            if (readOnly) Console.WriteLine("READ ONLY: Ctrl+- would add 100 influence.");
            else AddInfluence();
            Console.Beep(900,100);
        }
        catch (Exception ex) { Console.WriteLine("Ctrl+- failed: "+ex.Message); Console.Beep(300,200); }
    }
    // The timer period follows what is needed: fast key-state polling only when a hotkey
    // had to fall back, the stock lock period while it runs, otherwise a lazy second.
    private static void ResetPollTimer()
    {
        if (pollTimerId!=UIntPtr.Zero)
        {
            KillTimer(IntPtr.Zero,pollTimerId);
            pollTimerId=UIntPtr.Zero;
        }
        uint interval=fallbackPollingNeeded ? 20U : (pinEnabled ? 250U : 1000U);
        pollTimerId=SetTimer(IntPtr.Zero,UIntPtr.Zero,interval,IntPtr.Zero);
        if (pollTimerId==UIntPtr.Zero)
            throw new InvalidOperationException("无法启动热键热更新定时器，错误码="+Marshal.GetLastWin32Error());
    }
    private static bool HotkeyLoop(bool readOnly)
    {
        List<int> registered=new List<int>();
        bool restoreChordWasDown=false;
        bool minusChordWasDown=false;
        bool pinChordWasDown=false;
        try
        {
            bool restoreRegistered=RegisterHotKey(IntPtr.Zero,900,0x0002|0x4000,0x7B);
            if (restoreRegistered) registered.Add(900);
            else
            {
                Console.WriteLine("Ctrl+F12 已被其他程序占用；改用按键状态检测，可能同时触发该程序原有动作。");
            }
            bool minusMainRegistered=RegisterHotKey(IntPtr.Zero,901,0x0002|0x4000,VkMinusMain);
            if (minusMainRegistered) registered.Add(901);
            else Console.WriteLine("Ctrl+主键盘减号注册失败，改用按键状态检测；错误码="+Marshal.GetLastWin32Error());
            bool minusNumpadRegistered=RegisterHotKey(IntPtr.Zero,902,0x0002|0x4000,VkMinusNumpad);
            if (minusNumpadRegistered) registered.Add(902);
            else Console.WriteLine("Ctrl+小键盘减号注册失败，改用按键状态检测；错误码="+Marshal.GetLastWin32Error());
            bool pinMainRegistered=RegisterHotKey(IntPtr.Zero,PinHotkeyMainId,PinHotkeyModifiers,VkMinusMain);
            if (pinMainRegistered) registered.Add(PinHotkeyMainId);
            else Console.WriteLine("Ctrl+Alt+主键盘减号注册失败，改用按键状态检测；错误码="+Marshal.GetLastWin32Error());
            bool pinNumpadRegistered=RegisterHotKey(IntPtr.Zero,PinHotkeyNumpadId,PinHotkeyModifiers,VkMinusNumpad);
            if (pinNumpadRegistered) registered.Add(PinHotkeyNumpadId);
            else Console.WriteLine("Ctrl+Alt+小键盘减号注册失败，改用按键状态检测；错误码="+Marshal.GetLastWin32Error());
            fallbackPollingNeeded=!restoreRegistered || !minusMainRegistered || !minusNumpadRegistered ||
                !pinMainRegistered || !pinNumpadRegistered;
            ResetPollTimer();
            foreach (HotkeyAssignment assignment in hotkeys.Values)
                registered.AddRange(RegisterSlot(assignment.Slot));
            Console.WriteLine(readOnly ? "READ ONLY MONITOR: hotkeys.txt 保存后自动生效；Ctrl+F12 退出监控。" :
                "Ready. Ctrl+数字/Shift+数字/Alt+数字填物资；Ctrl+Alt+- 全部物资拉满并锁定（再按一次只停止锁定）；"+
                "Ctrl+- 影响力 +100；Ctrl+F12 恢复并退出。");
            Console.WriteLine("新岛无需重启：游戏中保存一次或等自动存档，修改器会自动识别并立即纳入。hotkeys.txt 保存后自动生效。");
            foreach (HotkeyAssignment assignment in hotkeys.Values)
                Console.WriteLine("  "+HotkeyLabel(assignment.Slot)+" = "+assignment.Name+
                    (assignment.Guid==0 ? " (fast ships)" :
                     (assignment.ToggleZero ? " (fill to capacity <-> clear to 0)" : " (fill once to current capacity)")));
            Console.WriteLine("  Ctrl+Alt+- = 全部物资拉满并锁定，再按一次只停止锁定（Ctrl+F12 还原到修改前）");
            DateTime nextReloadCheck=DateTime.UtcNow.AddSeconds(1);
            nextSaveCheckUtc=DateTime.UtcNow.AddSeconds(1);
            Msg message;
            while (GetMessage(out message,IntPtr.Zero,0,0)>0)
            {
                if (message.message==0x0113 && message.wParam==pollTimerId)
                {
                    if (game.HasExited) { Console.WriteLine("Game has exited."); break; }
                    if (!restoreRegistered)
                    {
                        bool chordDown=KeyDown(0x7B) && KeyDown(VkControl);
                        if (chordDown && !restoreChordWasDown) return readOnly ? true : EmergencyRestore();
                        restoreChordWasDown=chordDown;
                    }
                    if (!minusMainRegistered || !minusNumpadRegistered)
                    {
                        bool minusDown=(!minusMainRegistered && KeyDown(VkMinusMain)) ||
                            (!minusNumpadRegistered && KeyDown(VkMinusNumpad));
                        // Alt must be up: Ctrl+Alt+- belongs to the stock lock.
                        bool chordDown=KeyDown(VkControl) && !KeyDown(VkMenu) && minusDown;
                        if (chordDown && !minusChordWasDown) ActivateInfluenceHotkey(readOnly);
                        minusChordWasDown=chordDown;
                    }
                    if (!pinMainRegistered || !pinNumpadRegistered)
                    {
                        bool minusDown=(!pinMainRegistered && KeyDown(VkMinusMain)) ||
                            (!pinNumpadRegistered && KeyDown(VkMinusNumpad));
                        bool chordDown=KeyDown(VkControl) && KeyDown(VkMenu) && minusDown;
                        if (chordDown && !pinChordWasDown) ActivatePinHotkey(readOnly);
                        pinChordWasDown=chordDown;
                    }
                    DateTime now=DateTime.UtcNow;
                    ApplyInfluenceScan();
                    if (!readOnly && influenceTarget==null && now>=nextInfluenceRetryUtc)
                    {
                        nextInfluenceRetryUtc=now.AddSeconds(influenceRetrySeconds);
                        if (influenceRetrySeconds<30) influenceRetrySeconds=influenceRetrySeconds<5 ? 5 : influenceRetrySeconds*2;
                        RequestInfluenceScan();
                    }
                    if (pinEnabled && !readOnly)
                    {
                        if (now>=nextPinTickUtc)
                        {
                            nextPinTickUtc=now.AddSeconds(PinIntervalSeconds);
                            PinTick();
                        }
                        if (now>=nextPinRescanUtc)
                        {
                            nextPinRescanUtc=now.AddSeconds(PinRecordRefreshSeconds);
                            RefreshPinRecords();
                        }
                    }
                    ApplyPendingScan();
                    if (now>=nextSaveCheckUtc)
                    {
                        nextSaveCheckUtc=now.AddSeconds(SaveCheckSeconds);
                        CheckNewestSave();
                    }
                    if (now>=nextReloadCheck)
                    {
                        nextReloadCheck=now.AddSeconds(1);
                        TryReloadHotkeys(registered);
                    }
                    continue;
                }
                if (message.message!=0x0312) continue;
                int id=unchecked((int)message.wParam.ToUInt64());
                if (id==900) return readOnly ? true : EmergencyRestore();
                if (id==901 || id==902) { ActivateInfluenceHotkey(readOnly); continue; }
                if (id==PinHotkeyMainId || id==PinHotkeyNumpadId) { ActivatePinHotkey(readOnly); continue; }
                if (id<100 || id>=180) continue;
                int slot=(id-100)/2;
                try
                {
                    if (game.HasExited) { Console.WriteLine("Game has exited."); break; }
                    if (!GameIsForeground()) continue;
                    HotkeyAssignment assignment;
                    if (!hotkeys.TryGetValue(slot,out assignment)) continue;
                    if (readOnly) Console.WriteLine("READ ONLY: "+HotkeyLabel(slot)+" would run "+assignment.Name+
                        (assignment.ToggleZero ? " (fill/clear toggle)" : ""));
                    else if (assignment.Guid==0) EnableShips();
                    else if (assignment.ToggleZero) ToggleGood(assignment.Guid);
                    else FillGood(assignment.Guid);
                    Console.Beep(900,100);
                }
                catch (Exception ex) { Console.WriteLine("Hotkey failed: "+ex.Message); Console.Beep(300,200); }
            }
            return true;
        }
        finally
        {
            if (pollTimerId!=UIntPtr.Zero) KillTimer(IntPtr.Zero,pollTimerId);
            pinEnabled=false;
            foreach(int id in registered) UnregisterHotKey(IntPtr.Zero,id);
        }
    }
    private static int Main(string[] args)
    {
        bool directLaunch=args.Length==0;
        try { Console.OutputEncoding=Encoding.UTF8; } catch {}
        AppDomain.CurrentDomain.ProcessExit+=delegate {
            RestoreShips();
            if(processHandle!=IntPtr.Zero) CloseHandle(processHandle);
        };
        try
        {
            if (args.Length>0 && args[0].Equals("--refresh-areas",StringComparison.OrdinalIgnoreCase))
            {
                HashSet<uint> refreshed=RefreshOwnedAreasFromNewestSave();
                Console.WriteLine("owned_areas.txt: "+string.Join(",",SortedAreas(refreshed)));
                return 0;
            }
            bool dryRun=args.Length>0 && args[0].Equals("--dry-run",StringComparison.OrdinalIgnoreCase);
            bool monitor=args.Length>0 && args[0].Equals("--monitor",StringComparison.OrdinalIgnoreCase);
            dryRun=dryRun || monitor;
            if (!dryRun) RefuseOtherTrainers();
            LoadHotkeys();
            HashSet<uint> owned=null;
            try { owned=RefreshOwnedAreasFromNewestSave(); }
            catch (Exception ex) { Console.WriteLine("自动解析最新存档失败："+ex.Message); }
            if (owned==null)
            {
                owned=LoadOwnedAreas();
                Console.WriteLine("改用现有 owned_areas.txt 的 "+owned.Count+" 座岛；在游戏里保存一次后重启修改器即可刷新。");
            }
            ownedAreaIds=owned;
            Console.WriteLine("Owned area IDs from latest save: "+string.Join(",",SortedAreas(owned)));
            Attach(dryRun);
            Console.WriteLine("Mapping owned warehouses in process memory (single scan)...");
            Stopwatch mappingWatch=Stopwatch.StartNew();
            ScanOutput first=ScanOwnedGoods(owned,selectedGuids,true,true,true);
            stockTargets=first.Configured;
            pinCandidates=first.AllGoods!=null ? first.AllGoods : new List<GoodTarget>();
            influenceCandidateCount=first.InfluenceCandidates.Count;
            influenceTarget=influenceCandidateCount==1 ? first.InfluenceCandidates[0] : null;
            if (first.SeenAreas!=null)
                foreach (uint area in first.SeenAreas)
                    if (!owned.Contains(area)) baselineUnknownAreas.Add(area);
            int foundTargets=first.ConfiguredCount;
            if (foundTargets==0)
            {
                Console.WriteLine("Direct warehouse search found no goods; trying the original scan...");
                stockTargets=FindOwnedGoods(owned);
            }
            ValidateStockTargets();
            mappingWatch.Stop();
            Console.WriteLine("Warehouse mapping took "+mappingWatch.Elapsed.TotalSeconds.ToString("F1")+" seconds.");
            Console.WriteLine("全部物资共定位 "+pinCandidates.Count+" 条仓库记录，供 Ctrl+Alt+- 库存锁定使用。");
            if (CountTargets(stockTargets)==0)
            {
                Console.WriteLine("警告：游戏内存里没有找到任何仓库记录 —— 游戏可能还停在主菜单或正在载入存档。");
                Console.WriteLine("      请先在游戏里载入存档，然后关闭本窗口并重新运行 Start-Trainer.cmd。");
            }
            if (influenceTarget==null)
            {
                Console.WriteLine("提示：暂时没定位到影响力资源表（多半是启动时游戏还没载入完存档）。");
                Console.WriteLine("      修改器会在后台自动重试，成功后打印“Ctrl+- 影响力已就绪”；也可以直接按一次 Ctrl+- 立即触发重扫。");
                nextInfluenceRetryUtc=DateTime.UtcNow.AddSeconds(3);
            }
            ShowStockTargets();
            if (dryRun && !monitor)
            {
                Console.WriteLine("Ship timer address at 0x"+shipPatchAddress.ToString("X"));
                return 0;
            }
            return HotkeyLoop(monitor) ? 0 : 1;
        }
        catch (Exception ex)
        {
            Console.WriteLine("修改器启动失败："+ex.Message);
            try
            {
                string log=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"trainer.log");
                File.AppendAllText(log,DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")+" "+ex+Environment.NewLine,Encoding.UTF8);
                Console.WriteLine("详细错误已写入："+log);
            }
            catch (Exception logError) { Console.WriteLine("写入错误日志失败："+logError.Message); }
            if (directLaunch)
            {
                Console.WriteLine("按 Enter 关闭此窗口。");
                Console.ReadLine();
            }
            return 1;
        }
    }
}
