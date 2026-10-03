using System.Net;
using System.Runtime.InteropServices;

namespace Bastion.Core.Network;

public enum TcpState
{
    Closed = 1, Listen, SynSent, SynReceived, Established, FinWait1, FinWait2, CloseWait, Closing, LastAck, TimeWait, DeleteTcb,
}

public sealed record TcpConnection(IPEndPoint Local, IPEndPoint Remote, TcpState State, int ProcessId);

/// <summary>Reads the system TCP table (IPv4 and IPv6) including the owning process id.</summary>
public static class TcpTable
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;

    public static IReadOnlyList<TcpConnection> Read()
    {
        if (!OperatingSystem.IsWindows())
            return [];
        var list = new List<TcpConnection>();
        ReadTable(AfInet, list);
        ReadTable(AfInet6, list);
        return list;
    }

    private static void ReadTable(int family, List<TcpConnection> list)
    {
        var size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, TcpTableOwnerPidAll, 0);
        for (var attempt = 0; attempt < 3; attempt++)
        {
            size += 4096;
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var result = GetExtendedTcpTable(buffer, ref size, false, family, TcpTableOwnerPidAll, 0);
                if (result == 122) // ERROR_INSUFFICIENT_BUFFER: table grew, retry
                    continue;
                if (result != 0)
                    return;
                var count = Marshal.ReadInt32(buffer);
                var row = buffer + 4;
                for (var i = 0; i < count; i++)
                {
                    if (family == AfInet)
                    {
                        var r = Marshal.PtrToStructure<MibTcpRowOwnerPid>(row);
                        list.Add(new TcpConnection(
                            new IPEndPoint(new IPAddress(r.LocalAddr), Port(r.LocalPort)),
                            new IPEndPoint(new IPAddress(r.RemoteAddr), Port(r.RemotePort)),
                            (TcpState)r.State, (int)r.OwningPid));
                        row += Marshal.SizeOf<MibTcpRowOwnerPid>();
                    }
                    else
                    {
                        var r = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(row);
                        list.Add(new TcpConnection(
                            new IPEndPoint(new IPAddress(r.LocalAddr, r.LocalScopeId), Port(r.LocalPort)),
                            new IPEndPoint(new IPAddress(r.RemoteAddr, r.RemoteScopeId), Port(r.RemotePort)),
                            (TcpState)r.State, (int)r.OwningPid));
                        row += Marshal.SizeOf<MibTcp6RowOwnerPid>();
                    }
                }
                return;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    private static int Port(uint networkOrder) => (int)(((networkOrder & 0xFF) << 8) | ((networkOrder >> 8) & 0xFF));

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int family, int tableClass, uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] LocalAddr;
        public uint LocalScopeId;
        public uint LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] RemoteAddr;
        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public uint OwningPid;
    }
}
