using System.IO;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace TaintAnalyzer.Tests.Fixtures.Loop;

public class PipeLoops
{
    // read loop, never inspects IsCompleted -> FLAG
    public async Task PipeNoCheck(PipeReader reader)
    {
        int total = 0;
        while (total < 100)
        {
            ReadResult result = await reader.ReadAsync();
            total += (int)result.Buffer.Length;
            reader.AdvanceTo(result.Buffer.End);
        }
    }

    // read loop, inspects IsCompleted -> CLEAR
    public async Task PipeWithCheck(PipeReader reader)
    {
        while (true)
        {
            ReadResult result = await reader.ReadAsync();
            reader.AdvanceTo(result.Buffer.Start, result.Buffer.End);
            if (result.IsCompleted) break;
        }
    }

    // single read, NOT in a loop -> CLEAR (Tier 2 back-edge gate)
    public async Task PipeSingleRead(PipeReader reader)
    {
        ReadResult result = await reader.ReadAsync();
        reader.AdvanceTo(result.Buffer.End);
    }
}

public class PlainLoops
{
    // loop with no read call -> CLEAR (not a candidate)
    public int LoopNoRead(int n)
    {
        int sum = 0;
        for (int i = 0; i < n; i++) sum += i;
        return sum;
    }
}

public class StreamLoops
{
    // stream read loop, never checks count == 0 -> FLAG
    public int StreamNoCheck(Stream s, int limit)
    {
        byte[] buf = new byte[256];
        int total = 0;
        while (total < limit)
        {
            int n = s.Read(buf, 0, buf.Length);
            total += n;
        }
        return total;
    }

    // stream read loop, checks count == 0 -> CLEAR
    public int StreamWithCheck(Stream s)
    {
        byte[] buf = new byte[256];
        int total = 0;
        while (true)
        {
            int n = s.Read(buf, 0, buf.Length);
            if (n == 0) break;
            total += n;
        }
        return total;
    }

    // socket receive loop, never checks count == 0 -> FLAG
    public int SocketNoCheck(Socket sock, int limit)
    {
        byte[] buf = new byte[256];
        int total = 0;
        while (total < limit)
        {
            int n = sock.Receive(buf);
            total += n;
        }
        return total;
    }
}

// internal type, public read-loop method invoked via a delegate the call graph can't
// resolve — must still be enumerated under the Loop visibility relaxation.
internal class InternalMiddleware
{
    public async Task OnConnectedAsync(PipeReader reader)
    {
        int total = 0;
        while (total < 100)
        {
            ReadResult result = await reader.ReadAsync();
            total += (int)result.Buffer.Length;
            reader.AdvanceTo(result.Buffer.End);
        }
    }
}
