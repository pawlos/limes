using Mono.Cecil;

namespace TaintAnalyzer;

public enum ReadKind { PipeReader, StreamInt }

public sealed record ReadMatch(ReadKind Kind, string Api);

// Recognizer table for loop-termination detection (CWE-835), mirroring SinkShapes.
// Two questions per call site: is this a recognized read, and is this a completion check?
public static class ReadLoopShapes
{
    public static ReadMatch? RecognizeRead(MethodReference mr)
    {
        var t = mr.DeclaringType.FullName;
        var n = mr.Name;
        return (t, n) switch
        {
            ("System.IO.Pipelines.PipeReader", "ReadAsync") => new ReadMatch(ReadKind.PipeReader, "pipe_reader_read_async"),
            ("System.IO.Stream", "Read")                     => new ReadMatch(ReadKind.StreamInt, "stream_read"),
            ("System.IO.Stream", "ReadAsync")                => new ReadMatch(ReadKind.StreamInt, "stream_read_async"),
            ("System.Net.Sockets.Socket", "Receive")         => new ReadMatch(ReadKind.StreamInt, "socket_receive"),
            ("System.Net.Sockets.Socket", "ReceiveAsync")    => new ReadMatch(ReadKind.StreamInt, "socket_receive_async"),
            _ => null,
        };
    }

    // PipeReader completion signal: ReadResult.IsCompleted getter.
    public static bool IsPipeCompletionSignal(MethodReference mr)
        => mr.Name == "get_IsCompleted" && mr.DeclaringType.Name == "ReadResult";
}
