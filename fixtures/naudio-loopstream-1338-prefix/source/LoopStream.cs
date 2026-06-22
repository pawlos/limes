using System;
using System.IO;

// VULNERABLE reconstruction of NAudio.Extras.LoopStream (naudio/NAudio#1338, CWE-835).
//
// This mirrors the real library's structure so the loop detector sees the same IL shape:
//   * WaveStream is abstract and does NOT re-declare Read, so it inherits the abstract
//     Read(byte[],int,int) from System.IO.Stream. A call `sourceStream.Read(...)` where
//     sourceStream is statically typed WaveStream therefore binds to
//     System.IO.Stream::Read in IL — which ReadLoopShapes.RecognizeRead matches.
//   * LoopStream.Read is the verbatim buggy method from NAudio master.
//
// The bug: when the source stream is empty, sourceStream.Read always returns 0, so
// `read += readThisTime` never advances and `while (read < count)` spins at 100% CPU.
// The loop inspects the read result (`if (readThisTime < required)`) but never compares
// it against zero to break — the missing completion check the detector reports.

namespace NAudio.Wave
{
    public abstract class WaveStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override void Flush() { }
        public override void SetLength(long value) { }
        public override void Write(byte[] buffer, int offset, int count) { }
        public override long Seek(long offset, SeekOrigin origin) => 0;
        // Read(byte[],int,int) intentionally NOT declared — inherited abstract from Stream.
    }
}

namespace NAudio.Extras
{
    using NAudio.Wave;

    /// <summary>
    /// Loopable WaveStream — verbatim buggy Read from NAudio master (naudio/NAudio#1338).
    /// </summary>
    public class LoopStream : WaveStream
    {
        readonly WaveStream sourceStream;

        public LoopStream(WaveStream source)
        {
            sourceStream = source;
        }

        public override long Length
        {
            get { return long.MaxValue / 32; }
        }

        public override long Position
        {
            get { return sourceStream.Position; }
            set { sourceStream.Position = value; }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int read = 0;
            while (read < count)
            {
                int required = count - read;
                int readThisTime = sourceStream.Read(buffer, offset + read, required);
                if (readThisTime < required)
                {
                    sourceStream.Position = 0;
                }

                if (sourceStream.Position >= sourceStream.Length)
                {
                    sourceStream.Position = 0;
                }
                read += readThisTime;
            }
            return read;
        }
    }
}
