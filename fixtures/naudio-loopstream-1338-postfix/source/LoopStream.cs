using System;
using System.IO;

// PATCHED reconstruction of NAudio.Extras.LoopStream (naudio/NAudio#1339 fixes #1338).
//
// Same structure as the prefix variant; the only change is the added zero-check break:
//   if (readThisTime == 0 && sourceStream.Position == 0) break;
// A zero read from the very start of the source means the source is empty, so the loop
// stops instead of spinning. The read result is now compared against zero, which
// LoopTerminationAnalyzer.StreamCompletionPresent recognizes as a completion check —
// so the detector reports no findings.

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
    /// Loopable WaveStream — patched Read (naudio/NAudio#1339).
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
                if (readThisTime == 0 && sourceStream.Position == 0)
                {
                    // Nothing read from the very start: the source is empty, so stop
                    // rather than spin forever (naudio/NAudio#1339).
                    break;
                }
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
