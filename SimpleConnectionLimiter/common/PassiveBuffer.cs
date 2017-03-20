using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SimpleConnectionLimiter.common
{
    /// <summary>
    /// A buffer aimed to reduce memory move / copy.
    /// Not thread safe!
    /// </summary>
    public class PassiveBuffer
    {

        public int Size => _tail - _head;

        public int Capacity { get; }

        public int Available => Capacity - Size;

        public bool IsEmpty => Size <= 0;

        public bool IsFull => Available <= 0;

        private readonly byte[] _rawArray;
        private int _head = 0;
        private int _tail = 0;

        public PassiveBuffer(int capacity)
        {
            Capacity = capacity;

            _rawArray = new byte[capacity * 2];
        }

        public void Clear()
        {
            _head = 0;
            _tail = 0;
        }

        public void RequireRead(int readCount, out ArraySegment<byte> rawBuffer )
        {
            if (readCount < 0)
            {
                throw new ArgumentException(nameof(readCount), "Can't less than 0!");
            }
            if (readCount > Size)
            {
                throw new ArgumentOutOfRangeException(nameof(readCount));
            }

            rawBuffer = new ArraySegment<byte>(_rawArray, _head, readCount);
        }

        public void ConfirmRead(int readCount)
        {
            if (readCount < 0)
            {
                throw new ArgumentException(nameof(readCount), "Can't less than 0!");
            }
            if (readCount > Size)
            {
                throw new ArgumentOutOfRangeException(nameof(readCount));
            }

            _head += readCount;

            if (Size <= 0)
            {
                Clear();
            }
        }

        public void RequireWrite(int writeCount, bool ensureSize, bool forceTrim, out ArraySegment<byte> rawBuffer)
        {
            if (writeCount < 0)
            {
                throw new ArgumentException(nameof(writeCount), "Can't less than 0!");
            }
            if (writeCount > Capacity - Size)
            {
                throw new ArgumentOutOfRangeException(nameof(writeCount));
            }

            var tailAvailable = _rawArray.Length - _tail;
            if (forceTrim || tailAvailable < writeCount / 2 || _head > Size / 2 || (ensureSize && tailAvailable < writeCount))
            {
                // Trim
                Buffer.BlockCopy(_rawArray, _head, _rawArray, 0, Size);
                _tail = Size;
                _head = 0;
                tailAvailable = _rawArray.Length - _tail;
            }
            
            rawBuffer = new ArraySegment<byte>(_rawArray, _tail, Math.Min(tailAvailable, writeCount));
        }

        public void ConfirmWrite(int writeCount)
        {
            if (writeCount < 0)
            {
                throw new ArgumentException(nameof(writeCount), "Can't less than 0!");
            }
            var tailAvailable = _rawArray.Length - _tail;
            if (writeCount > tailAvailable || writeCount > Capacity - Size)
            {
                throw new ArgumentOutOfRangeException(nameof(writeCount));
            }

            _tail += writeCount;
        }
    }
}
