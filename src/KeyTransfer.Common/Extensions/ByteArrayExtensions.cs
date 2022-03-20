namespace KeyTransfer.Common.Extensions;

public static class ByteArrayExtensions
{
    public static byte[] Concatenate(this byte[] value, byte[] anotherArray)
    {
        var result = new byte[value.Length + anotherArray.Length];

        Buffer.BlockCopy(
            src: value,
            srcOffset: 0,
            dst: result,
            dstOffset: 0,
            count: value.Length);

        Buffer.BlockCopy(
            src: anotherArray,
            srcOffset: 0,
            dst: result,
            dstOffset: value.Length,
            count: anotherArray.Length);

        return result;
    }

    public static byte[] Subarray(this byte[] value, int index, int size)
    {
        var result = new byte[size];

        Buffer.BlockCopy(value, index, result, 0, size);

        return result;
    }

    public static string AsString(this byte[] value)
    {
        return Convert.ToHexString(value).ToLower();
    }

    /// <summary>Compares two <see cref="byte"/> arrays.</summary>
    /// <param name="value">This <see cref="byte"/> array.</param>
    /// <param name="anotherArray">
    /// <see cref="byte"/> array to compare against.
    /// </param>
    /// <returns>True if two arrays are equal.</returns>
    public static bool IsEqualTo(this byte[] value, byte[] anotherArray)
    {
        var length = value.Length;

        if (length != anotherArray.Length)
            return false;

        int result = 0;

        // This way it's constant time for a given length.
        for (int i = 0; i < length; i++)
            result |= value[i] ^ anotherArray[i];

        return result == 0;
    }
}

