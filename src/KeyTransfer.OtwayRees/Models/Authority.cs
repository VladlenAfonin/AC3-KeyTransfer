using System.Security.Cryptography;
using Serilog;
using KeyTransfer.Common.Cryptography;
using KeyTransfer.Common.Extensions;

namespace KeyTransfer.OtwayRees.Models;

public class Authority
{
    public byte[] SessionId { get; }

    public int Size { get; }

    private readonly byte[] _keyAt;
    private readonly byte[] _keyBt;

    private readonly ILogger _logger;

    public Authority(ILogger logger, byte[] sessionId, byte[] keyA, byte[] keyB, int size = 16)
    {
        _logger = logger;

        _logger.Information($"Authority created.");

        Size = size;
        SessionId = sessionId;

        _keyAt = keyA;
        _keyBt = keyB;
    }

    public (byte[], byte[]) GenerateInitialResponse((
        byte[] sessionId,
        byte[] IdA,
        byte[] IdB,
        byte[] encryptedMessageA,
        byte[] encryptedMessageB) message)
    {
        // Generate a session key to be shared.
        var sessionKey = RandomNumberGenerator.GetBytes(Size);

        _logger.Information($"Authority.GenerateInitialResponse:" +
            $"\n\tSession key generated: {sessionKey.AsString()}");

        var messageA = Utilities.Decrypt(
            message.encryptedMessageA, _keyAt);
        var messageB = Utilities.Decrypt(
            message.encryptedMessageB, _keyBt);

        if (
            !messageA.Subarray(Size, Size).IsEqualTo(message.sessionId) ||
            !messageB.Subarray(Size, Size).IsEqualTo(message.sessionId))
        {
            _logger.Error($"Authority.GenerateInitialResponse:" +
                $"\n\tInvalid session id.");

            throw new InvalidOperationException($"Invalid session id.");
        }

        if (
            !messageA.Subarray(2 * Size, Size).IsEqualTo(message.IdA) ||
            !messageB.Subarray(2 * Size, Size).IsEqualTo(message.IdA))
        {
            _logger.Error($"Authority.GenerateInitialResponse:" +
                $"\n\tInvalid participant A id.");

            throw new InvalidOperationException($"Invalid participant A id.");
        }

        if (
            !messageA.Subarray(3 * Size, Size).IsEqualTo(message.IdB) ||
            !messageB.Subarray(3 * Size, Size).IsEqualTo(message.IdB))
        {
            _logger.Error($"Authority.GenerateInitialResponse:" +
                $"\n\tInvalid participant B id.");

            throw new InvalidOperationException($"Invalid participant B id.");
        }

        var nonceA = messageA.Subarray(0, Size);
        var nonceB = messageB.Subarray(0, Size);

        _logger.Information($"Authority.GenerateInitialResponse:" +
            $"\n\tNonces found. A: {nonceA.AsString()}, B: {nonceB.AsString()}");

        var newMessageA = Utilities.Encrypt(
            nonceA.Concatenate(sessionKey), _keyAt);
        var newMessageB = Utilities.Encrypt(
            nonceB.Concatenate(sessionKey), _keyBt);

        return (newMessageA, newMessageB);
    }
}
