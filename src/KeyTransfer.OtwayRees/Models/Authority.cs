using System.Security.Cryptography;
using Serilog;
using KeyTransfer.Common.Cryptography;
using KeyTransfer.Common.Extensions;

namespace KeyTransfer.OtwayRees.Models;

public class Authority
{
    public byte[] SessionKey { get; private set; }

    private readonly byte[] _keyAt;
    private readonly byte[] _keyBt;

    private readonly ILogger _logger;

    public Authority(byte[] keyAt, byte[] keyBt, ILogger logger)
    {
        SessionKey = new byte[keyAt.Length];

        _keyAt = keyAt;
        _keyBt = keyBt;
        _logger = logger;
    }

    public byte[] AcceptRequest(byte[] IdA, byte[] IdB, byte[] NonceA)
    {
        SessionKey = RandomNumberGenerator.GetBytes(_keyAt.Length);

        _logger.Information($"Authority.AcceptRequest:" +
            $"\n\tSession key: {SessionKey.AsString()}");

        byte[] plainMessage = NonceA
            .Concatenate(IdB)
            .Concatenate(SessionKey)
            .Concatenate(Utilities.Encrypt(
                SessionKey.Concatenate(IdA), _keyBt));

        _logger.Information($"Authority.AcceptRequest:" +
            $"\n\tPlain message: {plainMessage.AsString()}");

        byte[] result = Utilities.Encrypt(plainMessage, _keyAt);

        _logger.Information($"Authority.AcceptRequest:" +
            $"\n\tEncrypted message: {result.AsString()}");

        return result;
    }
}

