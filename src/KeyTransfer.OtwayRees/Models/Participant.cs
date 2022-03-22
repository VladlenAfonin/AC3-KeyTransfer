using System.Security.Cryptography;
using Serilog;
using KeyTransfer.Common.Cryptography;
using KeyTransfer.Common.Extensions;

namespace KeyTransfer.OtwayRees.Models;

public class Participant
{
    public byte[] SessionId { get; }

    public byte[] SessionKey { get; private set; }

    public byte[] PrivateKey { get; }

    public byte[] Id { get; }

    public byte[] Nonce { get; set; }

    public string Name { get; }

    public int Size { get; }

    private readonly ILogger _logger;

    /// <summary>Initialize a new <see cref="Participant" />.</summary>
    /// <param name="sessionId"></param>
    /// <param name="name"></param>
    /// <param name="size"></param>
    public Participant(ILogger logger, byte[] sessionId, string name, int size = 16)
    {
        _logger = logger;

        SessionId = sessionId;
        SessionKey = new byte[size];
        Name = name;
        Size = size;

        Id = RandomNumberGenerator.GetBytes(size);
        PrivateKey = RandomNumberGenerator.GetBytes(size);
        Nonce = RandomNumberGenerator.GetBytes(size);

        _logger.Information($"Participant {Name} created." +
            $"\n\tId:         {Id.AsString()}" +
            $"\n\tPrivateKey: {PrivateKey.AsString()}" +
            $"\n\tNonce:      {Nonce.AsString()}");
    }

    /// <summary>
    /// First protocol step. Generate and return initial message.
    /// </summary>
    /// <param name="anotherId">Id of another participant.</param>
    /// <returns>Initial protocol message.</returns>
    public (byte[], byte[], byte[], byte[]) SendInitialMessage(byte[] anotherId)
    {
        var message = Nonce
            .Concatenate(SessionId)
            .Concatenate(Id)
            .Concatenate(anotherId);

        var encryptedMessage = Utilities.Encrypt(message, PrivateKey);

        return (SessionId, Id, anotherId, encryptedMessage);
    }

    /// <summary>
    /// Append this <see cref="Participant"/>'s message to the end of initial
    /// message.
    /// </summary>
    /// <param name="message">Initial protocol message.</param>
    /// <returns>Appended initial message.</returns>
    public (byte[], byte[], byte[], byte[], byte[]) AppendToInitialMessage((
        byte[] sessionId,
        byte[] IdA,
        byte[] IdB,
        byte[] encryptedMessage) message)
    {
        if (!message.IdB.IsEqualTo(Id))
        {
            _logger.Error($"Participant {Name}.AppendToInitialMessage:" +
                $"\n\tReceived invalid id.");

            throw new InvalidOperationException($"Received invalid id.");
        }

        var appndix = Nonce
            .Concatenate(SessionId)
            .Concatenate(message.IdA)
            .Concatenate(Id);

        var encryptedAppendix = Utilities.Encrypt(appndix, PrivateKey);

        return (
            message.sessionId,
            message.IdA,
            message.IdB,
            message.encryptedMessage,
            encryptedAppendix);
    }

    /// <summary>
    /// Check message from authority and return other participant's part.
    /// </summary>
    /// <param name="message">Message form authority.</param>
    /// <returns>Part of the message for another participant.</returns>
    public byte[] GetAndPass((
        byte[] encryptedMessageA,
        byte[] encryptedMessageB) message)
    {
        var messageB = Utilities.Decrypt(message.encryptedMessageB, PrivateKey);

        (var nonce, SessionKey) = (messageB.Subarray(0, Size), messageB.Subarray(Size, Size));

        _logger.Information($"Participant {Name}.GetAndPass:" +
            $"\n\tComparing nonce received {nonce.AsString()} to current nonce {Nonce.AsString()}");

        _logger.Information($"Participant {Name}.GetAndPass:" +
            $"\n\tSession key received {SessionKey.AsString()}");

        if (!nonce.IsEqualTo(Nonce))
        {
            _logger.Error($"Participant {Name}.GetAndPass:" +
                $"\n\tReceived invalid nonce.");

            SessionKey = new byte[Size];
        }

        return message.encryptedMessageA;
    }

    /// <summary>
    /// Performs a final check making sure the key is established.
    /// </summary>
    /// <param name="encryptedMessage">
    /// Encrypted message with nonce and session key.
    /// </param>
    /// <returns>True if the check is successful.</returns>
    public bool PerformFinalCheck(byte[] encryptedMessage)
    {
        var message = Utilities.Decrypt(encryptedMessage, PrivateKey);

        (var nonce, SessionKey) = (message.Subarray(0, Size), message.Subarray(Size, Size));

        _logger.Information($"Participant {Name}.PerformFinalCheck:" +
            $"\n\tComparing nonce received {nonce.AsString()} to current nonce {Nonce.AsString()}");

        _logger.Information($"Participant {Name}.PerformFinalCheck:" +
            $"\n\tSession key received {SessionKey.AsString()}");

        if (!nonce.IsEqualTo(Nonce))
        {
            _logger.Error($"Participant {Name}.PerformFinalCheck:" +
                $"\n\tReceived invalid nonce.");

            SessionKey = new byte[Size];
        }

        return nonce.IsEqualTo(Nonce);
    }
}
