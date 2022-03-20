using System.Security.Cryptography;
using Serilog;
using KeyTransfer.Common.Cryptography;
using KeyTransfer.Common.Extensions;

namespace KeyTransfer.NeedhamSchroeder.Models;

public class Participant
{
    public int Size { get; }

    public byte[] Nonce { get; private set; }

    public byte[] Id { get; private set; }

    public byte[] PrivateKey { get; }

    public byte[] SessionKey { get; private set; }

    public string Name { get; }

    private readonly ILogger _logger;

    public byte[] EncryptedPart { get; private set; }

    public Participant(
        ILogger logger, string name, int size = 16)
    {
        _logger = logger;

        Name = name;
        Size = size;
        EncryptedPart = new byte[size];
        SessionKey = new byte[size];

        // Generate values for participant.
        PrivateKey = RandomNumberGenerator.GetBytes(size);
        Nonce = RandomNumberGenerator.GetBytes(size);
        Id = RandomNumberGenerator.GetBytes(size);

        _logger.Information($"Created participant {Name} with" +
            $"\n\tId =        {Id.AsString()}" +
            $"\n\tPrivate key {PrivateKey.AsString()}" +
            $"\n\tNonce       {Nonce.AsString()}");
    }

    /// <summary>
    /// Third part of the protocol. Checks the first half of the message.
    /// </summary>
    /// <param name="encryptedMessage">Message from authority.</param>
    /// <returns>True if the check is successful.</returns>
    public bool CheckFirst(byte[] encryptedMessage)
    {
        _logger.Information($"Participant {Name}.CheckFirst:" +
            $"\n\tEncrypted message: {encryptedMessage.AsString()}");

        var message = Utilities.Decrypt(encryptedMessage, PrivateKey);

        _logger.Information($"Participant {Name}.CheckFirst:" +
            $"\n\tPlain message: {message.AsString()}");

        // Extract the part relating to another participant.
        EncryptedPart = message.Subarray(3 * Size, 2 * Size);

        _logger.Information($"Participant {Name}.CheckFirst:" +
            $"\n\tExtracted another participant message part: {EncryptedPart.AsString()}");

        SessionKey = message.Subarray(2 * Size, Size);

        _logger.Information($"Participant {Name}.CheckFirst:" +
            $"\n\tExtracted session key: {SessionKey.AsString()}");

        _logger.Information($"Participant {Name}.CheckFirst:" +
            $"\n\tComparing first message part {message.Subarray(0, Size).AsString()}" +
            $" to nonce {Nonce.AsString()}");

        return message.Subarray(0, Size).IsEqualTo(Nonce);
    }

    /// <summary>
    /// B checks and verifies the message, encrypts his nonce with session key
    /// and sends it to A.
    /// </summary>
    /// <param name="encryptedMessage"></param>
    /// <returns></returns>
    public byte[] EstablishKey(byte[] encryptedMessage)
    {
        _logger.Information($"Participant {Name}.EstablishKey:" +
            $"\n\tEncrypted message: {encryptedMessage.AsString()}");

        var message = Utilities.Decrypt(encryptedMessage, PrivateKey);

        _logger.Information($"Participant {Name}.EstablishKey:" +
            $"\n\tPlain message: {message.AsString()}");

        SessionKey = message.Subarray(0, Size);

        _logger.Information($"Participant {Name}.EstablishKey:" +
            $"\n\tExtracted session key: {SessionKey.AsString()}");

        var newMessage = Utilities.Encrypt(Nonce, SessionKey);

        _logger.Information($"Participant {Name}.EstablishKey:" +
            $"\n\tEncrypted nonce: {newMessage.AsString()}");

        return newMessage;
    }

    /// <summary>
    /// A recieves B's encrypted nonce and sends it back modified.
    /// </summary>
    /// <param name="encryptedMessage"></param>
    /// <returns></returns>
    public byte[] RespondWithModifiedNonce(byte[] encryptedMessage)
    {
        _logger.Information($"Participant {Name}.RespondWithModifiedNonce:" +
            $"\n\tEncrypted message: {encryptedMessage.AsString()}");

        var message = Utilities.Decrypt(encryptedMessage, SessionKey);

        _logger.Information($"Participant {Name}.RespondWithModifiedNonce:" +
            $"\n\tPlain message: {message.AsString()}");

        message[Size - 1] -= 1;

        _logger.Information($"Participant {Name}.RespondWithModifiedNonce:" +
            $"\n\tModified message: {message.AsString()}");

        var newMessage = Utilities.Encrypt(message, SessionKey);

        _logger.Information($"Participant {Name}.RespondWithModifiedNonce:" +
            $"\n\tEncrypted modified message: {newMessage.AsString()}");

        return newMessage;
    }

    /// <summary>B performs a final nonce check.</summary>
    /// <param name="encryptedMessage"></param>
    /// <returns></returns>
    public bool FinalCheck(byte[] encryptedMessage)
    {
        _logger.Information($"Participant {Name}.FinalCheck:" +
            $"\n\tEncrypted message: {encryptedMessage.AsString()}");

        var message = Utilities.Decrypt(encryptedMessage, SessionKey);

        _logger.Information($"Participant {Name}.FinalCheck:" +
            $"\n\tPlain message: {message.AsString()}");

        message[Size - 1] += 1;

        _logger.Information($"Participant {Name}.FinalCheck:" +
            $"\n\tComparing recieved incremented message {message.AsString()}" +
            $" to nonce {Nonce.AsString()}");

        return message.IsEqualTo(Nonce);
    }
}
