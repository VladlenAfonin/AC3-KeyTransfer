using System.Security.Cryptography;
using Serilog;
using KeyTransfer.NeedhamSchroeder.Models;

var logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateLogger();

var a = new Participant(logger, "A");
var b = new Participant(logger, "B");
var t = new Authority(a.PrivateKey, b.PrivateKey, logger);

var resultA = a.CheckFirst(t.AcceptRequest(a.Id, b.Id, a.Nonce));

Console.WriteLine($"\nA: Nonce check: {resultA}.\n");

var encryptedNonceB = b.EstablishKey(a.EncryptedPart);

var encryptedModifiedNonceB = a.RespondWithModifiedNonce(encryptedNonceB);

// Enable to see invalid protocol execution.
//b.Nonce = RandomNumberGenerator.GetBytes(16);

var result = b.FinalCheck(encryptedModifiedNonceB);

Console.WriteLine($"\nB: Final nonce check {result}.");