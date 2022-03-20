using System.Security.Cryptography;
using Serilog;
using KeyTransfer.OtwayRees.Models;

var logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateLogger();

var sessionId = RandomNumberGenerator.GetBytes(16);

var a = new Participant(logger, sessionId, "A");
var b = new Participant(logger, sessionId, "B");
var t = new Authority(logger, sessionId, a.PrivateKey, b.PrivateKey);

var initialMessage = a.SendInitialMessage(b.Id);

var appendedMessage = b.AppendToInitialMessage(initialMessage);

var authorityResponse = t.GenerateInitialResponse(appendedMessage);

// Enable to see invalid protocol execution.
//b.Nonce = RandomNumberGenerator.GetBytes(16);

var fromBtoA = b.GetAndPass(authorityResponse);

var result = a.PerformFinalCheck(fromBtoA);

Console.WriteLine($"{result}.");