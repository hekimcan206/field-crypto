using FieldCrypto.DevKms;

var app = DevKmsApp.Build(args);
app.Logger.LogWarning("FieldCrypto DevKms is a development tool: master keys live in this process. Never use it for real data.");
await app.RunAsync();
