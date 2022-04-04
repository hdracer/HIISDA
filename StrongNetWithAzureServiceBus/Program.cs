using Microsoft.ServiceBus;
using Microsoft.ServiceBus.Messaging;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using RestSharp;
using Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace StrongNetWithAzureServiceBus
{
    class Program
    {
        private static string OPERATION_REGISTER = "Register";
        private static string OPERATION_PROVIDETOKEN = "ProvideToken";
        private static string OPERATION_SENDDATA = "SendData";
        private static string OPERATION_LISTENDATA = "ListenData";
        private static string OPERATION_REVOKEPUBLISHER = "RevokePublisher";

        private static string REQUEST_FILE_NAME = "publisherTokenRequest.bin";
        private static string TOKEN_FILE_NAME = "serviceBusToken.bin";
        private static string SERVICE_BUS_URI = "sb://jwsdev.servicebus.windows.net/";
        private static string SENDER_POLICY_KEY_NAME = "Send";
        private static string LISTEN_POLICY_KEY_NAME = "Listen";
        private static string EVENT_HUB_NAME = "attested";
        private static string SNKSP = "JW Secure StrongNet Key Storage Provider";
        private static string ATTESTED_KEY_NAME = "AzureSbPublisherKey";
        private static string SNKSP_REG_KEY = @"SOFTWARE\JWSecure\StrongNetKsp";
        private static string SNSERVICEURI_REG_VALUE = "ServiceUri";
        private static string SNAPI_ROOT = "bhtmvc/api";

        static void Usage()
        {
            Console.WriteLine(
                "StrongNetWithAzureServiceBus.exe [ Command ] <Mandatory Parameter>");
            Console.WriteLine(
                " {0}", OPERATION_REGISTER);
            Console.WriteLine(
                " {0} <Azure SAS Policy Key for 'Send'>", OPERATION_PROVIDETOKEN);
            Console.WriteLine(
                " {0}", OPERATION_SENDDATA);
            Console.WriteLine(
                " {0} <Azure SAS Policy Key for 'Listen'> <Azure Storage Account Name> <Azure Storage Account Key>", OPERATION_LISTENDATA);
            Console.WriteLine(
                " {0} <Azure Namespace Manager Connection String> <Publisher ID>", OPERATION_REVOKEPUBLISHER);
        }

        static void Main(string[] args)
        {
            if (1 > args.Length)
            {
                Usage();
                return;
            }

            //
            // Perform the operation indicated by the first command line 
            // argument
            //

            if (0 == String.Compare(args[0], OPERATION_REGISTER, true))
            {
                //
                // Create an attested key
                //

                CngProvider cng = new CngProvider(SNKSP);
                CngKeyCreationParameters createParams = new CngKeyCreationParameters();
                createParams.Provider = cng;
                createParams.KeyCreationOptions = CngKeyCreationOptions.None;
                
                CngKey snKey = CngKey.Create(
                    CngAlgorithm2.Rsa, ATTESTED_KEY_NAME, createParams);

                //
                // Create a signed request message
                //

                StringBuilder pubKeyHashString = null;
                byte[] registrationRequest = CryptoHelper.CreateMessageWithPrependedSignatureAndPublicKey(
                    snKey, ref pubKeyHashString);

                //
                // Save the message
                //

                File.WriteAllBytes(REQUEST_FILE_NAME, registrationRequest);
                Console.WriteLine(
                    "Success: created registration request for publisher ID {0}", 
                    pubKeyHashString);
            }
            else if (0 == String.Compare(args[0], OPERATION_PROVIDETOKEN, true))
            {
                //
                // Receive the publisher token request
                //

                byte[] publisherTokenRequest = File.ReadAllBytes(REQUEST_FILE_NAME);

                //
                // Check the signature
                //

                StringBuilder publisherPubKeyHashString = null;
                if (false == CryptoHelper.VerifyMessageWithPrependedSignatureAndPublicKey(
                    publisherTokenRequest, ref publisherPubKeyHashString))
                {
                    return;
                }

                //
                // Read the location of the StrongNet Attestation Server 
                //

                RegistryKey snReg = 
                    Registry.LocalMachine.OpenSubKey(SNKSP_REG_KEY, false);
                string snAsUri = (string) snReg.GetValue(SNSERVICEURI_REG_VALUE);

                //
                // Confirm with the StrongNet Attestation Server that this is
                // an attested key
                //

                var client = new RestClient(String.Format(
                    "{0}/{1}", snAsUri, SNAPI_ROOT));
                var request = new RestRequest("MbkAttestation", Method.GET);
                request.AddQueryParameter(
                    "publicKeyHash", publisherPubKeyHashString.ToString());
                var response = client.Execute(request);
                if (System.Net.HttpStatusCode.OK != response.StatusCode || 
                    ResponseStatus.Completed != response.ResponseStatus)
                {
                    Console.WriteLine("Error: invalid publisher token request public key");
                    return;
                }

                //
                // Using Publisher Policy, acquire a shared access token, 
                // simulating registration. This would happen on the server in
                // order to limit exposure of the Azure access key.
                //
                // http://blogs.msdn.com/b/servicebus/archive/2015/02/02/event-hub-publisher-policy-in-action.aspx
                //
                // Timespan can be long if the registration server checks every
                // publisher with the attestation server, the event processor checks a 
                // signature on every message, publisher IDs can be revoked, and 
                // you trust the storage of your policy key. 
                //

                string token = SharedAccessSignatureTokenProvider.GetPublisherSharedAccessSignature(
                     new Uri(SERVICE_BUS_URI),
                     EVENT_HUB_NAME, 
                     publisherPubKeyHashString.ToString(), 
                     SENDER_POLICY_KEY_NAME,
                     args[1],
                     new TimeSpan(0, 30, 0));

                //
                // Send the token back to the requestor
                //

                File.WriteAllText(TOKEN_FILE_NAME, token);
                Console.WriteLine(
                    "Success: issued SAS policy '{0}' token to publisher ID {1}",
                    SENDER_POLICY_KEY_NAME,
                    publisherPubKeyHashString);
            }
            else if (0 == String.Compare(args[0], OPERATION_SENDDATA, true))
            {
                //
                // Read back a previously acquired Azure Service Bus publisher token
                //

                string token = File.ReadAllText(TOKEN_FILE_NAME);

                //
                // Open the attested key
                //

                CngProvider cng = new CngProvider(SNKSP);
                CngKey snKey = CngKey.Open(ATTESTED_KEY_NAME, cng);

                //
                // Create a new signed message to simulate what will get posted
                // by each sender to the event hub.
                //

                StringBuilder pubKeyHashString = null;
                byte[] signedMessage = CryptoHelper.CreateMessageWithPrependedSignatureAndPublicKey(
                    snKey, ref pubKeyHashString);

                //
                // Create a connection string for this policy and hub. Using 
                // the hash of the public key as the publisher identity 
                // allows correlation between security policy compliance and
                // sender data streams (but only if the processor verifies a 
                // message signature and that the public key is known to the 
                // attestation server). 
                //

                string connStr = ServiceBusConnectionStringBuilder.CreateUsingSharedAccessSignature(
                     new Uri(SERVICE_BUS_URI),
                     EVENT_HUB_NAME,
                     pubKeyHashString.ToString(),
                     token);

                //
                // Create a sender for this connection 
                //

                EventHubSender sender = EventHubSender.CreateFromConnectionString(connStr);

                //
                // Send the signed message
                //

                sender.Send(new EventData(signedMessage));
                Console.WriteLine("Success: message sent");
            }
            else if (0 == String.Compare(args[0], OPERATION_LISTENDATA, true))
            {
                //
                // Create a receiver for the indicated policy
                //

                string evtConnStr = ServiceBusConnectionStringBuilder.CreateUsingSharedAccessKey(
                    new Uri(SERVICE_BUS_URI), LISTEN_POLICY_KEY_NAME, args[1]);
                string storageConnStr = string.Format(
                    "DefaultEndpointsProtocol=https;AccountName={0};AccountKey={1}",
                    args[2],
                    args[3]);

                //
                // Use a variation of multi-threaded listener sample code from 
                // Microsoft. This saves us from having to know which partition 
                // the test message got queued to. 
                //
                // http://azure.microsoft.com/en-us/documentation/articles/service-bus-event-hubs-csharp-ephcs-getstarted/
                // 

                var processorHost = new EventProcessorHost(
                    Guid.NewGuid().ToString(),
                    EVENT_HUB_NAME,
                    EventHubConsumerGroup.DefaultGroupName,
                    evtConnStr,
                    storageConnStr);
                processorHost.RegisterEventProcessorAsync<SignatureCheckingEventProcessor>().Wait();

                Console.WriteLine("Receiving. Press enter key to stop worker.");
                Console.ReadLine();
            }
            else if (0 == String.Compare(args[0], OPERATION_REVOKEPUBLISHER, true))
            {
                //
                // Create a namespace manager from a connection string acquired
                // from the Azure management portal
                //

                var nsm = Microsoft.ServiceBus.NamespaceManager.CreateFromConnectionString(
                    args[1]);

                //
                // Revoke this publisher
                //

                nsm.RevokePublisher(EVENT_HUB_NAME, args[2]);

                //
                // List revoked publishers
                //
                
                var revokedPublishers = nsm.GetRevokedPublishers(EVENT_HUB_NAME);

                //
                // Restore this publisher
                //

                nsm.RestorePublisher(EVENT_HUB_NAME, args[2]);
            }
            else 
            {
                Usage();
            }
        }
    }

    class CryptoHelper
    {
        //
        // Check the signature of a message that is assumed to start with the
        // signature (from a 2048-bit RSA key), followed by the signer public
        // key in Crypto API format. 
        //
        // If you want to add any actual message payload after that, you'll 
        // probably want a more sophisticated approach for serialization.
        //

        public static bool VerifyMessageWithPrependedSignatureAndPublicKey(
            byte[] messageIn,
            ref StringBuilder pubKeyHashString)
        {
            // 
            // Assume signer is 2048 bits
            // 

            byte[] signatureBytes = new byte[256];
            if (messageIn.Length < signatureBytes.Length + 1)
            {
                Console.WriteLine("Error: invalid signed message length");
                return false;
            }
            byte[] publicKey = new byte[messageIn.Length - signatureBytes.Length];

            //
            // Copy out the signature
            //

            Array.Copy(
                messageIn,
                signatureBytes,
                signatureBytes.Length);

            //
            // Copy out the public key
            //

            Array.Copy(
                messageIn,
                signatureBytes.Length,
                publicKey,
                0,
                publicKey.Length);

            //
            // Hash the public key
            //

            SHA1 sha = new SHA1CryptoServiceProvider();
            byte[] pubKeyHash = sha.ComputeHash(
                publicKey);

            //
            // Verify the signature
            //

            CngKey publisherPublic = CngKey.Import(
                publicKey,
                CngKeyBlobFormat.GenericPublicBlob);
            Security.Cryptography.RSACng rsaCng = new Security.Cryptography.RSACng(publisherPublic);
            if (false == rsaCng.VerifyHash(
                pubKeyHash,
                signatureBytes,
                CngAlgorithm.Sha1))
            {
                Console.WriteLine("Error: invalid request signature");
                return false;
            }

            //
            // Encode the public key hash to string
            //

            SoapHexBinary shb = new SoapHexBinary(pubKeyHash);
            pubKeyHashString = new StringBuilder(shb.ToString());

            return true;
        }

        public static byte[] CreateMessageWithPrependedSignatureAndPublicKey(
            CngKey snKey,
            ref StringBuilder pubKeyHashString)
        {
            byte[] signedMessage = null;

            //
            // Get the public key
            //

            byte[] snKeyPublic = snKey.Export(CngKeyBlobFormat.GenericPublicBlob);

            //
            // Hash the public key
            //

            SHA1 sha = new SHA1CryptoServiceProvider();
            byte[] snKeyHash = sha.ComputeHash(snKeyPublic);

            //
            // Sign the hash
            //

            SafeNCryptKeyHandle keyHandle = snKey.Handle;
            byte[] sig = NCryptNative.SignHashPkcs1(keyHandle, snKeyHash, "SHA1");

            //
            // Compose the message
            //

            signedMessage = new byte[snKeyPublic.Length + sig.Length];
            sig.CopyTo(signedMessage, 0);
            snKeyPublic.CopyTo(signedMessage, sig.Length);

            //
            // Encode the public key hash to string
            //

            SoapHexBinary shb = new SoapHexBinary(snKeyHash);
            pubKeyHashString = new StringBuilder(shb.ToString());

            return signedMessage;
        }
    }

    class SignatureCheckingEventProcessor : IEventProcessor
    {
        async Task IEventProcessor.CloseAsync(PartitionContext context, CloseReason reason)
        {
            if (reason == CloseReason.Shutdown)
            {
                await context.CheckpointAsync();
            }
        }

        Task IEventProcessor.OpenAsync(PartitionContext context)
        {
            return Task.FromResult<object>(null);
        }

        async Task IEventProcessor.ProcessEventsAsync(PartitionContext context, IEnumerable<EventData> messages)
        {
            foreach (EventData eventData in messages)
            {
                byte[] message = eventData.GetBytes();

                Console.WriteLine(string.Format(
                    "Message received. Partition: {0}, Publisher: {1}, Size: {2}",
                    context.Lease.PartitionId, 
                    eventData.SystemProperties[EventDataSystemPropertyNames.Publisher],
                    message.Length));

                //
                // Check the signature 
                //

                StringBuilder pubKeyHashString = null;
                if (false == (CryptoHelper.VerifyMessageWithPrependedSignatureAndPublicKey(
                    message, ref pubKeyHashString)))
                {
                    Console.WriteLine("Error: invalid published message");
                    break;
                }

                //
                // Check the publisher ID
                //

                if (0 != String.Compare(
                    pubKeyHashString.ToString(),
                    (string) eventData.SystemProperties[EventDataSystemPropertyNames.Publisher],
                    true))
                {
                    Console.WriteLine("Error: mismatched publisher ID");
                    break;
                }

                //
                // Report success
                //

                Console.WriteLine("Success: valid message received");
            }

            await context.CheckpointAsync();
        }
    }
}

