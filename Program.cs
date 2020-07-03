using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json;

// Josh Kraines, COPADS project 3
namespace Messenger
{
    using PrimeGen;

    // represents a key with 1 associated email address ( i.e. public keys ) 
    public class Key
    {
        public string email { get; set; }
        public string key { get; set; }
    }

    // represents a key that can take a list of emails, this is only used for private keys
    public class PrivateKey
    {
        public string[] email { get; set; }
        public string key { get; set; }
    }

    // represents a message, either to be sent or recieved
    public class Message
    {
        public string email { get; set; }
        public string content { get; set; }
    }
    
    // contains message processing logic. Allows users to generate and upload RSA encryption keys which can then be used
    // by others to encrypt a message that can be read only by the person whose encryption key had been used.
    class Messenger
    {
        // base endpoint for all our requests
        private const string uri = "http://kayrun.cs.rit.edu:5000";

        // controls main logic, processes arguments and redirects to appropriate functions
        static void Main(string[] args)
        {
            var messenger = new Messenger();

            if (args.Length == 0)
            {
                Console.WriteLine("Invalid number of arguments!");
                Environment.Exit(1);
            }
            // determine which function the user wants to execute
            switch (args[0])
            {
                case "keyGen":
                    if (args.Length < 2)
                    {
                        Console.WriteLine("Need to specify a key size!");
                        Environment.Exit(1);
                    }
                    messenger.keyGen(Int32.Parse(args[1]));
                    break;
                case "sendKey":
                    if (args.Length < 2)
                    {
                        Console.WriteLine("Need to specify an email!");
                        Environment.Exit(1);
                    }
                    messenger.sendKey(args[1]);
                    break;
                case "getKey":
                    if (args.Length < 2)
                    {
                        Console.WriteLine("Need to specify an email!");
                        Environment.Exit(1);
                    }
                    messenger.getKey(args[1]);
                    break;
                case "sendMsg":
                    if (args.Length < 3)
                    {
                        Console.WriteLine("Need to specify an email and a message!");
                        Environment.Exit(1);
                    }
                    messenger.sendMsg(args[1], args[2]);
                    break;
                case "getMsg":
                    if (args.Length < 2)
                    {
                        Console.WriteLine("Need to specify an email!");
                        Environment.Exit(1);
                    }
                    messenger.getMsg(args[1]);
                    break;
                default:
                    Console.WriteLine("Invalid function specified!");
                    break;
            }
        }

        // we will generate both the public and private keys in this function and store them on the disk
        // with the names 'public.key' and 'private.key'
        void keyGen(int bits)
        {
            // generate bitlengths for p & q
            var rand = new Random();
            var half = bits / 2;
            var margin = (int)Math.Round(half * 0.1);
            var pLength = rand.Next( half - margin, half + margin );
            var qLength = bits - pLength;

            // generate p, q, & E
            var primeGen = new PrimeGenerator();
            var p = primeGen.parallelizer(pLength, 1);
            var q = primeGen.parallelizer(qLength, 1);
            var e = (BigInteger) 65537;

            // calculate N, r, D
            var n = p * q;
            var r = (p - 1) * (q - 1);
            var d = modInverse(e, r);
            
            // convert BigInts to Byte Arrays and make a byte Array representing the length of each
            var eByteArray = e.ToByteArray();
            var eBytesToRead = BitConverter.GetBytes(eByteArray.Length);
            
            var nByteArray = n.ToByteArray();
            var nBytesToRead = BitConverter.GetBytes(nByteArray.Length);
            
            var dByteArray = d.ToByteArray();
            var dBytesToRead = BitConverter.GetBytes(dByteArray.Length);

            // computers bad and endianness needs to be checked on a system to system basis
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(eBytesToRead);
                Array.Reverse(nBytesToRead);
                Array.Reverse(dBytesToRead);
            }
            
            // build strings & base64 encode them
            var publicKey = eBytesToRead.Concat(eByteArray).Concat(nBytesToRead).Concat(nByteArray).ToArray();
            var privateKey = dBytesToRead.Concat(dByteArray).Concat(nBytesToRead).Concat(nByteArray).ToArray();

            var publicBase64 = Convert.ToBase64String(publicKey);
            var privateBase64 = Convert.ToBase64String(privateKey);
            
            // build json
            var publicKeyObj = new Key();
            publicKeyObj.key = publicBase64;
            publicKeyObj.email = "";

            var privateKeyObj = new PrivateKey();
            privateKeyObj.key = privateBase64;
            privateKeyObj.email = new string[0];
            
            var publicKeyJson = JsonSerializer.Serialize(publicKeyObj);
            var privateKeyJson = JsonSerializer.Serialize(privateKeyObj);

            // save in working directory
            var pathPublic = Directory.GetCurrentDirectory() + "\\public.key";
            var pathPrivate = Directory.GetCurrentDirectory() + "\\private.key";

            try
            {
                using (var fileStream = new StreamWriter(pathPublic))
                {
                    fileStream.WriteLine(publicKeyJson);
                }

                using (var fileStream = new StreamWriter(pathPrivate))
                {
                    fileStream.WriteLine(privateKeyJson);
                }
            }
            catch (IOException)
            {
                Console.WriteLine("Could not write key files!");
                Environment.Exit(1);
            }

            Console.WriteLine("Successfully created public & private key");
        }
        
        // code from professor, calculates mod inverse. a = E, n = r
        static BigInteger modInverse(BigInteger a, BigInteger n)
        {
            BigInteger i = n, v = 0, d = 1;
            while (a>0) {
                BigInteger t = i/a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t*x;
                v = x;
            }
            v %= n;
            if (v<0) v = (v+n)%n;
            return v;
        }

        // uploads public key to server under the 'email' passed in, updates private key on this machine with 'email'
        void sendKey(string email)
        {
            var oldJson = "";
            try
            {
                oldJson = File.ReadAllText(Directory.GetCurrentDirectory() + "\\public.key");
            }
            catch (FileNotFoundException)
            {
                Console.WriteLine("You are trying to send a key that does not exist!");
                Environment.Exit(1);
            }

            var pk = JsonSerializer.Deserialize<Key>(oldJson);
            pk.email = email;
            var newJson = JsonSerializer.Serialize(pk);

            using (var client = new HttpClient())
            {
                var uriFull = uri + "/Key/" + email;
                var content = new StringContent(newJson, Encoding.UTF8, "application/json");
                var response = client.PutAsync(uriFull, content).Result;
                
                // if query executed successfully, process the response data
                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine("Key Saved");
                }
                else
                {
                    Console.WriteLine("Query failed: " + response.ReasonPhrase);
                    Environment.Exit(1);
                }
            }

            // key was placed correctly, so update private.key with associated email
            var oldPrivate = File.ReadAllText(Directory.GetCurrentDirectory() + "\\private.key");
            var keyObj = JsonSerializer.Deserialize<PrivateKey>(oldPrivate);
            var addresses = new List<string>();
            foreach (var addr in keyObj.email)
            {
                addresses.Add(addr);
            }
            addresses.Add(email);
            keyObj.email = addresses.ToArray();

            var newPk = JsonSerializer.Serialize(keyObj);
            
            using (var fileStream = new StreamWriter(Directory.GetCurrentDirectory() + "\\private.key"))
            {
                try
                {
                    fileStream.WriteLine(newPk);
                }
                catch (IOException)
                {
                    Console.WriteLine("Could not edit private.key!");
                    Environment.Exit(1);
                }
            }
            
        }

        // gets key off server that is associated with the given email
        void getKey(string email)
        {
            var jsonResult = "";
            
            // retrieve the key by sending a GET request to the /Key/[email] endpoint
            using (var client = new HttpClient())
            {
                client.BaseAddress = new Uri(uri);
                var response = client.GetAsync("/Key/" + email).Result;

                // if query executed successfully, process the response data
                if (response.StatusCode == HttpStatusCode.OK)
                {
                    jsonResult = response.Content.ReadAsStringAsync().Result;
                    // Console.WriteLine("Grabbed key for " + email);
                }
                else if (response.StatusCode == HttpStatusCode.NoContent)
                {
                    Console.WriteLine("Could not find key for: " + email);
                    Environment.Exit(1);
                }
                else
                {
                    Console.WriteLine("Query unsuccessful: " + response.ReasonPhrase);
                    Environment.Exit(1);
                }
            }
            
            // store key in file on disk
            var key = JsonSerializer.Deserialize<Key>(jsonResult);
            
            var pathToKey = Directory.GetCurrentDirectory() + "\\" + key.email + ".key";
            
            using (var fileStream = new StreamWriter(pathToKey))
            {
                fileStream.WriteLine(jsonResult);
            }
        }

        // finds key on local machine that corresponds to the 'email' param, then encrypts using that public key.
        // finally we base64 encode the message and pass it on to the server
        void sendMsg(string email, string msg)
        {
            // look for key
            var keyPath = Directory.GetCurrentDirectory() + "\\" + email + ".key";
            
            // get key and deserialize
            var keyJson = "";
            try
            {
                keyJson = File.ReadAllText(keyPath);
            }
            catch (FileNotFoundException)
            {
                Console.WriteLine("Key does not exist for " + email);
                Environment.Exit(1);
            }
            catch (IOException)
            {
                Console.WriteLine("Could not access key for " + email + "!");
                Environment.Exit(1);
            }

            var keyObj = JsonSerializer.Deserialize<Key>(keyJson);

            // decode key
            var key = keyObj.key;
            var bytes = Convert.FromBase64String(key);
            
            // get # of bytes for 1st value 'e'
            var first4 = new byte[4];
            for (var i = 0; i < 4; i++)
            {
                first4[i] = bytes[i];
            }
            // reverse if necessary due to endianness
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(first4);
            }
            var eLen = new BigInteger(first4);
            
            // read bytes for 'e', and convert to BigInt
            var eBytes = new byte[(int)eLen];
            for (var i = 0; i < eLen; i++)
            {
                eBytes[i] = bytes[i + 4];
            }
            var eVal = new BigInteger(eBytes);

            // get # of bytes for 2nd value 'n'
            var second4 = new byte[4];
            for (var i = 0; i < 4; i++)
            {
                second4[i] = bytes[i + 4 + (int)eLen];
            }
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(second4);
            }
            var rLen = new BigInteger(second4);
            
            // read bytes for 'n' and convert to BigInt
            var rBytes = new byte[(int) rLen];
            for (var i = 0; i < rLen; i++)
            {
                rBytes[i] = bytes[8 + (int)eLen + i];
            }
            var rVal = new BigInteger(rBytes);

            // encode message
            var msgBigInt = new BigInteger(Encoding.ASCII.GetBytes(msg));
            var msgModPow = BigInteger.ModPow(msgBigInt, eVal, rVal);
            var msgBase64 = Convert.ToBase64String(msgModPow.ToByteArray());
            var msgObj = new Message();
            msgObj.email = email;
            msgObj.content = msgBase64;
            var jsonMsg = JsonSerializer.Serialize(msgObj);
            
            // send message
            using (var client = new HttpClient())
            {
                var uriFull = uri + "/Message/" + email;
                var content = new StringContent(jsonMsg, Encoding.UTF8, "application/json");

                var response = client.PutAsync(uriFull, content).Result;

                // if query executed successfully, process the response data
                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine("Message Written");
                }
                else
                {
                    Console.WriteLine("Query failed: " + response.ReasonPhrase);
                    Environment.Exit(1);
                }
            }
        }

        // grabs message off server, checks if it was intended for this machine, then decrypts it using the
        // local private key, printing the result to the console
        void getMsg(string email)
        {
            // get the base64 encoded message from the server
            var jsonResult = "";
            using (var client = new HttpClient())
            {
                client.BaseAddress = new Uri(uri);
                var response = client.GetAsync("/Message/" + email).Result;

                // if query executed successfully, process the response data
                if (response.IsSuccessStatusCode)
                {
                    jsonResult = response.Content.ReadAsStringAsync().Result;
                }
                else
                {
                    Console.WriteLine("Query failed: " + response.ReasonPhrase);
                    Environment.Exit(1);
                }
            }
            // check that the message was intended for me, exit if not
            var pkJson = "";
            try
            {
                pkJson = File.ReadAllText(Directory.GetCurrentDirectory() + "\\private.key");
            }
            catch (FileNotFoundException)
            {
                Console.WriteLine("Could not find private key!");
                Environment.Exit(1);
            }
            catch (IOException)
            {
                Console.WriteLine("Could not access private key!");
                Environment.Exit(1);
            }

            var pkObj = JsonSerializer.Deserialize<PrivateKey>(pkJson);
            var msgObj = JsonSerializer.Deserialize<Message>(jsonResult);

            var contains = false;
            foreach (var addr in pkObj.email)
            {
                if (addr == msgObj.email)
                {
                    contains = true;
                }
            }
            if (!contains)
            {
                Console.WriteLine("Message is not for you!");
                Environment.Exit(1);
            }

            // decode my private key
            var key = pkObj.key;
            var bytes = Convert.FromBase64String(key);
            
            // get # of bytes for 1st value 'd'
            var first4 = new byte[4];
            for (var i = 0; i < 4; i++)
            {
                first4[i] = bytes[i];
            }
            // reverse if necessary due to endianness
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(first4);
            }
            var dLen = new BigInteger(first4);
            
            // read bytes for 'd', and convert to BigInt
            var dBytes = new byte[(int)dLen];
            for (var i = 0; i < dLen; i++)
            {
                dBytes[i] = bytes[i + 4];
            }
            var dVal = new BigInteger(dBytes);

            // get # of bytes for 2nd value 'n'
            var second4 = new byte[4];
            for (var i = 0; i < 4; i++)
            {
                second4[i] = bytes[i + 4 + (int)dLen];
            }
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(second4);
            }
            var rLen = new BigInteger(second4);
            
            // read bytes for 'n' and convert to BigInt
            var rBytes = new byte[(int) rLen];
            for (var i = 0; i < rLen; i++)
            {
                rBytes[i] = bytes[8 + (int)dLen + i];
            }
            var rVal = new BigInteger(rBytes);
            
            // decode message using private key, then print
            var msgBytes = Convert.FromBase64String(msgObj.content);
            var encodedBigInt = new BigInteger(msgBytes);
            var decodedBigInt = BigInteger.ModPow(encodedBigInt, dVal, rVal);
            var decodedBytes = decodedBigInt.ToByteArray();
            var decodedMsg = Encoding.ASCII.GetString(decodedBytes, 0, decodedBytes.Length);
            Console.WriteLine(decodedMsg);
        }
    }
}

// from project 2, source for generating prime numbers, not all is used, since we only needed the parallel functionality
namespace PrimeGen
{
    using PrimeTest;
    // Custom exception to break us out of the parallel.For()
    public class CountReachedException : Exception
    {
        public CountReachedException() : base() { }
        public CountReachedException(string message) : base(message) { }
        public CountReachedException(string message, System.Exception inner) : base(message, inner) { }

        // A constructor is needed for serialization when an
        // exception propagates from a remoting server to the client. 
        protected CountReachedException(System.Runtime.Serialization.SerializationInfo info,
            System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }

    class PrimeGenerator
    {
        // print a usage message to console
        void PrintUsage()
        {
            Console.WriteLine("Usage: dotnet run <bits> <count>:");
            Console.WriteLine("    - bits - the number of bits of the prime number, this must be a");
            Console.WriteLine("      multiple of 8, and at least 32 bits");
            Console.WriteLine("    - count - the number of prime numbers to generate defaults to 1");
        }

        // method to spawn threads that will generate prime numbers and test for primality
        // params:
        //    int bits: number of bits each generated integer should be
        //    int count: number of primes we want printed
        public BigInteger parallelizer( int bits, int count )
        {

            // lock object to be used in the critical section of the parallel for loop
            var primeLock = new Object();
            
            var numPrimes = 0;
            var numbytes = bits / 8;
            var rng = new RNGCryptoServiceProvider();

            var bigInt = new BigInteger();

            try
            {
                // loop will spawn threads that will create a biginteger, test primality, and process result
                Parallel.For(0, Int32.MaxValue, i =>
                {
                    // create ByteArray based on number of bits provided in command line
                    var byteArr = new Byte[numbytes];
                    rng.GetBytes(byteArr);
                    var bi = new BigInteger(byteArr);
                    
                    // if the big integer is (probably) prime, handle it
                    if (bi.IsProbablyPrime())
                    {
                        // enter lock block
                        lock (primeLock)
                        {
                            bigInt = bi;
                            if (numPrimes < count)
                            {
                                // increment number of primes, and print the number
                                numPrimes++;
                                // if we have found the correct number of primes, throw exception that will act as a break
                                if (numPrimes == count)
                                {
                                    throw new CountReachedException();
                                }
                            }
                            
                        }
                    }
                });
            }
            // catch our exceptions, so program doesn't crash
            catch (AggregateException)
            {
            }
            catch (CountReachedException)
            {
            }
            return bigInt;
        }

        BigInteger sequential(int bits, int count)
        {
            var numPrimes = 0;
            var numbytes = bits / 8;
            var rng = new RNGCryptoServiceProvider();
            
            var bigInt = new BigInteger();
            
            while (numPrimes < count)
            {
                var byteArr = new Byte[numbytes];
                rng.GetBytes(byteArr);
                var bi = new BigInteger(byteArr);

                if (bi.IsProbablyPrime())
                {
                    bigInt = bi;
                    numPrimes++;
                }
            }

            return bigInt;
        }
    }
}

// also from project 2, used to test primality of numbers
namespace PrimeTest
{
    // static class to hold extension method IsProbablyPrime()
    public static class PrimeTester
    {
        // method tests to see if a generated number is prime or not
        public static bool IsProbablyPrime( this BigInteger value, int witnesses = 10)
        {
            if (value <= 1) return false;

            if (witnesses <= 0) witnesses = 10;

            var d = value - 1;
            var s = 0;

            while (d % 2 == 0)
            {
                d /= 2;
                s += 1;
            }

            var bytes = new Byte[value.ToByteArray().LongLength];
            BigInteger a;

            for (int i = 0; i < witnesses; i++)
            {
                do
                {
                    var Gen = new Random();
                    Gen.NextBytes(bytes);
                    a = new BigInteger(bytes);
                } while (a < 2 || a >= value - 2);

                var x = BigInteger.ModPow(a, d, value);
                if (x == 1 || x == value - 1) continue;

                for (int r = 1; r < s; r++)
                {
                    x = BigInteger.ModPow(x,2,value);
                    if (x == 1) return false;
                    if (x == value - 1) break;
                }

                if (x != value - 1) return false;
            }
            return true;
        }
    }
}