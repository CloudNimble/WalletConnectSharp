using System;
using System.Numerics;
using System.Threading.Tasks;
using Nethereum.ABI.FunctionEncoding.Attributes;
using Nethereum.Contracts;
using Nethereum.Hex.HexTypes;
using Nethereum.Web3;
using WalletConnectSharp.Core.Models;
using WalletConnectSharp.Desktop;
using WalletConnectSharp.NEthereum;

namespace WalletConnectSharp.Examples.Examples
{
    public class NEthereumSendTransactionExample : IExample
    {
        public static readonly string PROJECT_ID = "r84TUAUGeuaW5xbzrivZfxqmhAkuMUQl";
        
       
        [Function("deposit")]
        public class DepositFunction : FunctionMessage
        {
        }
        
        public string Name
        {
            get
            {
                return "nethereum_send_tx_example";
            }
        }

        public async Task Execute(string[] args)
        {
            var clientMeta = new ClientMeta()
            {
                Name = "WalletConnectSharp",
                Description = "An example that showcases how to use the WalletConnectSharp library",
                Icons = new []{ "https://app.warriders.com/favicon.ico" },
                URL = "https://app.warriders.com/"
            };

            var client = new WalletConnect(clientMeta);

            var rpcEndpoint = "https://eth-mainnet.alchemyapi.io/v2/" + PROJECT_ID;
            
            Console.WriteLine("Connect using the following URL");
            Console.WriteLine(client.URI);

            await client.Connect();
            
            Console.WriteLine("The account " + client.Accounts[0] + " has connected!");

            Console.WriteLine("Using RPC endpoint " + rpcEndpoint + " as the fallback RPC endpoint");

            //We use an External Account so we can sign transactions
            var web3 = client.BuildWeb3(new Uri(rpcEndpoint)).AsWalletAccount(true);

            var firstAccount = client.Accounts[0];
            var contractAddress = "0x9e0575D1e280D97b63A3021Eb335B6D48b0C6cc3";

            Console.WriteLine($"Signing test transactions from {firstAccount}");
            
            var depositHandler = web3.Eth.GetContractTransactionHandler<DepositFunction>();
            var deposit = new DepositFunction()
            {
                FromAddress = firstAccount,
                AmountToSend = 1
            };
            var signedTransaction = await depositHandler.SignTransactionAsync(contractAddress, deposit);
            
            Console.WriteLine($"Signed Transaction: {signedTransaction}");

            var result = await web3.Eth.Transactions.SendRawTransaction.SendRequestAsync(signedTransaction);
            Console.WriteLine($"Sent Transaction: {result}");

            await client.Disconnect();
        }
    }
}