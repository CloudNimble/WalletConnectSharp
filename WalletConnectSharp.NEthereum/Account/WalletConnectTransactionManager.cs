using System.Linq;
using System.Numerics;
using System.Threading.Tasks;
using Nethereum.Hex.HexConvertors.Extensions;
using Nethereum.Hex.HexTypes;
using Nethereum.JsonRpc.Client;
using Nethereum.RLP;
using Nethereum.RPC.Accounts;
using Nethereum.RPC.Eth.DTOs;
using Nethereum.RPC.TransactionManagers;
using Nethereum.Util;
using WalletConnectSharp.Core;
using WalletConnectSharp.Core.Models;
using WalletConnectSharp.Core.Models.Ethereum;
using WalletConnectSharp.NEthereum.Model;

namespace WalletConnectSharp.NEthereum.Account
{
    public class WalletConnectTransactionManager : TransactionManager
    {

        private WalletConnectSession _session;
        private IAccount _account;
        private bool allowEthSign;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="client"></param>
        /// <param name="session"></param>
        /// <param name="account"></param>
        /// <param name="allowEthSign"></param>
        public WalletConnectTransactionManager(IClient client, WalletConnectSession session, IAccount account, bool allowEthSign) : base(client)
        {
            _session = session;
            _account = account;
            this.allowEthSign = allowEthSign;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="transaction"></param>
        /// <returns></returns>
        public override async Task<string> SignTransactionAsync(TransactionInput transaction)
        {
            //RWM: The ChainId needs to be added to the transaction to prevent replay attacks.
            transaction.ChainId = new HexBigInteger(new BigInteger(_session.ChainId));

            try
            {
                var request = new NEthSignTransaction(transaction);
                var response = await _session.Send<NEthSignTransaction, EthResponse>(request);
                return response.Result;
            }
            catch (WalletException e)
            {
                if (!e.Message.ToLower().Contains("method not supported") || !allowEthSign) throw;
                
                if (transaction.Nonce == null)
                {
                    var nextNonce = await _account.NonceService.GetNextNonceAsync();
                    transaction.Nonce = nextNonce;
                }

                if (transaction.Gas == null)
                {
                    var estimatedGas = await EstimateGasAsync(transaction);
                    transaction.Gas = estimatedGas;
                }

                if (transaction.GasPrice == null)
                {
                    var estimatedGasPrice = await GetGasPriceAsync(transaction);
                    transaction.GasPrice = estimatedGasPrice;
                }

                byte[] nonce = transaction.Nonce.Value.ToBytesForRLPEncoding();
                byte[] gasPrice = transaction.GasPrice.Value.ToBytesForRLPEncoding();
                byte[] gasLimit = transaction.Gas.Value.ToBytesForRLPEncoding();
                byte[] to = HexByteConvertorExtensions.HexToByteArray(transaction.To);
                byte[] amount = transaction.Value.Value.ToBytesForRLPEncoding();
                byte[] data = HexByteConvertorExtensions.HexToByteArray(transaction.Data);
                byte[] chainId = transaction.ChainId.Value.ToBytesForRLPEncoding();

                byte[] rawData = RLP.EncodeList(new[]
                {
                    nonce,
                    gasPrice,
                    gasLimit,
                    to,
                    amount,
                    data,
                    chainId
                });

                var hash = "0x" + Sha3Keccack.Current.CalculateHash(rawData).ToHex();

                var request = new EthSign(_account.Address, hash);

                var response = await _session.Send<EthSign, EthResponse>(request);

                return response.Result;

            }
        }

    }

}