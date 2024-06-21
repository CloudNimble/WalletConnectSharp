using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json;
using WalletConnectSharp.Core.Events;
using WalletConnectSharp.Core.Models;
using WalletConnectSharp.Core.Network;

namespace WalletConnectSharp.Core
{

    /// <summary>
    /// Defines the core protocols for establishing a communication channel using a network transport such as HTTPS or WSS.
    /// </summary>
    public class WalletConnectProtocol : IDisposable
    {

        /// <summary>
        /// JSON RPC endpoints for signing.
        /// </summary>
        public static readonly string[] SigningMethods = new[]
        {
            "eth_sendTransaction",
            "eth_signTransaction",
            "eth_sign",
            "eth_signTypedData",
            "eth_signTypedData_v1",
            "eth_signTypedData_v2",
            "eth_signTypedData_v3",
            "eth_signTypedData_v4",
            "personal_sign",
        };

        /// <summary>
        /// An <see cref="EventDelegator"/> to provide custom implementation of the events defined by this protocol.
        /// </summary>
        public readonly EventDelegator Events;

        protected string Version = "1";
        protected string _bridgeUrl;
        protected string _key;
        protected byte[] _keyRaw;
        protected List<string> _activeTopics = new List<string>();

        /// <summary>
        /// An <see cref="EventHandler{WalletConnectProtocol}"/> that will be called when a connection is established.
        /// </summary>
        public event EventHandler<WalletConnectProtocol> OnTransportConnect;

        /// <summary>
        /// An <see cref="EventHandler{WalletConnectProtocol}"/> that will be called when a connection is closed.
        /// </summary>
        public event EventHandler<WalletConnectProtocol> OnTransportDisconnect;

        /// <summary>
        /// Indicates if a session has been connected.
        /// </summary>
        public bool SessionConnected { get; protected set; }

        /// <summary>
        /// Indicates if the current session is disconnected.
        /// </summary>
        public bool Disconnected { get; protected set; }

        /// <summary>
        /// Indicates if both the session is connected and a transport method is connected.
        /// </summary>
        public bool Connected
        {
            get
            {
                return SessionConnected && TransportConnected;
            }
        }

        /// <summary>
        /// Indicates that an attempt to connect is in progress.
        /// </summary>
        public bool Connecting { get; protected set; }

        /// <summary>
        /// Indicates if a network transport is connected.
        /// </summary>
        public bool TransportConnected
        {
            get
            {
                return Transport != null &&
                       Transport.Connected &&
                       Transport.URL.Replace("https://", "").Replace("wss://", "") == _bridgeUrl.Replace("https://", "").Replace("wss://", "");
            }
        }

        /// <summary>
        /// An <see cref="ITransport"/> instance for managing communication over a network channel.
        /// </summary>
        public ITransport Transport { get; private set; }

        /// <summary>
        /// An <see cref="ICipher"/> instance for encrypting and decrypting payloads.
        /// </summary>
        public ICipher Cipher { get; private set; }

        /// <summary>
        /// A <see cref="ClientMeta"/> describing the details of the host application.
        /// </summary>
        public ClientMeta DappMetadata { get; set; }

        /// <summary>
        /// A <see cref="ClientMeta"/> describing the details of the connected peer.
        /// </summary>
        public ClientMeta WalletMetadata { get; set; }

        /// <summary>
        /// A <see cref="ReadOnlyCollection{string}"/> of ActiveTopics.
        /// </summary>
        /// <remarks>
        /// @caldwell0414: Topics are a way of grouping specific messages that are moving over the network connection and provide a way to perform specific actions
        /// related to that communication.  WalletConnectSharp creates a topic for each connected client to ensure that communication can be directed specifically
        /// to that client and messages from that client have their own handling.
        /// </remarks>
        public ReadOnlyCollection<string> ActiveTopics
        {
            get
            {
                return _activeTopics.AsReadOnly();
            }
        }

        /// <summary>
        /// The PeerID value received when a network connection is established.
        /// </summary>
        public string PeerId
        {
            get;
            protected set;
        }


        /// <summary>
        /// Create a new <see cref="WalletConnectProtocol"/> using a <see cref="SavedSession"/>.
        /// </summary>
        /// <param name="savedSession">The SavedSession data to use. Cannot be null.</param>
        /// <param name="transport">The transport interface to use for sending/receiving messages, null will result in the default transport being used.</param>
        /// <param name="cipher">The cipher to use for encrypting and decrypting payload data, null will result in AESCipher being used.</param>
        /// <param name="eventDelegator">The EventDelegator class to use, null will result in the default being used.</param>
        /// <exception cref="ArgumentException">If a null SavedSession object was given.</exception>
        /// <remarks>This will effectively resume the session, as long as the session data is valid.</remarks>
        public WalletConnectProtocol(SavedSession savedSession, ITransport transport = null, ICipher cipher = null, EventDelegator eventDelegator = null)
        {
            if (savedSession == null)
                throw new ArgumentException("savedSession cannot be null");

            if (eventDelegator == null)
                eventDelegator = new EventDelegator();

            this.Events = eventDelegator;

            //TODO Do we need this for resuming?
            //_handshakeTopic = topicGuid.ToString();

            if (transport == null)
                transport = TransportFactory.Instance.BuildDefaultTransport(eventDelegator);

            this._bridgeUrl = savedSession.BridgeURL;
            this.Transport = transport;

            if (cipher == null)
                cipher = new AESCipher();

            this.Cipher = cipher;

            this._keyRaw = savedSession.KeyRaw;

            //Convert hex 
            this._key = savedSession.Key;

            this.PeerId = savedSession.PeerID;

            /*Transport.Open(this._bridgeUrl).ContinueWith(delegate(Task task)
            {
                Transport.Subscribe(savedSession.ClientID);
            });

            this.Connected = true;*/
        }

        /// <summary>
        /// Create a new <see cref="WalletConnectProtocol"/> and establish a new session.
        /// </summary>
        /// <param name="clientMeta">The metadata to send to the peer.</param>
        /// <param name="transport">The transport interface to use for sending/receiving messages, null will result in the default transport being used.</param>
        /// <param name="cipher">The cipher to use for encrypting and decrypting payload data, null will result in AESCipher being used.</param>
        /// <param name="chainId">The chainId this dApp is using.</param>
        /// <param name="bridgeUrl">The bridgeURL to use to communicate with the peer.</param>
        /// <param name="eventDelegator">The EventDelegator class to use, null will result in the default being used.</param>
        /// <exception cref="ArgumentException">If an invalid ClientMeta object was given.</exception>
        public WalletConnectProtocol(ITransport transport = null, ICipher cipher = null, EventDelegator eventDelegator = null)
        {
            if (eventDelegator == null)
                eventDelegator = new EventDelegator();

            this.Events = eventDelegator;

            if (transport == null)
                transport = TransportFactory.Instance.BuildDefaultTransport(eventDelegator);

            this.Transport = transport;

            if (cipher == null)
                cipher = new AESCipher();

            this.Cipher = cipher;
        }

        /// <summary>
        /// Attaches a <see cref="TransportOnMessageReceived"/> handler and opens a network connection.
        /// </summary>
        /// <returns></returns>
        protected async Task SetupTransport()
        {
            Transport.MessageReceived += TransportOnMessageReceived;

            await Transport.Open(this._bridgeUrl);

            //Debug.Log("[WalletConnect] Transport Opened");

            TriggerOnTransportConnect();
        }

        /// <summary>
        /// Disconnects a <see cref="TransportOnMessageReceived"/> handler and closes a network connection.
        /// </summary>
        /// <returns></returns>
        /// <remarks>
        /// Calls the <see cref="EventHandler{WalletConnectProtocol}"/> for OnTransportConnected if available.
        /// </remarks>
        protected async Task DisconnectTransport()
        {
            await Transport.Close();

            Transport.MessageReceived -= TransportOnMessageReceived;

            if (OnTransportDisconnect != null)
                OnTransportDisconnect(this, this);
        }

        /// <summary>
        /// Calls the <see cref="EventHandler{WalletConnectProtocol}"/> for OnTransportConnected if available.
        /// </summary>
        protected virtual void TriggerOnTransportConnect()
        {
            if (OnTransportConnect != null)
                OnTransportConnect(this, this);
        }

        /// <summary>
        /// Opens a network communication channel and monitors it for communication.
        /// </summary>
        /// <returns></returns>
        public virtual async Task Connect()
        {
            await SetupTransport();
        }

        /// <summary>
        /// Attaches to the active <see cref="ITransport"/> and listens for communication directed at a specific topic.
        /// </summary>
        /// <param name="topic">The topic to listen for on the <see cref="ITransport"/> instance.</param>
        /// <returns></returns>
        public async Task SubscribeAndListenToTopic(string topic)
        {
            await Transport.Subscribe(topic);

            ListenToTopic(topic);
        }

        /// <summary>
        /// Adds the specified topic to <see cref="ActiveTopics"/>.
        /// </summary>
        /// <param name="topic">The topic to listen for on the <see cref="ITransport"/> instance.</param>
        /// <returns></returns>
        public void ListenToTopic(string topic)
        {
            if (!_activeTopics.Contains(topic))
            {
                _activeTopics.Add(topic);
            }
        }

        /// <summary>
        /// Handles an incoming message from the <see cref="ITransport"/>.
        /// </summary>
        /// <param name="sender">Origination source for the event.</param>
        /// <param name="e">A <see cref="MessageReceivedEventArgs"/> instance providing details of the event.</param>
        private async void TransportOnMessageReceived(object sender, MessageReceivedEventArgs e)
        {
            var networkMessage = e.Message;

            if (!_activeTopics.Contains(networkMessage.Topic))
                return;

            var encryptedPayload = JsonConvert.DeserializeObject<EncryptedPayload>(networkMessage.Payload);

            var json = await Cipher.DecryptWithKey(_keyRaw, encryptedPayload);

            var response = JsonConvert.DeserializeObject<JsonRpcResponse>(json);

            bool wasResponse = false;
            if (response != null && response.Event != null)
                wasResponse = Events.Trigger(response.Event, json);

            if (!wasResponse)
            {
                var request = JsonConvert.DeserializeObject<JsonRpcRequest>(json);

                if (request != null && request.Method != null)
                    Events.Trigger(request.Method, json);
            }
        }

        /// <summary>
        /// Sends a <see cref="typeof{T}"/> request object over the network and listens for a <see cref="typeof{TR}"/> response.
        /// </summary>
        /// <typeparam name="T">Request payload type.</typeparam>
        /// <typeparam name="TR">Response payload type.</typeparam>
        /// <param name="requestObject">The payload to send.</param>
        /// <param name="requestId">Identifier for the request.</param>
        /// <param name="sendingTopic">Topic defining the channel on which the request should be sent.</param>
        /// <param name="forcePushNotification">Indicator if a force push should be sent.</param>
        /// <returns></returns>
        public async Task<TR> SendRequestAwaitResponse<T, TR>(T requestObject, object requestId, string sendingTopic = null, bool? forcePushNotification = null)
        {
            TaskCompletionSource<TR> response = new TaskCompletionSource<TR>(TaskCreationOptions.None);

            Events.ListenForGenericResponse<TR>(requestId, (sender, args) =>
            {
                response.SetResult(args.Response);
            });

            await SendRequest(requestObject, sendingTopic, forcePushNotification);

            return await response.Task;
        }

        /// <summary>
        /// Sends a <see cref="typeof{T}"/> request object over the network but does not wait for a response.
        /// </summary>
        /// <typeparam name="T">Request payload type.</typeparam>
        /// <param name="requestObject">The payload to send.</param>
        /// <param name="sendingTopic">Topic defining the channel on which the request should be sent.</param>
        /// <param name="forcePushNotification">Indicator if a force push should be sent.</param>
        /// <returns></returns>
        public async Task SendRequest<T>(T requestObject, string sendingTopic = null, bool? forcePushNotification = null)
        {
            bool silent;
            if (forcePushNotification != null)
            {
                silent = (bool)!forcePushNotification;
            }
            else if (requestObject is JsonRpcRequest request)
            {
                silent = request.Method.StartsWith("wc_") || !SigningMethods.Contains(request.Method);
            }
            else
            {
                silent = false;
            }

            string json = JsonConvert.SerializeObject(requestObject);

            var encrypted = await Cipher.EncryptWithKey(_keyRaw, json);

            if (sendingTopic == null)
                sendingTopic = PeerId;

            var message = new NetworkMessage()
            {
                Payload = JsonConvert.SerializeObject(encrypted),
                Silent = silent,
                Topic = sendingTopic,
                Type = "pub"
            };

            await this.Transport.SendMessage(message);
        }

        /// <summary>
        /// Required implementation for <see cref="IDisposable"/>.
        /// </summary>
        public void Dispose()
        {
            if (Transport != null)
            {
                Transport.Dispose();
                Transport = null;
            }
        }

        /// <summary>
        /// Disconnects the <see cref="ITransport"/>.
        /// </summary>
        /// <returns></returns>
        public virtual async Task Disconnect()
        {
            await DisconnectTransport();
        }
    }
}