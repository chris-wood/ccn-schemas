% engine-v2.pl

% data structures:

% trustCtx(Trustmodel, ListOfTrustedKeys, OptionalSchema)
% key(name(Locator), id(KeyId), val(Bits))
% pkt(DataName, Data, KeyInfo, PktHash, Signature)

% ==== code that is common to all trust models:

isValidPkt(Packet, TrustContextIn, TrustContextOut) :-
  Packet = pkt(DataName, _, KeyInfo, PktHash, PktSignature),
  getTrustedKey(DataName, KeyInfo, TrustContextIn, TrustContextOut),
  KeyInfo = key(_, _, KeyBits),
  isValidSignature(PktHash, PktSignature, KeyBits),
  write('Key '), write(KeyInfo), write(' validates the pkt.'), nl.

getTrustedKey(DataName, KeyInfo, TrustContextIn, TrustContextOut) :-
  ( % test whether key is already known:
    keyIsInTrustContext(KeyInfo, TrustContextIn),
    TrustContextIn = TrustContextOut
  ); % otherwise fetch it
  fetchTrustedKey(DataName, KeyInfo, TrustContextIn, TrustContextOut).

keyIsInTrustContext(KeyInfo, Context) :-
  Context = trustCtx(_, TrustedKeyList, _),
  member(KeyInfo, TrustedKeyList).

isValidSignature(h(val(Msg)), Signature, val(KeyBits)) :-
  S is Msg + KeyBits,
  Signature = s(S).

% ==== a) pre-shared key (keyed MAC)

fetchTrustedKey(_, _, Context, Context) :-
  Context = trustCtx('preshared', _, _),
  % no keys can be fetched at runtime:
  fail.

% ==== b) hierarchical trust

fetchTrustedKey(_, Key, TrustContextIn, TrustContextOut) :-
  TrustContextIn = trustCtx('hierarchical', _, _),
  Key = key(KeyLocator, _, KeyBits),
  ccnFetchCert(KeyLocator, CertPkt),
  CertPkt = pkt(KeyLocator, KeyBits, _, _, _),
  isValidPkt(CertPkt, TrustContextIn, TrustContextTmp),
  TrustContextTmp = trustCtx('hierarchical', KeyList, _),
  TrustContextOut = trustCtx('hierarchical', [Key | KeyList], _).

% ==== c) schematized trust

fetchTrustedKey(DataName, Key, TrustContextIn, TrustContextOut) :-
  TrustContextIn = trustCtx('schematized', _, Schema),
  Key = key(KeyLocator, _, KeyBits),
  isValidSignerName(Schema, DataName, KeyLocator), % this is new
  ccnFetchCert(KeyLocator, CertPkt),
  CertPkt = pkt(KeyLocator, KeyBits, _, _, _),
  isValidPkt(CertPkt, TrustContextIn, TrustContextTmp),
  TrustContextTmp = trustCtx('schematized', Schema, KeyList),
  TrustContextOut = trustCtx('schematized', [Key | KeyList]).

% ==== d) web of trust

% fetchTrustedKey(_, % DataName irrelevant for web of trust
%                 Key, TrustContextIn, TrustContextOut) :-
%   TrustContextIn = trustCtx('webOfTrust', TrustedKeyList),
%   Key = key(KeyLocator, _, KeyBits),
%   ccnFetchCert(KeyLocator, CertPkt),
%   CertPkt = pkt(KeyLocator, KeyBits, _, _, _),
%   isValidPkt(CertPkt, TrustContextIn, TrustContextTmp),
%   TrustContextTmp = trustCtx('schematized', Schema, KeyList),
%   TrustContextOut = trustCtx('schematized', [Key | KeyList]).
% 
%   if unKnownKey(KeyNameOrId):
%     getTrustedKeyByName(KeyNameOrId, Param, confidenceContextIn,
%                         confidnceContextOut)
%   getKeyBits(KeyNameOrId)
% 
% getTrustedKeyByName(KeyNameOrId, Param, confidenceContextIn) :-
%                        // side effect: put it into
%                        // trusted key DB
%   ccnLookup(KeyNameOrId) --> signed (public) Key Bits, PktHAsh, PktSign
%   extractSignerNameFromSignature --> signerKeyName
%   validatePkt(Strategy, Schema, KeyNameOrId, signerKeyName,
%               PktHash, PktSignature, confidenceContextIn, 
%               confidenceInSigner)
%   isTrustworthy(confidenceContextIn, Param, confidenceInSigner),
%   confidenceContextOut = (confidenceContextIn, confidenceInSigner)
%   addKeyBits(KeyNameOrId, KeyBits, confidenceContextOut)


% ----------------------------------------------------------------------
% test the different models

myHmacTrust(C) :-
  C = trustCtx('preshared',
               [ key(name('key1'), _, val(11)) |
                 [ key(name('key2'), _, val(22)) ] ],
               _).

hmac :-
  % case 1: pkt contains key locator and keyId
  Pkt = pkt('aDataName', val(1000), key(name('key1'), id(102), _), h(val(1000)), s(1011)),
  % case 2: pkt contains no key information - our code will try all known keys
  % Pkt = pkt('aDataName', val(1000), _, h(val(1000)), s(1022)),
  myHmacTrust(Ctx),
  isValidPkt(Pkt, Ctx, _).

% ---

myHierTrust(C) :-
  C = trustCtx('hierarchical',
               [ key(name('key30'), _, val(333)) ],   % CA root
               _).

ccnFetchCert(name(L), Cert) :-
  L = 'key10',
  Cert = pkt(name(L), val(1), key(name('key20'), _, _), h(val(1)), s(23)).

ccnFetchCert(name(L), Cert) :-
  L = 'key20',
  Cert = pkt(name(L), val(22), key(name('key30'), _, _), h(val(22)), s(355)).


hier :-
  % pkt contains key locator of signer
  Msg = val(2000),
  Pkt = pkt('aDataName', Msg, key(name('key10'), _, _), h(Msg), s(2001)),
  myHierTrust(Ctx),
  isValidPkt(Pkt, Ctx, _).

% eof
