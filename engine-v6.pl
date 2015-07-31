% engine-v6.pl

% start at the command line with:
%    swipl -s engine-v6.pl

% data structures:
%
% pkt(name(DataName), val(Msg), KeyInfo, h(Data), s(Signature))
%
% key(name(Locator), id(KeyId), val(Bits))
%
% trustCtx(Trustmodel, ListOfTrustedKeys, Aux)
%   where Aux is either SchemaList, ConfidenceList, or _
%
% schema(SignerPath, SigneePath)
%
% confid(FriendName, Float)

% ==== validation code that is common to all trust models:

isValidPkt(Packet, TrustContextIn, TrustContextOut) :-
  Packet = pkt(DataName, _, KeyInfo, PktHash, PktSignature),
  getTrustedKey(DataName, KeyInfo, TrustContextIn, TrustContextOut),
  KeyInfo = key(_, _, KeyBits),
  isValidSignature(PktHash, PktSignature, KeyBits),
  write(KeyInfo), write(' validates the packet with '), write(DataName), nl.

getTrustedKey(_, KeyInfo, TrustContext, TrustContext) :-
  TrustContext = trustCtx(_, TrustedKeyList, _),
  member(KeyInfo, TrustedKeyList).

getTrustedKey(DataName, KeyInfo, TrustContextIn, TrustContextOut) :-
  fetchTrustedKey(DataName, KeyInfo, TrustContextIn, TrustContextOut).


% ----
  
isValidSignature(h(val(Msg)), Signature, val(KeyBits)) :-
  S is Msg + KeyBits,
  Signature = s(S).

% ==== a) pre-shared key (keyed MAC)

fetchTrustedKey(_, _, Context, Context) :-
  Context = trustCtx('preshared', _, _),
  % no keys can be fetched at runtime:
  fail.

% ==== b) hierarchical trust AND schematized trust

fetchTrustedKey(DataName,KeyHint,TrustContextIn,TrustContextOut) :-
  KeyHint = key(KeyLocator, _, KeyBits),
  TrustContextIn = trustCtx(Model, _, Aux),
  ( Model = 'hierarchical'
  ;
    Model =  'schematized', % Aux has the list of schemas
    member(schema(KeyLocator, DataName), Aux)
  ),
  ccnFetchCert(KeyLocator, CertPkt),
  CertPkt = pkt(KeyLocator, KeyBits, _, _, _),
  isValidPkt(CertPkt, TrustContextIn, TrustContextTmp),
  TrustContextTmp = trustCtx(Model, KeyList, Aux),
  TrustContextOut = trustCtx(Model, [KeyHint | KeyList], Aux).

% ==== c) web of trust

fetchTrustedKey(_, Key, TrustContextIn, TrustContextOut) :-
  TrustContextIn = trustCtx('webOfTrust', KeyList, ConfidenceList),
  member(confid(FriendName, Conf), ConfidenceList),
  (
    Conf < 0.5, fail
  ;
    ccnFetchFriends(FriendName, FriendList),
    member(FriendFriend, FriendList), % for all peer's peers
    not(member(key(FriendFriend,_,_), KeyList)), % if new, do:
    ccnFetchCert(FriendFriend, CertPkt),
    CertPkt = pkt(FriendFriend, KeyBits, _, _, _),
    isValidPkt(CertPkt, TrustContextIn, TrustContextTmp),
    Key = key(FriendFriend, _, KeyBits),
    TrustContextTmp = trustCtx('webOfTrust', KeyList2, ConfList),
    C is Conf * 0.9,
    TrustContextOut = trustCtx('webOfTrust', [Key | KeyList2],
                           [confid(FriendFriend, C) | ConfList]),
    !    % one key suffices (social graph may have loops)
  ).

% ==== signing code, for schematized trust only

getSigningName(DataName, TrustContext, [SignerName|Tail]) :-
  TrustContext = trustCtx('schematized', KeyList, Schema),
  member(schema(SignerName, DataName), Schema),
  (member(key(SignerName, _, _), KeyList), Tail= []
  ;
   getSigningName(SignerName, TrustContext, Tail)
  ).


% ----------------------------------------------------------------------
% test the different models

myHmacTrust(C) :-
  C = trustCtx('preshared',
               [ key(name('/key/1'), _, val(11)) |
                  [ key(name('/key/2'), _, val(22)) ] ],
               _).

hmac :-
  % case 1: pkt contains key locator and keyId
  Pkt = pkt(name('/a/data/name'), val(1000), key(name('/key/1'),
            id(102), _), h(val(1000)), s(1011)),
  % case 2: pkt contains no key information - we try out all known keys
  % Pkt = pkt(name('/a/data/name'), val(1000), _, h(val(1000)), s(1022)),
  myHmacTrust(Ctx),
  isValidPkt(Pkt, Ctx, _).

% --- hierarchical: 

myHierTrust(C) :-
  C = trustCtx('hierarchical',
               [ key(name('/key/30'), _, val(333)) ],   % CA root
               _).

ccnFetchCert(name(L), Cert) :-
  L = '/key/10',
  Cert = pkt(name(L), val(1), key(name('/key/20'), _, _), h(val(1)), s(23)).

ccnFetchCert(name(L), Cert) :-
  L = '/key/20',
  Cert = pkt(name(L), val(22), key(name('/key/30'), _, _), h(val(22)), s(355)).


hier :-
  % pkt contains key locator of signer
  Msg = val(2000),
  Pkt = pkt(name('/a/data/name'), Msg, key(name('/key/10'), _, _), h(Msg), s(2001)),
  myHierTrust(Ctx),
  isValidPkt(Pkt, Ctx, _).

/*
% --- schematized: 

mySchemaTrust(C) :-
  C = trustCtx('schematized',
               [ key(name(['root','key']), _, val(104)) ], % one trust anchor
               [ schema(name(['root','key']), name(['ping','key'])),
                 schema(name(['ping','key']), name(['pong','key'])),
%                 schema(name(['ping','key']), name(['pang','key'])),
%                 schema(name(['pang','key']), name(['pkt',_])),
                 schema(name(['pong','key']), name(['pkt',_]))
               ]).

ccnFetchCert(N, pkt(N, val(Msg), KeyInfo, h(val(Msg)), s(S))) :-
  N = name(['ping','key']),
  Msg = 103,
  KeyInfo = key(name(['root','key']), id(104), _),
  S = 207.

ccnFetchCert(N, pkt(N, val(Msg), KeyInfo, h(val(Msg)), s(S))) :-
  N = name(['pong','key']),
  Msg = 102,
  KeyInfo = key(name(['ping','key']), id(103), _),
  S = 205.

ccnFetchCert(N, pkt(N, val(Msg), KeyInfo, h(val(Msg)), s(S))) :-
  N = name(['ping','key']),
  Msg = 103,
  KeyInfo = key(name(['pong','key']), id(102), _),
  S = 205.

sche :-
  % pkt contains key locator of signer
  Msg = val(1000),
  Pkt = pkt(name(['pkt','678']), Msg, key(name(['pong','key']), id(102), _), h(Msg), s(1102)),
  mySchemaTrust(Ctx),
  isValidPkt(Pkt, Ctx, _).
*/

% --- webOfTrust: 

myTrustWeb(C) :-
  C = trustCtx('webOfTrust',
               [ key(name(['alice','key']), _, val(7)) ], % one trust anchor
               [ confid(name(['alice','key']), 0.9) ]).

ccnFetchFriends(name(['alice','key']), [ name(['bob', 'key']) ]).

ccnFetchCert(N, pkt(N, val(Msg), KeyInfo, h(val(Msg)), s(S))) :-
  N = name(['bob','key']),
  Msg = 15,
  KeyInfo = key(name(['alice','key']), _, _),
  S = 22.

woft :-
  % no key hint, this time
  Msg = val(55),
  Pkt = pkt(name(['pkt','678']), Msg, _, h(Msg), s(70)),
  myTrustWeb(Ctx),
  isValidPkt(Pkt, Ctx, _).

% ----------------------------------------------------------------------

% signing

sign :-
  mySchemaTrust(Ctx),
  N = name(['pkt','678']),
  getSigningName(N, Ctx, Path),
  write('you as a producer can sign data having name '), nl,
  write('  '), write(N), nl,
  write('via '), write(Path), nl.

% ----------------------------------------------------------------------

main :-
  write('Three tests to run:'), nl,
  write('  hmac.'), nl,
  write('  hier.'), nl,
  write('  sche.'), nl,
  write('  woft.'), nl,
  write('  sign.'), nl.

% ======================================================================

% Prolog code to demo the loop case for schematized trust

% INSERT HERE all code snippets from Section V

isValidSignature(h(val(Msg)), Signature, val(KeyBits)) :-
  % mimic the computation of a signature: add Msg value to Key value
  S is Msg + KeyBits,
  Signature = s(S).

demoTrustContext(C) :-
  C = trustCtx('schematized',
        [ % trust anchor (public key of Root)
          key(name(['root','key']), _, val(104)) ],
        [ % schema(SignerKeyName, SignedKeyName)
          schema(name(['root','key']), name(['ping','key'])),
          schema(name(['pong','key']), name(['ping','key'])), % CAUSE 1!
          schema(name(['ping','key']), name(['pong','key'])),
          schema(name(['pong','key']), name(['pkt',_]))
        ]).

% two certificates for the same key of Ping:

ccnFetchCert(N, pkt(N, val(Msg), KeyInfo, h(val(Msg)), s(S))) :-
  N = name(['ping','key']),
  Msg = 103,
  KeyInfo = key(name(['pong','key']), id(102), _),
  S = 205.

ccnFetchCert(N, pkt(N, val(Msg), KeyInfo, h(val(Msg)), s(S))) :-
  % CAUSE 2: Root's certificate is fetched AFTER Pong's cert (above)
  N = name(['ping','key']),
  Msg = 103,
  KeyInfo = key(name(['root','key']), id(104), _),
  S = 207.

% one certificate for Pong's key:

ccnFetchCert(N, pkt(N, val(Msg), KeyInfo, h(val(Msg)), s(S))) :-
  N = name(['pong','key']),
  Msg = 102,
  KeyInfo = key(name(['ping','key']), id(103), _),
  S = 205.


loopDemo :-
  % this predicate will loop forever (= stack overflow)
  % how to break: remove one schema line, or change order of certs
  Msg = val(1000),
  Pkt = pkt(name(['pkt','678']), Msg,
            key(name(['pong','key']), id(102), _),
            h(Msg), s(1102)),
  demoTrustContext(Ctx),
  isValidPkt(Pkt, Ctx, _).


% eof
