% A Prolog implementation of Van Jacobson's schematized trust, see
% http://www.caida.org/workshops/ndn/1502/slides/ndn1502_vjacobson.pdf

% loop DoS example

% Problem description: In step (2), if the certificate from the trust
% anchor for the 'ping' key is delivered systematically later (3b)
% than the certificate from the 'pong' key for 'ping' (3a), then the
% router will loop forever when trying to validate the trust
% chain. The ping-ping loop is the smallest loop possible - a real
% cycle might be arbitrarily long (not under control of the router)
% and would need arbitrary memory to detect - or time when using
% Pollard's rho method to be discovered.

% packet structure for data:
%   pkt(Name, Data, signedInfo(SigningName, keyID(SigningKey)), Signature)

% certificate structure
%   pkt(KeyName, KeyID, KeyBits, signedInfo(SigningName, keyID(SigningKey)),
%       Signature),


% --- the core of schematized trust
% (signature validation according to the given schema)

isValidPacket(Packet, Schema, RootKeyName) :-
  Packet = pkt(Name, Data, signedInfo(SigningName, KeyID), Signature),
  schema(Schema, SigningName, Name),
  isInTrustedChain(SigningName, KeyID, Schema, RootKeyName, SigningBits),
  isValidSignature(Name, Data, Signature, SigningBits),
  log_validpkt(Name, Data, Signature, SigningBits).

isInTrustedChain(SigningName, KeyID, Schema, RootKeyName, SigningBits) :-
  untrustedRetrieve(pkt(SigningName, KeyID, SigningBits,
                        signedInfo(ParentName,ParentKeyID), Signature)),
  schema(Schema, ParentName, SigningName),
  ( trustedRetrieve(ParentName, ParentBits)
  ; isInTrustedChain(ParentName, ParentKeyID, Schema, RootKeyName, ParentBits)
  ),
  isValidSignature(SigningName, SigningBits, Signature, ParentBits),
  log_validcert(SigningName, SigningBits, ParentName, ParentKeyID,
                Signature, ParentBits).


% --- demo: a hierarchical trust schema with a loop (see Fig XYZ)

% Format of schema rules:
%   schema(SchemaName, DataNamePattern, KeyPattern).

schema('LoopSchema',
       [Pfx, 'root', 'key'],  % root has permission to sign ping's key
       [Pfx, 'ping', 'key']).

schema('LoopSchema',
       [Pfx, 'ping', 'key'],  % ping has permission to sign pong's key
       [Pfx, 'pong', 'key']).

schema('LoopSchema',
       [Pfx, 'pong', 'key'],  % pong has permission to sign ping's key
       [Pfx, 'ping', 'key']).

schema('LoopSchema',
       [Pfx, 'pong', 'key'],  % pong has permission to sign packets
       [Pfx, 'pkt', _]).

 schema('SimpleSchema',
        [Pfx, 'root', 'key'],  % root has permission to sign ping's key
        [Pfx, 'ping', 'key']).

 schema('SimpleSchema',
        [Pfx, 'ping', 'key'],  % ping has permission to sign pong's key
        [Pfx, 'pong', 'key']).

 schema('SimpleSchema',
        [Pfx, 'pong', 'key'],  % pong has permission to sign packets
        [Pfx, 'pkt', _]).

% --- set of published keys (using numbers as toy signatures, keyIDs)

trustedRetrieve(N, K) :-
   N = ['somePrefix', 'root', 'key'],
   K = 104.

% certificate database: correctly signed and published keys:

untrustedRetrieve(pkt(N,I,K,signedInfo(PK,keyID(104)),S)) :-
   PK = [Prefix, 'root', 'key'],
   N =  [Prefix, 'ping', 'key'],
   K =  103,
   I =  keyID(K),
   S =  207.

untrustedRetrieve(pkt(N,I,K,signedInfo(PK,keyID(103)),S)) :-
   PK = [Prefix, 'ping', 'key'],
   N =  [Prefix, 'pong', 'key'],
   K =  102,
   I =  keyID(K),
   S =  205.

untrustedRetrieve(pkt(N,I,K,signedInfo(PK,keyID(102)),S)) :-
   PK = [Prefix, 'pong', 'key'],
   N =  [Prefix, 'ping', 'key'],
   I =  keyID(K),
   K =  103,
   S =  205.


% --- simulated signature computation:
%     by simply adding keyvalue to datavalue
%     (and neglecting the name part for the moment)

isValidSignature(Name, Data, Signature, KeyBits) :-
   Name = _,
   Signature =:= Data + KeyBits.

% --- log

log_validpkt(Name, Data, Signature, SigningBits) :-
  write('* packet for '), write(Name), write(' is valid (dataBits='),
  write(Data), write(', signature='), write(Signature),
  write(' signingBits='), write(SigningBits), write(')'), nl.

log_validcert(SigningName, SigningBits, ParentName, ParentKeyID, Signature, ParentBits) :-
  write('* cert <'), write(SigningName), write('/keyBits='), write(SigningBits),
  write('> correctly signed by '), write(ParentName), write('/keyID='),
  write(ParentKeyID), write(' (signature='), write(Signature),
  write(', signingBits='), write(ParentBits), write(')'), nl.

% --- the main loop demo:

loopmain :-
  Prefix = 'somePrefix',
  RootKeyName = [Prefix, 'root', 'key'],

  PktName = [Prefix, 'pkt', 678],
  Data = 1000,
  Signature = 1102,
  SigningName = [Prefix, 'pong', 'key'],
  KeyID = keyID(102),
  Packet = pkt(PktName, Data, signedInfo(SigningName, KeyID), Signature),

  isValidPacket(Packet, 'LoopSchema', RootKeyName).

% --- a simple hierarchical demo:

simplemain :-
  Prefix = 'somePrefix',
  RootKeyName = [Prefix, 'root', 'key'],

  PktName = [Prefix, 'pkt', 678],
  Data = 1000,
  Signature = 1102,
  SigningName = [Prefix, 'pong', 'key'],
  KeyID = keyID(102),
  Packet = pkt(PktName, Data, signedInfo(SigningName, KeyID), Signature),

  isValidPacket(Packet, 'SimpleSchema', RootKeyName).

% eof
