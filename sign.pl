% Let the engine know this rule set is dynamic (so we can add facts as needed)
:-dynamic(signerKey/1).

% The key database
signerKey(['somePrefix', 'root', 'key']).
signerKey(['somePrefix', 'ping', 'key']).
% signerKey(['somePrefix', 'pong', 'key']).
%%% pong's key is not present -- we would need to create it when signing

% A hierarchical trust schema database
% Format of schema rules:
%   schema(SchemaName, DataNamePattern, KeyPattern).
schema('SimpleSchema',
       [Pfx, 'root', 'key'],  % root has permission to sign ping's key
       [Pfx, 'ping', 'key']).

schema('SimpleSchema',
       [Pfx, 'ping', 'key'],  % ping has permission to sign pong's key
       [Pfx, 'pong', 'key']).

schema('SimpleSchema',
       [Pfx, 'pong', 'key'],  % pong has permission to sign packets
       [Pfx, 'pkt', _]).

% Create a key (and let the world know)
createKey(KeyName) :-
  write('Creating key: '),
  write(KeyName),
  asserta(signerKey(KeyName)).

% Schema match clause (traverse up the schema towards a root)
schemaMatch(Name, Schema, RootKeyName) :-
  schema(Schema, X, Name),             % A) there exists a signing key for Name, name
  signerKey(X),                        % B) we actually have that key...
  schemaMatch(X, Schema, RootKeyName). % C) recurse for that signing key

% Schema match clause (traverse up the schema towards a root)
schemaMatch(Name, Schema, RootKeyName) :-
  schema(Schema, X, Name),             % A) there exists a signing key for Name, name
  not(signerKey(X)),                   % B) we do not have that key...
  createKey(X),                        % ... so, create it
  schemaMatch(X, Schema, RootKeyName). % C) recurse for that signing key

% Terminal clause (i.e., we've reached a root)
schemaMatch(Name, Schema, RootKeyName) :-
  schema(Schema, RootKeyName, Name).

% Run the main query
main :-
  Prefix = 'somePrefix',
  RootKeyName = [Prefix, 'root', 'key'],
  PktName = [Prefix, 'pkt', 678],
  schemaMatch(PktName, 'SimpleSchema', RootKeyName). % use variables to report back alternatives
