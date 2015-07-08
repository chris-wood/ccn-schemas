% A hierarchical trust schema database
% Format of schema rules:
%   schema(SchemaName, Data Name Pattern, Key Pattern).

schema('SimpleSchema',
       [Pfx, 'root', 'key'],  % root has permission to sign ping's key
       [Pfx, 'ping', 'key']).

schema('SimpleSchema',
       [Pfx, 'ping', 'key'],  % ping has permission to sign pong's key
       [Pfx, 'pong', 'key']).

schema('SimpleSchema',
       [Pfx, 'pong', 'key'],  % pong has permission to sign packets
       [Pfx, 'pkt', _]).

% Schema match clause -- traverse up the schema
schemaMatch(Name, Schema, RootKeyName) :-
  schema(Schema, X, Name),             % A) there exists a signing key for Name, name
  schemaMatch(X, Schema, RootKeyName). % B) recurse for that signing key

% Terminal clause (we've reached a root)
schemaMatch(Name, Schema, RootKeyName) :-
  schema(Schema, RootKeyName, Name).

main :-
  Prefix = 'somePrefix',
  RootKeyName = [Prefix, 'root', 'key'],
  PktName = [Prefix, 'pkt', 678],
  schemaMatch(PktName, 'SimpleSchema', RootKeyName). % use variables to report back alternatives
