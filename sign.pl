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

% Schema match clause
schemaMatch(Name, Schema, RootKeyName) :-
%  print(Name),
  schema(Schema, X, Name), % there exists a signing key for Name
  schemaMatch(X, Schema, RootKeyName). % there exists a signing key for that parent

schemaMatch(Name, Schema, RootKeyName) :-
  schema(Schema, RootKeyName, Name).

main :-
  Prefix = 'somePrefix',
  RootKeyName = [Prefix, 'root', 'key'],
  PktName = [Prefix, 'pkt', 678],
  schemaMatch(PktName, 'SimpleSchema', RootKeyName). % use variables to report back alternatives
