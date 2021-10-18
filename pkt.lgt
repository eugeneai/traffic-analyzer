:- use_module(library(process)).
:- use_module(library(sgml), [load_structure/3]).
:- use_module(util, [
     json_load/3,
     assert_package/1,
     retract_package/1,
     current_package/1,
     retractall_package/1,
     attach_package_db/1,
     detach_package_db
   ]).
:- use_module(library(option),[option/2,option/3]).

:- object(pcap_config).
  :- public([current_option/1, current_option/2]).
  current_option(A=B):-
    option(A,B).
  current_option(A,B):-
    option(A,B).

  % ek|fields|json|jsonraw|pdml|ps|psml|tabs|text
  option(output_format,'json').
  option(wireshark_executable, '/usr/bin/tshark').
  option(test_db_name, 'pcap-small.db').
  option(db_name, 'pcap.db').
  % option()
:- end_object.

:- object(sniffing).
  :- public(current_pack/1).
  :- use_module(lists, [member/2]).
  :- use_module(option, [option/2,option/3]).
  :- public(layers/2).
  layers(json(Attrs), Layers):-
    option('_source'(json(Sources)),Attrs),
    option(layers(Layers),Sources).
:- end_object.

:- object(db(_FileName_),
     extends(sniffing)).

  :- use_module(util,[
       json_load/3,
       assert_package/1,
       retract_package/1,
       current_package/1,
       retractall_package/1,
       attach_package_db/1,
       detach_package_db/0
     ]).
  :- use_module(option, [option/2,option/3]).

  :- public(connect_db/0).
  connect_db:-
    attach_package_db(_FileName_).

  :- public(disconnect_db/0).
  disconnect_db:-
    detach_package_db.
  current_pack(Pkg):-
    current_package(Pkg).

:- end_object.

:- object(pcap(_FileName_,_DisplayFilter_),
     extends(sniffing)).
  :- public(load/0).

  :- use_module(sgml,[load_structure/3]).
  :- use_module(process,[process_create/3]).
  :- meta_predicate(sgml:load_structure(*,*,*)).
  :- use_module(util,[
       json_load/3,
       assert_package/1,
       retract_package/1,
       current_package/1,
       retractall_package/1,
       attach_package_db/1,
       detach_package_db/0
     ]).
  :- use_module(lists,[member/2]).

  load :-
    pcap_config::current_option(wireshark_executable, Exec),
    pcap_config::current_option(output_format, Format),
    get_args(Format, Args),
    format('Exeuting ~w ~w ~n | swilgt ...',[Exec,Args]),
    process_create(Exec, Args, [stdout(pipe(Pipe))]),
    % load_structure(Pipe, Content, [dialect(xml)]),
    json_load(Pipe, Content, [null(null), true(true), flase(false)]),
    format('JSON loaded~nNow converting into db.',[]),
    % Content=[H|_],
    % format('\n~w~n',[H]),
    store(Content),
    true.

  get_args(Format, ['-r', _FileName_, '-T', Format]):-
    _DisplayFilter_ = none, !.
  get_args(Format, ['-r', _FileName_, '-Y', _DisplayFilter_, '-T', Format]).

  :- public(store/1).
  store(Packages):-
    pcap_config::current_option(db_name,DBFile),
    attach_package_db(DBFile),
    forall(member(P,Packages), package_store(P)),
    detach_package_db.

  package_store(JSON):-
    ::layers(JSON,Layers),
    assert_package(Layers).
%    format('STORING: ~w~n',[JSON]).

:- end_object.


:- object(packet(_Layers_)).
   :- use_module(option, [option/2]).
   :- use_module(lists, [member/2]).

   :- public(field/3).
   field(Option, json(Attrs)):-
     field(Option, Attrs).
   field(Option, Attrs):-
     Attrs\=json(_),
     option(Option, Attrs).
   field(Option, Attrs):-
     Attrs\=json(_),
     Option =.. [Name,Value],
     % debugger::trace,
     split_ref(Name, Head, Tail),
     % format('~k Attr:~k~n~n',[Head, Attrs]),
     Op1 =.. [Head, JSON],
     option(Op1, Attrs),
     format('GOT: ~k = ~k~n~n',[Head, JSON]),
     % debugger::trace,
     % Op2 =.. [Tail, Value],
     field(Option, JSON).
   field(Option, Attrs):-
     Attrs\=json(_),
     % debugger::trace,
     member(_=json(A),Attrs),
     field(Option, A).

   % field(Name=Value, Attrs):-
   %   split_ref(Name, Head, Tail),!,
   %   format('~k Attr:~k~n~n',[Head, Attrs]),
   %   debugger::trace,
   %   option(eth=JSON, Attrs),
   %   format('GOT: ~k = ~k~n~n',[Head, JSON]),
   %   debugger::trace,
   %   field(Tail=Value, JSON).

   :- public(split_ref/3).
   split_ref(Atom,Ref,Refs):-
     % format('Split: ~k,~k,~k~n',[Atom,Ref,Refs]),
     atom(Atom),
     sub_atom(Atom,B,1,TL,'.'),
     S is B+1,
     sub_atom(Atom,S,TL,0,Refs),
     sub_atom(Atom,0,B ,_,Ref),!.

   :- public(field/1).
   field(Option):-
     field(Option, _Layers_).


:- end_object.
