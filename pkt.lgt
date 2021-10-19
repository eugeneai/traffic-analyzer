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
     split_ref(Name, Head, Tail),
     Op1 =.. [Head, JSON],
     option(Op1, Attrs),
     field(Option, JSON).
   field(Option, Attrs):-
     Attrs\=json(_),
     member(_=json(A),Attrs),
     field(Option, A).

   :- public(split_ref/3).
   split_ref(Atom,Ref,Refs):-
     atom(Atom),
     sub_atom(Atom,B,1,TL,'.'),
     S is B+1,
     sub_atom(Atom,S,TL,0,Refs),
     sub_atom(Atom,0,B ,_,Ref),!.

   :- public(field/1).
   field(Option):-
     field(Option, _Layers_).

   :- public(tcp_addr/2).
   tcp_addr(src, A:P):-
     field('ip.src'(A)),
     field('tcp.srcport'(B)),
     atom_number(B,P).
   tcp_addr(dst, A:P):-
     field('ip.dst'(A)),
     field('tcp.dstport'(B)),
     atom_number(B,P).
   tcp_addr(src-dst,S-D):-
     tcp_addr(src,S),
     tcp_addr(dst,D).
   :- public(time/2).
   time(abs,A):-
     field('frame.time_epoch'(A)).
   :- public(eth_addr/2).
   eth_addr(src,A):-
     field('eth.src_tree'(json(Tree))),
     field('eth.addr'(A),Tree).
   eth_addr(dst,A):-
     field('eth.dst_tree'(json(Tree))),
     field('eth.addr'(A),Tree).
   :- public(number/1).
   number(N):-
     field('frame.number'(A)),
     atom_number(A,N).
   :- public(tcp_flag/2).
   tcp_flag(Flag,A):-
     member(Flag,[ns,cwr,ecn,urg,ack,push,reset,syn,fin]),
     field('tcp.flags_tree'(T)),
     atom_concat('tcp.flags.',Flag,F),
     Q =.. [F,A],
     field(Q,T).
   :- public(tcp_flag/1).
   tcp_flag(Flag):-
     tcp_flag(Flag,'1').
   :- public(tcp_fin/0).
   tcp_fin :-
     tcp_flag(fin).
   :- public(tcp_push/0).
   tcp_push :-
     tcp_flag(push).
   :- public(tcp_ack/1).
   tcp_ack(N):-
     tcp_flag(ack),
     field('tcp.ack_raw'(A)),
     atom_number(A,N).
   :- public(tcp_seq/1).
   tcp_seq(N):-
     tcp_flag(syn),
     field('tcp.seq_raw'(A)),
     atom_number(A,N).
   :- public(tcp_len/1).
   tcp_len(N):-
     field('tcp.len'(A)),
     atom_number(A,N).
   :- public(tcp_payload/1).
   tcp_payload(Data):-
     field('tcp.payload'(Data)).

:- end_object.

:- object(state(_Pkg_)).
   :- public(inc/2).
   inc(A,B):- add(A,1,B).
   :- public(add/3).
   add(A,B,C):-
     C is (A + B) mod 4294967296.
   :- public(conn_none/2).
   % TODO: sa(SYNA-ACKA,SYND-ACKD)
   conn_none(A-D,
     c(none-none,A-D,none,none)).

   :- public(shift/3).
   shift(   % ---->
       c(none-none,AD,_,_),
       c(start-none,AD,sa(SA-none,none),last([N])),
       created(AD)
       ) :-
     _Pkg_::tcp_addr(src-dst,AD),
     _Pkg_::tcp_seq(SA),    % Generated
     \+ _Pkg_::tcp_fin,
     _Pkg_::number(N).
   shift(   % <----
       c(start-none,A-D,sa(SA-_,_),last([P|Tail])),
       c(start-start,A-D,sa(SA-_,SeqD-AD),last([N,P|Tail])),
       syn_back(A-D)
   ) :-
     _Pkg_::number(N),
     _Pkg_::tcp_addr(src-dst,D-A),  % opposite direction
     inc(SA,AD),
     _Pkg_::tcp_ack(AD),
     _Pkg_::tcp_seq(SeqD),  % Generated
     \+ _Pkg_::tcp_fin.
   shift(   % ---->
       c(start-start,A-D,sa(SA-_,SD-AD),last([P|Tail])),
       c(est-est,A-D,sa(SA1-AA,SD-AD),last([N,P|Tail])),
       established(A-D)
   ) :-
     _Pkg_::number(N),
     _Pkg_::tcp_addr(src-dst,A-D),  % opposite direction
     inc(SD,AA),
     inc(SA,SA1),
     _Pkg_::tcp_ack(AA),
     \+ _Pkg_::tcp_fin.
   shift(   % ----> push
       c(est-est,A-D,sa(SA-AA,SD-AD),last([P|Tail])),
       c(est-est,A-D,sa(SA1-AA,AA-SA1),last([N,P|Tail])),
       push(A-D,forward,Data)
    ) :-
     _Pkg_::number(N),
     _Pkg_::tcp_push,
     _Pkg_::tcp_ack(AA),
     _Pkg_::tcp_len(LA),
     add(SA,LA,SA1),
     \+ _Pkg_::tcp_fin,
     _Pkg_::tcp_payload(Data).
   shift(   % <---- push
       c(est-est,D-A,sa(SD-AD,SA-AA),last([P|Tail])),
       c(est-est,D-A,sa(AA-SA1,SA1-AA),last([N,P|Tail])),
       push(A-D,backward,Data)
    ) :-
     _Pkg_::number(N),
     _Pkg_::tcp_push,
     _Pkg_::tcp_ack(AA),
     _Pkg_::tcp_len(LA),
     add(SA,LA,SA1),
     \+ _Pkg_::tcp_fin,
     _Pkg_::tcp_payload(Data).
   shift(   % ----> ACK
       c(est-est,A-D,sa(SD-AD,SA-AA),last([P|Tail])),
       c(est-est,A-D,sa(SD-AD,SA-AA),last([N,P|Tail])),
       ack(A-D,forward)
       ) :-
     _Pkg_::tcp_addr(src-dst,A-D),
     _Pkg_::tcp_ack(AD),    % Check
     \+ _Pkg_::tcp_fin,
     _Pkg_::number(N).
   shift(   % <---- ACK
       c(est-est,A-D,sa(SD-AD,SA-AA),last([P|Tail])),
       c(est-est,A-D,sa(SD-AD,SA-AA),last([N,P|Tail])),
       ack(A-D,backward)
       ) :-
     _Pkg_::tcp_addr(src-dst,D-A),
     _Pkg_::tcp_ack(AA),    % Check
     \+ _Pkg_::tcp_fin,
     _Pkg_::number(N).
   shift(   % ----> ACK,Fin
       c(est-est,A-D,sa(SD-AD,SA-AA),last([P|Tail])),
       c(fw1-cw,A-D,sa(SD-AD,SA-AA),last([N,P|Tail])),
       fin_start(A-D,forward)
       ) :-
     _Pkg_::tcp_addr(src-dst,A-D),
     _Pkg_::tcp_ack(AD),    % Check
     _Pkg_::tcp_fin,
     _Pkg_::number(N).
   shift(   % <---- Ack
       c(fw1-cw,A-D,sa(SD-AD,SA-AA),last([P|Tail])),
       c(fw2-cw,A-D,sa(SD-AD,SA-AA),last([N,P|Tail])),
       fin_ack(A-D,backward)
       ) :-
     _Pkg_::tcp_addr(src-dst,D-A),
     inc(AA,AA1),
     _Pkg_::tcp_ack(AA1),    % Check
     \+ _Pkg_::tcp_fin,
     _Pkg_::number(N).
   shift(   % <---- Ack,FIN
       c(fw2-cw,A-D,sa(SD-AD,SA-AA),last([P|Tail])),
       c(closed-last,A-D,sa(SD-AD,SA-AA),last([N,P|Tail])),
       fin_fin(A-D,backward)
       ) :-
     _Pkg_::tcp_addr(src-dst,D-A),
     inc(AA,AA1),
     _Pkg_::tcp_ack(AA1),    % Check
     _Pkg_::tcp_fin,
     % _Pkg_::tcp_flag(push), % TODO: Analyze payload,
     % format('PKG: ~n~w~n',[_Pkg_]),
     % _Pkg_::tcp_payload(Data),
     _Pkg_::number(N).
   shift(   % ----> ACK
       c(closed-last,A-D,sa(SD-AD,SA-AA),last([P|Tail])),
       c(closed-closed,A-D,sa(SD-AD,SA-AA),last([N,P|Tail])),
       ack(A-D,forward)
       ) :-
     _Pkg_::tcp_addr(src-dst,A-D),
     inc(AD,AD1),
     _Pkg_::tcp_ack(AD1),    % Check
     \+ _Pkg_::tcp_fin,
     _Pkg_::number(N).
:- end_object.


:- object(connections(_Pkg_)).
   :- public(shift/3).
   shift([],[NewState], Event):-
     debugger::debug,
     state(_Pkg_)::conn_none(A-B,S),!,
     shift(S,NewState,Event).
   shift(State, NextState, Event):-
     state(_Pkg_)::shift(State, NextState, Event),!.
     % State = NextState,!.
   shift([State|T],[NextState|T], Event) :-
     shift(State, NextState, Event),!.
   shift([X|T],[X|R],Event) :-
     shift(T, R, Event),!.
:- end_object.

:- object(analyzer(_Sniffing_)).
   :- protected(current_pack/1).
   current_pack(packet(Layers)) :-
     _Sniffing_::current_pack(json(Layers)).
   :- protected(init/1).
   init([]).
   :- protected(state/1).
   :- dynamic(state/1).
   :- public(run/1).
   run(LastState) :-
     % debugger::trace,
     init(State),
     assert(state(State)),
     proceed(LastState).
   :- protected(proceed/1).
   proceed(LastState):-
     forall(
       current_pack(Pkg),
       (
         state(State),
         format('Current State ~w ~n',[State]),
         connections(Pkg)::shift(State,NextState,Event),
         format('Event ~w ~n',[Event]),
         retract(state(State)),
         assert(state(NextState))
       )
     ),
     state(LastState).
:- end_object.
