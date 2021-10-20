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
  option(event_store_name, 'event.pl').
  % option()
:- end_object.

:- object(sniffing).
  :- public(current_pack/1).
  :- use_module(lists, [member/2]).
  :- use_module(library(option), [option/2,option/3]).
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
  :- use_module(library(option), [option/2,option/3]).

  :- public(connect_db/0).
  connect_db:-
    attach_package_db(_FileName_).

  :- public(disconnect_db/0).
  disconnect_db:-
    detach_package_db.
  current_pack(Pkg):-
    current_package(Pkg).
%    current_package(Pkg),
%    retract_package(Pkg).

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
   :- use_module(library(option), [option/2]).
   :- use_module(lists, [member/2]).

   :- public(field/3).
   field(Option, json(Attrs)):-
     field(Option, Attrs).
   field(Option, Attrs):-
     Attrs\=json(_),
     option(Option, Attrs).
   field(Option, Attrs):-
     Attrs\=json(_),
     Option =.. [Name,_],
     split_ref(Name, Head, _),
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
   :- public(ip_addr/2).
   ip_addr(src,S) :-
     field('ip.src'(S)).
   ip_addr(dst,D) :-
     field('ip.dst'(D)).
   ip_addr(src-dst,S-D) :-
     ip_addr(src,S),
     ip_addr(dst,D).
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
     field('frame.number'(A)),!,
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

   :- protected(tcpep/2). % tcp end point
   %                state,     ip:port       syn:ack receive buffer
   tcpep(Ip:Port, e(none,      Ip:Port,     none:none,  []         )).

   :- public(conn_none/2).
   % TODO: sa(SYNS-ACKS,SYND-ACKD)
   %         Addrs  SRC  DST       sa    receiver buffers
   conn_none(S-D, c(SE,DE)) :-
     tcpep(S,SE),
     tcpep(D,DE).

   ack(A):-
     _Pkg_::tcp_ack(A),
     \+ _Pkg_::tcp_fin.
   conn_ack(A,A1):-
     inc(A,A1),
     _Pkg_::tcp_ack(A1),
     \+ _Pkg_::tcp_fin.
   fin_ack(A):-
     inc(A,A1),
     _Pkg_::tcp_ack(A1),
     _Pkg_::tcp_fin.

   :- public(shift/3).
   shift(   % ---->
       c(e(none ,S,  _:SA, SB), e(none,D, DS:DA,DB)),
       c(e(start,S, SS:SA, SB), e(none,D, DS:DA,DB)),
       initiate(S-D)
       ) :-
     _Pkg_::tcp_addr(src-dst,S-D),
     _Pkg_::tcp_seq(SS),    % Generated
     \+ _Pkg_::tcp_fin,!.
   shift(   % <----
       c(e(start,S, SS:SA, SB), e(none, D,  _:_ ,DB)),
       c(e(start,S, SS:SA, SB), e(start,D, DS:DA,DB)),
       backward(syn(S-D))
   ) :-
     _Pkg_::tcp_addr(src-dst,D-S),  % opposite direction
     _Pkg_::tcp_seq(DS),  % Generated
     conn_ack(SS,DA),!.
   shift(   % ---->
       c(e(start,S, SS :_,  SB), e(start,D, DS:DA, DB)),
       c(e(est  ,S, SS1:SA, SB), e(est  ,D, DS:DA, DB)),
       established(S-D)
   ) :-
     _Pkg_::tcp_addr(src-dst,S-D),
     inc(SS,SS1),
     conn_ack(DS,SA),!.
   % Pushing
   shift(   % ----> push
       c(e(est,S,  SS:SA, SB), e(est,D, DS:DA, DB)),
       c(e(est,S, SS1:SA, []), e(est,D, DS:DA, DB)),
       push(S-D,[Data|SB])
    ) :-
     _Pkg_::tcp_addr(src-dst,S-D),
     _Pkg_::tcp_push,
     _Pkg_::tcp_len(LA),
     add(SS,LA,SS1),
     ack(SA),!,
     _Pkg_::tcp_payload(Data).
   shift(   % ----> ACK
       c(e(est,S, SS:SA, SB), e(est,D, DS:DA, DB)),
       c(e(est,S, SS:SA, SB), e(est,D, DS:DA, DB)),
       ack(S-D)
       ) :-
     _Pkg_::tcp_addr(src-dst,S-D),
     _Pkg_::tcp_ack(SA),    % Check
     \+ _Pkg_::tcp_fin.
   shift(   % ----> ACK,Fin
       c(e(est,S, SS:SA, SB), e(est,D, DS:DA, DB)),
       c(e(fw1,S, SS:SA, SB), e(cw, D, DS:DA, DB)),
       fin_start(S-D)
       ) :-
     _Pkg_::tcp_addr(src-dst,S-D),
     _Pkg_::tcp_ack(SA),    % Check
     _Pkg_::tcp_fin,!.
   shift(   % <---- Ack
       c(e(fw1,S, SS:SA, SB), e(cw, D, DS:DA, DB)),
       c(e(fw2,S, SS:SA, SB), e(cw, D, DS:DA, DB)),
       backward(fin_ack(S-D))
       ) :-
     _Pkg_::tcp_addr(src-dst,D-S),  % Backward
     conn_ack(DA,_),!.
   shift(   % <---- Ack,Fin
       c(e(fw1,S, SS:SA, SB),    e(cw, D, DS:DA, DB)),
       c(e(closed,S, SS:SA, SB), e(last, D, DS:DA, DB)),
       backward(fin_ack(S-D))
       ) :-
     _Pkg_::tcp_addr(src-dst,D-S),
     fin_ack(DA),!.
   shift(   % <---- Ack,FIN
       c(e(fw2,   S, SS:SA, SB), e(cw, D, DS:DA, DB)),
       c(e(closed,S, SS:SA, SB), e(last, D, DS:DA, DB)),
       backward(fin_fin(S-D))
       ) :-
     _Pkg_::tcp_addr(src-dst,D-S),  % Backward
     fin_ack(DA),!.
     % _Pkg_::tcp_flag(push), % TODO: Analyze payload,
     % format('PKG: ~n~w~n',[_Pkg_]),
     % _Pkg_::tcp_payload(Data),
   shift(   % ----> ACK
       c(e(closed,S, SS:SA, SB), e(last,   D, DS:DA, DB)),
       c(e(closed,S, SS:SA, SB), e(closed, D, DS:DA, DB)),
       closed(S-D)
       ) :-
     _Pkg_::tcp_addr(src-dst,S-D),
     conn_ack(SA,_),!.

   % reset
   shift(   % <---- Rst
       c(e(start, S, SS:SA, SB), e(none,   D,    _:_ ,DB)),
       c(e(closed,S, SS:SA, SB), e(closed, D, none:DA, DB)),
       backward(reset(S-D))
   ) :-
     _Pkg_::tcp_addr(src-dst,D-S),  % opposite direction
     _Pkg_::tcp_flag(reset),
     conn_ack(SS,DA),!.
   % icmp
   shift(   % ---->
       c(e(none, S, _,    SB),e(none,D, _,    DB)),
       c(e(none, S, none, SB),e(none,D, none, DB)),
       icmp(S-D)
       ) :-
     _Pkg_::field('ip.proto'('1')),
     % debugger::trace,
     _Pkg_::ip_addr(src-dst,S-D),!.
:- end_object.

:- object(receiver).
   :- public(event/1).
:- end_object.

:- object(connections(_Pkg_)).
   :- public(shift/3).
   shift([],[s(NewState,[N])], Event):-
     _Pkg_::number(N),
     % (N>=25000,!,
     % debugger::trace;true),
     state(_Pkg_)::conn_none(_-_,InitialState),!,
     shift(InitialState,NewState,Event),!.

   % forward direction
   shift(State, NextState, Event):-
     state(_Pkg_)::shift(State, NextState, Event),
     !.
   % in reverse direction
   shift(
     c(SE, DE), c(SE1,DE1), backward(Event)
   ):-
     state(_Pkg_)::shift(
     c(DE, SE), c(DE1,SE1), Event
   ),!.
   shift([s(State,_)|T],T, Event) :-
     shift(State, _, Event),
     final_state(Event),!.
   shift([s(State,[P|ST])|T],[s(NextState,[N,P|ST])|T], Event) :-
     shift(State, NextState, Event),
     _Pkg_::number(N),
     N>P, % Just for a case check
     !.
   shift([X|T],[X|R],Event) :-
     shift(T, R, Event),!.
   :- protected(final_state/1).
   final_state(closed(_)).
   final_state(reset(_)).
   final_state(icmp(_)).
:- end_object.

:- object(analyzer(_Sniffing_,_Receiver_)).
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
     assertz(state(State)),
     proceed(LastState).
   :- protected(proceed/1).
   proceed(LastState):-
     forall(
       (
         current_pack(Pkg),
         % format('~nP ~n'),
         Pkg::number(PkgN),
         % PkgN>=17550,
         % PkgN<25000,
         format('~nPKG ~w~n',[PkgN]),
         true
       ),
       (
         state(State),
         format('Current State ~w ~n',[State]),
         connections(Pkg)::shift(State,NextState,Event),
         format('Event ~w ~n',[Event]),!,
         _Receiver_::event(Event),!,
         retract(state(State)),!,
         assertz(state(NextState))
       )
     ),
     state(LastState).
:- end_object.

:- object(event_saver(_FileName_), extends(receiver)).
   :- protected(stream/1).
   :- dynamic(stream/1).
   :- public(connect/0).
   connect :-
     open(_FileName_, write, Stream),!,
     assertz(stream(Stream)),
     !.
   :- public(disconnect/0).
   disconnect :-
     retract(stream(Stream)),!,
     close(Stream),!.
   event(Event) :-
     stream(Stream), !,
     % debugger::trace,
     format(Stream, '~k.~n', [Event]),!.
:- end_object.
